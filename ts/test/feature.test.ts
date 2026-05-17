import { describe, it, expect, beforeAll } from "vitest";
import {
  encryptMcap,
  decryptMcap,
  iterateMessages,
  generateKeyPair,
  type KeyPair,
} from "../src/index.js";
import { BinaryReader } from "../src/binary.js";
import {
  buildTestMcapWithAttachment,
  buildTestMcapWithMetadata,
  buildOversizedChunkMcap,
  buildEmptyMcap,
  buildTestMcapWithLz4Chunk,
  buildMultiChunkMcap,
  collectMessages,
} from "./helpers.js";

let keys: KeyPair;

beforeAll(async () => {
  keys = await generateKeyPair();
});

describe("attachment passthrough", () => {
  it("non-key attachment survives encrypt/decrypt", async () => {
    const plain = buildTestMcapWithAttachment();
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    const dec = await decryptMcap(enc, keys.privateKeyPem);

    expect(readAttachmentNames(dec)).toContain("config.json");
  });
});

describe("header preservation", () => {
  it("profile and library survive encrypt/decrypt", async () => {
    const plain = buildTestMcapWithAttachment(); // profile="ros2", library="test-lib"
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    const dec = await decryptMcap(enc, keys.privateKeyPem);

    const hdr = readMcapHeader(dec);
    expect(hdr.profile).toBe("ros2");
    expect(hdr.library).toBe("test-lib");
  });
});

describe("empty MCAP round-trip", () => {
  it("encrypts and decrypts with no messages", async () => {
    const plain = buildEmptyMcap();
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    const dec = await decryptMcap(enc, keys.privateKeyPem);

    expect(collectMessages(dec)).toHaveLength(0);
  });
});

describe("iterateMessages error paths", () => {
  it("throws with wrong private key", async () => {
    const plain = buildTestMcapWithAttachment();
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    const other = await generateKeyPair();
    const gen = iterateMessages(enc, other.privateKeyPem);
    await expect(gen.next()).rejects.toThrow(/private key does not match/);
  }, 20_000);
});

describe("metadata passthrough", () => {
  it("metadata record survives encrypt/decrypt round-trip", async () => {
    const plain = buildTestMcapWithMetadata();
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    const dec = await decryptMcap(enc, keys.privateKeyPem);

    const names = readMetadataNames(dec);
    expect(names).toContain("robot_info");
  });

  it("metadata key-value pairs are preserved correctly", async () => {
    const plain = buildTestMcapWithMetadata();
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    const dec = await decryptMcap(enc, keys.privateKeyPem);

    const recs = readMetadataRecords(dec);
    const robotInfo = recs.find((r) => r.name === "robot_info");
    expect(robotInfo).toBeDefined();
    expect(robotInfo?.metadata.get("serial")).toBe("ABC-123");
    expect(robotInfo?.metadata.get("version")).toBe("1.2.3");
  });

  it("metadata_count in Statistics matches the number of metadata records", async () => {
    const plain = buildTestMcapWithMetadata();
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    const dec = await decryptMcap(enc, keys.privateKeyPem);

    // Scan for Statistics record (opcode 0x0a) and check metadata_count field.
    const stats = readStatisticsMetadataCount(dec);
    expect(stats).toBe(1);
  });
});

describe("safeBigintToNumber guard", () => {
  it("throws a descriptive error when chunk compressedSize exceeds MAX_SAFE_INTEGER", async () => {
    const mcap = buildOversizedChunkMcap();
    await expect(encryptMcap(mcap, keys.publicKeyPem)).rejects.toThrow(
      /exceeds maximum safe integer/,
    );
  });
});

describe("LZ4 rejection", () => {
  it("throws on LZ4-compressed source MCAP", async () => {
    const mcap = buildTestMcapWithLz4Chunk();
    await expect(encryptMcap(mcap, keys.publicKeyPem)).rejects.toThrow(/LZ4/);
  });
});

describe("multi-chunk iterateMessages", () => {
  it("returns all messages across multiple chunks in order", async () => {
    const { mcap: plain, messages: expected } = buildMultiChunkMcap(3, 4);
    const enc = await encryptMcap(plain, keys.publicKeyPem);

    const got: Array<{ channelId: number; sequence: number; data: Uint8Array }> = [];
    for await (const { message } of iterateMessages(enc, keys.privateKeyPem)) {
      got.push({ channelId: message.channelId, sequence: message.sequence, data: new Uint8Array(message.data) });
    }

    expect(got).toHaveLength(expected.length); // 3 chunks × 4 messages = 12
    for (let i = 0; i < expected.length; i++) {
      expect(got[i]!.channelId).toBe(expected[i]!.channelId);
      expect(got[i]!.sequence).toBe(expected[i]!.sequence);
      expect(got[i]!.data).toEqual(expected[i]!.data);
    }
  });
});

// --- scan helpers ---

function readAttachmentNames(mcap: Uint8Array): string[] {
  const view = new DataView(mcap.buffer, mcap.byteOffset);
  const names: string[] = [];
  let pos = 8; // skip magic
  while (pos + 9 <= mcap.length) {
    const opcode = mcap[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    if (opcode === 0x09) {
      const r = new BinaryReader(mcap.slice(pos + 9, pos + 9 + length));
      r.readUint64(); // log_time
      r.readUint64(); // create_time
      names.push(r.readString());
    }
    pos += 9 + length;
  }
  return names;
}

function readMcapHeader(mcap: Uint8Array): { profile: string; library: string } {
  const view = new DataView(mcap.buffer, mcap.byteOffset);
  let pos = 8; // skip magic
  while (pos + 9 <= mcap.length) {
    const opcode = mcap[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    if (opcode === 0x01) {
      const r = new BinaryReader(mcap.slice(pos + 9, pos + 9 + length));
      return { profile: r.readString(), library: r.readString() };
    }
    pos += 9 + length;
  }
  throw new Error("no Header record found in MCAP");
}

function readMetadataNames(mcap: Uint8Array): string[] {
  const view = new DataView(mcap.buffer, mcap.byteOffset);
  const names: string[] = [];
  let pos = 8;
  while (pos + 9 <= mcap.length) {
    const opcode = mcap[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    if (opcode === 0x0c) {
      const r = new BinaryReader(mcap.slice(pos + 9, pos + 9 + length));
      names.push(r.readString());
    }
    pos += 9 + length;
  }
  return names;
}

function readMetadataRecords(mcap: Uint8Array): { name: string; metadata: Map<string, string> }[] {
  const view = new DataView(mcap.buffer, mcap.byteOffset);
  const recs: { name: string; metadata: Map<string, string> }[] = [];
  let pos = 8;
  while (pos + 9 <= mcap.length) {
    const opcode = mcap[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    if (opcode === 0x0c) {
      const r = new BinaryReader(mcap.slice(pos + 9, pos + 9 + length));
      const name = r.readString();
      const count = r.readUint32();
      const metadata = new Map<string, string>();
      for (let i = 0; i < count; i++) {
        metadata.set(r.readString(), r.readString());
      }
      recs.push({ name, metadata });
    }
    pos += 9 + length;
  }
  return recs;
}

function readStatisticsMetadataCount(mcap: Uint8Array): number {
  const view = new DataView(mcap.buffer, mcap.byteOffset);
  let pos = 8;
  while (pos + 9 <= mcap.length) {
    const opcode = mcap[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    if (opcode === 0x0a) {
      const r = new BinaryReader(mcap.slice(pos + 9, pos + 9 + length));
      r.readUint64(); // message_count
      r.readUint16(); // schema_count
      r.readUint32(); // channel_count
      r.readUint32(); // attachment_count
      return r.readUint32(); // metadata_count
    }
    pos += 9 + length;
  }
  throw new Error("no Statistics record found");
}

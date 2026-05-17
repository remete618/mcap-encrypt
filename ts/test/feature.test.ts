import { describe, it, expect, beforeAll } from "vitest";
import {
  encryptMcap,
  decryptMcap,
  iterateMessages,
  generateKeyPair,
  type KeyPair,
} from "../src/index.js";
import { BinaryReader } from "../src/binary.js";
import { decodeEncryptedChunk } from "../src/chunk.js";
import { decodeEncryptedAttachment } from "../src/attachment.js";
import {
  OP_ENCRYPTED_ATTACHMENT,
} from "../src/record.js";
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

describe("nonce uniqueness", () => {
  it("every EncryptedChunk has a distinct 24-byte nonce", async () => {
    const { mcap: plain } = buildMultiChunkMcap(6, 5);
    const enc = await encryptMcap(plain, keys.publicKeyPem);

    const nonces = extractNonces(enc);
    expect(nonces.length).toBeGreaterThanOrEqual(6);

    const unique = new Set(nonces);
    expect(unique.size).toBe(nonces.length);

    // Each nonce is 24 bytes (XChaCha20-Poly1305), so 48 hex chars.
    for (const n of nonces) {
      expect(n).toHaveLength(48);
    }
  });
});

describe("encrypted attachment round-trip", () => {
  it("attachment data is faithfully preserved through encrypt/decrypt", async () => {
    const plain = buildTestMcapWithAttachment(); // contains config.json with {"k":"v"}
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    const dec = await decryptMcap(enc, keys.privateKeyPem);

    const attaches = readAttachmentData(dec);
    expect(attaches.has("config.json")).toBe(true);
    const data = attaches.get("config.json")!;
    expect(new TextDecoder().decode(data)).toBe('{"k":"v"}');
  });

  it("encrypted file contains 0x82 EncryptedAttachment record (not plaintext 0x09)", async () => {
    const plain = buildTestMcapWithAttachment();
    const enc = await encryptMcap(plain, keys.publicKeyPem);

    const opcodes = scanOpcodes(enc);
    expect(opcodes).toContain(0x82);
    // The user attachment must NOT appear as a raw plaintext attachment.
    // (0x09 records may still exist for wrapped key attachments, but the
    //  config.json data must not be readable as plain bytes in the file.)
    const attNames = readAttachmentNames(enc);
    expect(attNames).not.toContain("config.json");
  });

  it("attachment data is not visible in plaintext inside the encrypted file", async () => {
    const plain = buildTestMcapWithAttachment();
    const enc = await encryptMcap(plain, keys.publicKeyPem);

    const needle = new TextEncoder().encode('{"k":"v"}');
    expect(containsSubsequence(enc, needle)).toBe(false);
  });
});

describe("re-encrypt guard", () => {
  it("throws a clear error when encrypting an already-encrypted MCAP", async () => {
    const plain = buildTestMcapWithAttachment();
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    await expect(encryptMcap(enc, keys.publicKeyPem)).rejects.toThrow(
      /already encrypted/,
    );
  });
});

describe("encrypted attachment tamper rejection", () => {
  it("rejects decryption when ciphertext is flipped", async () => {
    const plain = buildTestMcapWithAttachment();
    const enc = await encryptMcap(plain, keys.publicKeyPem);

    const tampered = tamperEncryptedAttachmentData(enc);
    await expect(decryptMcap(tampered, keys.privateKeyPem)).rejects.toThrow(
      /authentication failed/,
    );
  });

  it("rejects decryption when attachment name is altered", async () => {
    const plain = buildTestMcapWithAttachment();
    const enc = await encryptMcap(plain, keys.publicKeyPem);

    const tampered = tamperEncryptedAttachmentName(enc);
    await expect(decryptMcap(tampered, keys.privateKeyPem)).rejects.toThrow(
      /authentication failed/,
    );
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

function extractNonces(enc: Uint8Array): string[] {
  const view = new DataView(enc.buffer, enc.byteOffset);
  const nonces: string[] = [];
  let pos = 8; // skip magic
  while (pos + 9 <= enc.length) {
    const opcode = enc[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    if (opcode === 0x81) {
      const chunk = decodeEncryptedChunk(enc.slice(pos + 9, pos + 9 + length));
      nonces.push(Array.from(chunk.nonce).map((b) => b.toString(16).padStart(2, "0")).join(""));
    }
    pos += 9 + length;
  }
  return nonces;
}

function readAttachmentData(mcap: Uint8Array): Map<string, Uint8Array> {
  const view = new DataView(mcap.buffer, mcap.byteOffset);
  const result = new Map<string, Uint8Array>();
  let pos = 8;
  while (pos + 9 <= mcap.length) {
    const opcode = mcap[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    if (opcode === 0x09) {
      const r = new BinaryReader(mcap.slice(pos + 9, pos + 9 + length));
      r.readUint64(); // log_time
      r.readUint64(); // create_time
      const name = r.readString();
      r.readString(); // media_type
      const dataSize = Number(r.readUint64());
      const data = new Uint8Array(r.readBytes(dataSize));
      result.set(name, data);
    }
    pos += 9 + length;
  }
  return result;
}

function scanOpcodes(mcap: Uint8Array): number[] {
  const view = new DataView(mcap.buffer, mcap.byteOffset);
  const opcodes: number[] = [];
  let pos = 8;
  while (pos + 9 <= mcap.length) {
    const opcode = mcap[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    opcodes.push(opcode);
    pos += 9 + length;
  }
  return opcodes;
}

function containsSubsequence(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

// Finds the first 0x82 EncryptedAttachment record and flips a byte in its ciphertext.
function tamperEncryptedAttachmentData(mcap: Uint8Array): Uint8Array {
  const view = new DataView(mcap.buffer, mcap.byteOffset);
  const copy = mcap.slice();
  let pos = 8;
  while (pos + 9 <= copy.length) {
    const opcode = copy[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    if (opcode === OP_ENCRYPTED_ATTACHMENT) {
      const payload = copy.slice(pos + 9, pos + 9 + length);
      const ea = decodeEncryptedAttachment(payload);
      // Flip the last byte of the encrypted data (the Poly1305 tag area).
      const lastIdx = ea.encryptedData.length - 1;
      ea.encryptedData[lastIdx]! ^= 0xff;
      // Re-encode into the copy.
      const r = new BinaryReader(payload);
      // Skip past name, mediaType, logTime, createTime, nonce to find encryptedData offset.
      r.readString(); r.readString(); r.readUint64(); r.readUint64();
      r.readPrefixedBytes(); // nonce
      const encDataStart = r.offset; // points at the 4-byte length prefix of encryptedData
      const encDataOffset = pos + 9 + encDataStart + 4 + lastIdx;
      copy[encDataOffset]! ^= 0xff;
      return copy;
    }
    pos += 9 + length;
  }
  throw new Error("no EncryptedAttachment record found");
}

// Finds the first 0x82 record and flips a byte in the plaintext name field.
function tamperEncryptedAttachmentName(mcap: Uint8Array): Uint8Array {
  const view = new DataView(mcap.buffer, mcap.byteOffset);
  const copy = mcap.slice();
  let pos = 8;
  while (pos + 9 <= copy.length) {
    const opcode = copy[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    if (opcode === OP_ENCRYPTED_ATTACHMENT) {
      // name is at byte 0 of the payload: 4-byte length prefix + bytes.
      // Flip the first byte of the name string itself (offset 4 within payload).
      const nameByteOffset = pos + 9 + 4; // skip record header (9) + string length prefix (4)
      copy[nameByteOffset]! ^= 0x01;
      return copy;
    }
    pos += 9 + length;
  }
  throw new Error("no EncryptedAttachment record found");
}

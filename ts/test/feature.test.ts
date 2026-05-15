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
  buildEmptyMcap,
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

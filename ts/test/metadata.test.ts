import { describe, it, expect, beforeAll } from "vitest";
import { encryptMcap, decryptMcap, generateKeyPair, type KeyPair } from "../src/index.js";
import { buildTestMcapWithMetadata } from "./helpers.js";
import { OP_ENCRYPTED_METADATA } from "../src/record.js";
import { parseMetadata } from "../src/mcap.js";
import { BinaryReader } from "../src/binary.js";

let keys: KeyPair;
let metaMcap: Uint8Array;

beforeAll(async () => {
  keys = await generateKeyPair();
  metaMcap = buildTestMcapWithMetadata();
});

// Helper: collect all OP_METADATA records from a flat MCAP byte stream.
function collectMetadataRecords(data: Uint8Array): Array<{ name: string; metadata: Map<string, string> }> {
  const r = new BinaryReader(data.subarray(8)); // skip magic
  const results: Array<{ name: string; metadata: Map<string, string> }> = [];
  while (r.remaining >= 9) {
    const opcode = r.readUint8();
    const length = r.readUint64();
    const recData = new Uint8Array(r.readBytes(Number(length)));
    if (opcode === 0x0c) { // OP_METADATA
      results.push(parseMetadata(recData));
    }
  }
  return results;
}

// Helper: check whether a byte sequence contains the given text.
function contains(data: Uint8Array, text: string): boolean {
  const needle = new TextEncoder().encode(text);
  outer: for (let i = 0; i <= data.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (data[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

describe("metadata plaintext (default mode)", () => {
  it("passes metadata through unchanged", async () => {
    const enc = await encryptMcap(metaMcap, keys.publicKeyPem);
    const dec = await decryptMcap(enc, keys.privateKeyPem);
    const recs = collectMetadataRecords(dec);
    expect(recs).toHaveLength(1);
    expect(recs[0]!.name).toBe("robot_info");
    expect(recs[0]!.metadata.get("serial")).toBe("ABC-123");
  });
});

describe("metadata encrypt mode", () => {
  it("round-trips metadata with name visible in encrypted file", async () => {
    const enc = await encryptMcap(metaMcap, keys.publicKeyPem, { metadataMode: "encrypt" });
    // Name must be visible in the encrypted file.
    expect(contains(enc, "robot_info")).toBe(true);
    // But value must NOT be visible.
    expect(contains(enc, "ABC-123")).toBe(false);
    // Encrypted file must contain opcode 0x83.
    expect(Array.from(enc).includes(OP_ENCRYPTED_METADATA)).toBe(true);

    const dec = await decryptMcap(enc, keys.privateKeyPem);
    const recs = collectMetadataRecords(dec);
    expect(recs).toHaveLength(1);
    expect(recs[0]!.name).toBe("robot_info");
    expect(recs[0]!.metadata.get("serial")).toBe("ABC-123");
    expect(recs[0]!.metadata.get("version")).toBe("1.2.3");
  });

  it("rejects ciphertext tamper", async () => {
    const enc = await encryptMcap(metaMcap, keys.publicKeyPem, { metadataMode: "encrypt" });
    const tampered = new Uint8Array(enc);
    tampered[Math.floor(tampered.length / 2)] ^= 0xff;
    await expect(decryptMcap(tampered, keys.privateKeyPem)).rejects.toThrow();
  });
});

describe("metadata encrypt-all mode", () => {
  it("round-trips with both name and value invisible", async () => {
    const enc = await encryptMcap(metaMcap, keys.publicKeyPem, { metadataMode: "encrypt-all" });
    // Neither name nor value should be visible.
    expect(contains(enc, "robot_info")).toBe(false);
    expect(contains(enc, "ABC-123")).toBe(false);
    // Encrypted file must contain opcode 0x83.
    expect(Array.from(enc).includes(OP_ENCRYPTED_METADATA)).toBe(true);

    const dec = await decryptMcap(enc, keys.privateKeyPem);
    const recs = collectMetadataRecords(dec);
    expect(recs).toHaveLength(1);
    expect(recs[0]!.name).toBe("robot_info");
    expect(recs[0]!.metadata.get("serial")).toBe("ABC-123");
    expect(recs[0]!.metadata.get("version")).toBe("1.2.3");
  });

  it("rejects ciphertext tamper", async () => {
    const enc = await encryptMcap(metaMcap, keys.publicKeyPem, { metadataMode: "encrypt-all" });
    const tampered = new Uint8Array(enc);
    tampered[Math.floor(tampered.length / 2)] ^= 0xff;
    await expect(decryptMcap(tampered, keys.privateKeyPem)).rejects.toThrow();
  });
});

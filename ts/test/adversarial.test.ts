/**
 * Adversarial tests: verifies every field covered by the AEAD additional data
 * (AAD) is actually bound to the authentication tag.
 *
 * Structure:
 *  Part 1 – chunkAAD unit tests (8): pure function, no encrypt/decrypt
 *  Part 2 – end-to-end chunk field tamper (6): decode → modify → splice → reject
 *  Part 3 – fileId tamper via wrapped-key attachment (1)
 *  Part 4 – chunk reordering via chunkIdx (1)
 *
 * Note on compression: the test MCAP uses compression="" (no compression).
 * Replacing "" with any non-empty string changes the encoded byte length, making
 * in-place splice impossible. The compression field is proven AAD-bound by the
 * unit test in Part 1; an end-to-end splice test is omitted for that field only.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { encryptMcap, decryptMcap, generateKeyPair, type KeyPair } from "../src/index.js";
import { chunkAAD } from "../src/encrypt.js";
import {
  decodeEncryptedChunk,
  encodeEncryptedChunk,
  type EncryptedChunk,
} from "../src/chunk.js";
import { BinaryReader } from "../src/binary.js";
import { buildMultiChunkMcap } from "./helpers.js";

let keys: KeyPair;

beforeAll(async () => {
  keys = await generateKeyPair();
});

// ─── Part 1: chunkAAD field coverage ──────────────────────────────────────────
//
// Directly tests that each field contributes distinct bytes to the AAD output.
// This proves the field is included; Part 2 proves it is actually verified
// during decryption.

describe("chunkAAD field coverage", () => {
  const fileId = new Uint8Array(16).fill(0xaa);

  it("fileId is bound in AAD", () => {
    const other = new Uint8Array(16).fill(0xbb);
    expect(chunkAAD(fileId, 0n, "key-1", "", 0n, 0, 0n, 0n)).not.toEqual(
      chunkAAD(other, 0n, "key-1", "", 0n, 0, 0n, 0n),
    );
  });

  it("chunkIdx is bound in AAD", () => {
    expect(chunkAAD(fileId, 0n, "key-1", "", 0n, 0, 0n, 0n)).not.toEqual(
      chunkAAD(fileId, 1n, "key-1", "", 0n, 0, 0n, 0n),
    );
  });

  it("slotId is bound in AAD", () => {
    expect(chunkAAD(fileId, 0n, "key-1", "", 0n, 0, 0n, 0n)).not.toEqual(
      chunkAAD(fileId, 0n, "key-2", "", 0n, 0, 0n, 0n),
    );
  });

  it("compression is bound in AAD", () => {
    expect(chunkAAD(fileId, 0n, "key-1", "zstd", 0n, 0, 0n, 0n)).not.toEqual(
      chunkAAD(fileId, 0n, "key-1", "lz4", 0n, 0, 0n, 0n),
    );
  });

  it("uncompressedSize is bound in AAD", () => {
    expect(chunkAAD(fileId, 0n, "key-1", "", 100n, 0, 0n, 0n)).not.toEqual(
      chunkAAD(fileId, 0n, "key-1", "", 101n, 0, 0n, 0n),
    );
  });

  it("uncompressedCrc is bound in AAD", () => {
    expect(chunkAAD(fileId, 0n, "key-1", "", 0n, 1, 0n, 0n)).not.toEqual(
      chunkAAD(fileId, 0n, "key-1", "", 0n, 2, 0n, 0n),
    );
  });

  it("startTime is bound in AAD", () => {
    expect(chunkAAD(fileId, 0n, "key-1", "", 0n, 0, 1000n, 0n)).not.toEqual(
      chunkAAD(fileId, 0n, "key-1", "", 0n, 0, 2000n, 0n),
    );
  });

  it("endTime is bound in AAD", () => {
    expect(chunkAAD(fileId, 0n, "key-1", "", 0n, 0, 0n, 1000n)).not.toEqual(
      chunkAAD(fileId, 0n, "key-1", "", 0n, 0, 0n, 2000n),
    );
  });
});

// ─── Part 2: end-to-end chunk AAD tamper rejection ────────────────────────────

describe("chunk AAD end-to-end tamper rejection", () => {
  it("messageStartTime tamper causes authentication failure", async () => {
    const { mcap: plain } = buildMultiChunkMcap(2, 5);
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    const tampered = withTamperedChunk(enc, (ec) => ({
      ...ec,
      messageStartTime: ec.messageStartTime ^ 1n,
    }));
    await expect(decryptMcap(tampered, keys.privateKeyPem)).rejects.toThrow(
      /authentication failed/,
    );
  });

  it("messageEndTime tamper causes authentication failure", async () => {
    const { mcap: plain } = buildMultiChunkMcap(2, 5);
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    const tampered = withTamperedChunk(enc, (ec) => ({
      ...ec,
      messageEndTime: ec.messageEndTime ^ 1n,
    }));
    await expect(decryptMcap(tampered, keys.privateKeyPem)).rejects.toThrow(
      /authentication failed/,
    );
  });

  it("uncompressedSize tamper causes authentication failure", async () => {
    const { mcap: plain } = buildMultiChunkMcap(2, 5);
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    const tampered = withTamperedChunk(enc, (ec) => ({
      ...ec,
      uncompressedSize: ec.uncompressedSize ^ 1n,
    }));
    await expect(decryptMcap(tampered, keys.privateKeyPem)).rejects.toThrow(
      /authentication failed/,
    );
  });

  it("uncompressedCrc tamper causes authentication failure", async () => {
    const { mcap: plain } = buildMultiChunkMcap(2, 5);
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    // XOR the CRC to a non-zero value; the AEAD used crc=0 in AAD, so any
    // change to this field makes the AAD computed at decrypt time differ.
    const tampered = withTamperedChunk(enc, (ec) => ({
      ...ec,
      uncompressedCrc: ec.uncompressedCrc ^ 0xdeadbeef,
    }));
    await expect(decryptMcap(tampered, keys.privateKeyPem)).rejects.toThrow(
      /authentication failed/,
    );
  });

  it("slotId tamper causes authentication failure", async () => {
    const { mcap: plain } = buildMultiChunkMcap(2, 5);
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    // Change the last char of slotId "key-1" → "key-0" (same byte length).
    // XOR 0xff would create a non-ASCII byte, expanding the UTF-8 encoding.
    const tampered = withTamperedChunk(enc, (ec) => ({
      ...ec,
      slotId: ec.slotId.slice(0, -1) + String.fromCharCode(ec.slotId.charCodeAt(ec.slotId.length - 1) ^ 0x01),
    }));
    await expect(decryptMcap(tampered, keys.privateKeyPem)).rejects.toThrow(
      /authentication failed/,
    );
  });

  it("nonce tamper causes authentication failure", async () => {
    const { mcap: plain } = buildMultiChunkMcap(2, 5);
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    const tampered = withTamperedChunk(enc, (ec) => {
      const nonce = new Uint8Array(ec.nonce);
      nonce[0]! ^= 0xff;
      return { ...ec, nonce };
    });
    await expect(decryptMcap(tampered, keys.privateKeyPem)).rejects.toThrow(
      /authentication failed/,
    );
  });
});

// ─── Part 3: fileId tamper via wrapped-key attachment ─────────────────────────

describe("fileId tamper rejected", () => {
  it("flipping fileId in the wrapped-key attachment causes authentication failure", async () => {
    const { mcap: plain } = buildMultiChunkMcap(2, 5);
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    const tampered = tamperWrappedKeyFileId(enc);
    await expect(decryptMcap(tampered, keys.privateKeyPem)).rejects.toThrow(
      /authentication failed/,
    );
  });
});

// ─── Part 4: chunk reordering via chunkIdx ────────────────────────────────────

describe("chunk reordering rejected", () => {
  it("swapping two EncryptedChunk records causes authentication failure", async () => {
    const { mcap: plain } = buildMultiChunkMcap(2, 5);
    const enc = await encryptMcap(plain, keys.publicKeyPem);
    // Chunk 0 was authenticated with chunkIdx=0 in AAD; after the swap it sits
    // at position 1 and decrypt will try chunkIdx=0 on what is actually chunk 1.
    const tampered = swapFirstTwoChunks(enc);
    await expect(decryptMcap(tampered, keys.privateKeyPem)).rejects.toThrow(
      /authentication failed/,
    );
  });
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Finds the first 0x81 record, decodes it, applies `mod`, re-encodes, and
 * splices the result back in-place. Throws if the re-encoded length differs
 * (which would corrupt the record length field in the file header).
 */
function withTamperedChunk(
  enc: Uint8Array,
  mod: (ec: EncryptedChunk) => EncryptedChunk,
): Uint8Array {
  const view = new DataView(enc.buffer, enc.byteOffset);
  let pos = 8;
  while (pos + 9 <= enc.length) {
    const opcode = enc[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    if (opcode === 0x81) {
      const originalData = enc.slice(pos + 9, pos + 9 + length);
      const ec = decodeEncryptedChunk(originalData);
      const newData = encodeEncryptedChunk(mod(ec));
      if (newData.length !== length) {
        throw new Error(
          `tampered chunk re-encodes to ${newData.length} bytes but original was ${length}; in-place splice impossible`,
        );
      }
      const copy = enc.slice();
      copy.set(newData, pos + 9);
      return copy;
    }
    pos += 9 + length;
  }
  throw new Error("no EncryptedChunk (0x81) record found");
}

/**
 * Locates the wrapped-key attachment (0x09 with name "mcap_encryption_key"),
 * navigates to the WrappedKeyData payload, and flips the first byte of the
 * 16-byte fileId field. The fileId is included in the AAD of every
 * EncryptedChunk, so any modification must cause authentication to fail.
 */
function tamperWrappedKeyFileId(enc: Uint8Array): Uint8Array {
  const view = new DataView(enc.buffer, enc.byteOffset);
  let pos = 8;
  while (pos + 9 <= enc.length) {
    const opcode = enc[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    if (opcode === 0x09) {
      const payload = enc.slice(pos + 9, pos + 9 + length);
      const r = new BinaryReader(payload);
      r.readUint64(); // logTime
      r.readUint64(); // createTime
      const name = r.readString();
      if (name === "mcap_encryption_key") {
        r.readString();  // mediaType
        r.readUint64();  // dataSize
        // r.offset now points to the start of WrappedKeyData:
        //   version (1 byte) | fileId (16 bytes) | ...
        const fileIdByte0AbsOffset = pos + 9 + r.offset + 1; // skip version byte
        const copy = enc.slice();
        copy[fileIdByte0AbsOffset]! ^= 0xff;
        return copy;
      }
    }
    pos += 9 + length;
  }
  throw new Error("wrapped-key attachment not found in encrypted file");
}

/**
 * Swaps the positions of the first two EncryptedChunk (0x81) records.
 * After the swap, decrypting what is now at position 0 will use chunkIdx=0,
 * but the ciphertext was authenticated with chunkIdx=1 in its AAD, causing
 * AEAD authentication to fail on the first decrypted chunk.
 */
function swapFirstTwoChunks(enc: Uint8Array): Uint8Array {
  const view = new DataView(enc.buffer, enc.byteOffset);
  const chunks: Array<{ start: number; end: number }> = [];
  let pos = 8;
  while (pos + 9 <= enc.length) {
    const opcode = enc[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    if (opcode === 0x81) {
      chunks.push({ start: pos, end: pos + 9 + length });
      if (chunks.length === 2) break;
    }
    pos += 9 + length;
  }
  if (chunks.length < 2) {
    throw new Error(`need at least 2 EncryptedChunk records; found ${chunks.length}`);
  }
  const [c0, c1] = chunks as [{ start: number; end: number }, { start: number; end: number }];
  // Output order: preamble | chunk1 bytes | gap between chunks | chunk0 bytes | tail
  const parts = [
    enc.slice(0, c0.start),
    enc.slice(c1.start, c1.end),   // chunk 1 now at position 0
    enc.slice(c0.end, c1.start),   // records between the two chunks (if any)
    enc.slice(c0.start, c0.end),   // chunk 0 now at position 1
    enc.slice(c1.end),
  ];
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

import { describe, it, expect, beforeAll } from "vitest";
import {
  encryptMcap,
  inspectMcap,
  generateKeyPair,
  generateX25519KeyPair,
  type KeyPair,
  type X25519KeyPair,
} from "../src/index.js";
import { buildTestMcap } from "./helpers.js";

let rsaA: KeyPair;
let rsaB: KeyPair;
let x25519A: X25519KeyPair;
let testMcap: Uint8Array;

beforeAll(async () => {
  [rsaA, rsaB, x25519A] = await Promise.all([
    generateKeyPair(),
    generateKeyPair(),
    generateX25519KeyPair(),
  ]);
  testMcap = buildTestMcap();
}, 60_000);

describe("inspectMcap", () => {
  it("encrypted RSA file: reports isEncrypted, format version, file_id, chunk count, compression, recipient", async () => {
    const enc = await encryptMcap(testMcap, rsaA.publicKeyPem);
    const res = inspectMcap(enc);

    expect(res.isEncrypted).toBe(true);
    expect(res.formatVersion).toBe(3);
    expect(res.fileId).toBeInstanceOf(Uint8Array);
    expect(res.fileId!.length).toBe(16);
    expect(res.chunkCount).toBeGreaterThan(0);
    expect(res.encryptedChunkCount).toBe(res.chunkCount);
    // buildTestMcap uses no compression; encryptMcap preserves the source compression.
    expect(typeof res.compression).toBe("string");
    expect(res.recipients).toHaveLength(1);
    expect(res.recipients[0]!.kekAlg).toBe("rsa-oaep-sha256");
    expect(res.recipients[0]!.algorithm).toBe("xchacha20poly1305");
    expect(res.recipients[0]!.keyId).toMatch(/^[0-9a-f]{64}$/);
  });

  it("multi-recipient file: reports all recipients with correct algorithms", async () => {
    const enc = await encryptMcap(testMcap, [rsaB.publicKeyPem, x25519A.publicKeyPem]);
    const res = inspectMcap(enc);

    expect(res.isEncrypted).toBe(true);
    expect(res.recipients).toHaveLength(2);

    const algSet = new Set(res.recipients.map((r) => r.kekAlg));
    expect(algSet.has("rsa-oaep-sha256")).toBe(true);
    expect(algSet.has("x25519-hkdf-xchacha20poly1305")).toBe(true);
  });

  it("plain (non-encrypted) MCAP: reports isEncrypted=false and no recipients", () => {
    const res = inspectMcap(testMcap);

    expect(res.isEncrypted).toBe(false);
    expect(res.fileId).toBeNull();
    expect(res.chunkCount).toBe(0);
    expect(res.recipients).toHaveLength(0);
  });

  it("X25519 file: reports correct kekAlg", async () => {
    const enc = await encryptMcap(testMcap, x25519A.publicKeyPem);
    const res = inspectMcap(enc);

    expect(res.isEncrypted).toBe(true);
    expect(res.recipients).toHaveLength(1);
    expect(res.recipients[0]!.kekAlg).toBe("x25519-hkdf-xchacha20poly1305");
  });
});

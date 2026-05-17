import { describe, it, expect, beforeAll } from "vitest";
import {
  encryptMcap,
  decryptMcap,
  rotateMcapKeys,
  generateKeyPair,
  generateX25519KeyPair,
  type KeyPair,
  type X25519KeyPair,
} from "../src/index.js";
import { buildTestMcap, collectMessages } from "./helpers.js";

let keysA: KeyPair;
let testMcap: Uint8Array;

beforeAll(async () => {
  keysA = await generateKeyPair();
  testMcap = buildTestMcap();
});

describe("rotateMcapKeys", () => {
  it("round-trip: encrypt with A, rotate to B, decrypt with B — messages match", async () => {
    const keysB = await generateKeyPair();

    const enc = await encryptMcap(testMcap, keysA.publicKeyPem);
    const rotated = await rotateMcapKeys(enc, keysA.privateKeyPem, keysB.publicKeyPem);
    const dec = await decryptMcap(rotated, keysB.privateKeyPem);

    const orig = collectMessages(testMcap);
    const got = collectMessages(dec);

    expect(got).toHaveLength(orig.length);
    for (let i = 0; i < orig.length; i++) {
      expect(got[i]!.channelId).toBe(orig[i]!.channelId);
      expect(got[i]!.sequence).toBe(orig[i]!.sequence);
      expect(got[i]!.logTime).toBe(orig[i]!.logTime);
      expect(got[i]!.data).toEqual(orig[i]!.data);
    }
  });

  it("old key is rejected after rotation", async () => {
    const keysB = await generateKeyPair();

    const enc = await encryptMcap(testMcap, keysA.publicKeyPem);
    const rotated = await rotateMcapKeys(enc, keysA.privateKeyPem, keysB.publicKeyPem);

    // Key A must no longer decrypt the rotated file.
    await expect(decryptMcap(rotated, keysA.privateKeyPem)).rejects.toThrow();
    // Key B must succeed.
    await expect(decryptMcap(rotated, keysB.privateKeyPem)).resolves.toBeTruthy();
  });

  it("multi-recipient: both B and C can decrypt and get identical messages", async () => {
    const keysB: X25519KeyPair = await generateX25519KeyPair();
    const keysC: X25519KeyPair = await generateX25519KeyPair();

    const enc = await encryptMcap(testMcap, keysA.publicKeyPem);
    const rotated = await rotateMcapKeys(enc, keysA.privateKeyPem, [
      keysB.publicKeyPem,
      keysC.publicKeyPem,
    ]);

    const decB = await decryptMcap(rotated, keysB.privateKeyPem);
    const decC = await decryptMcap(rotated, keysC.privateKeyPem);

    const orig = collectMessages(testMcap);
    const gotB = collectMessages(decB);
    const gotC = collectMessages(decC);

    expect(gotB).toHaveLength(orig.length);
    expect(gotC).toHaveLength(orig.length);
    for (let i = 0; i < orig.length; i++) {
      expect(gotB[i]!.data).toEqual(orig[i]!.data);
      expect(gotC[i]!.data).toEqual(orig[i]!.data);
    }
  });

  it("rejects a plain (non-encrypted) MCAP with a clear error", async () => {
    const keysB = await generateKeyPair();
    await expect(
      rotateMcapKeys(testMcap, keysA.privateKeyPem, keysB.publicKeyPem),
    ).rejects.toThrow(/wrapped key attachment|old private key/);
  });

  it("rejects wrong old private key", async () => {
    const keysB = await generateKeyPair();
    const keysWrong = await generateKeyPair();

    const enc = await encryptMcap(testMcap, keysA.publicKeyPem);
    await expect(
      rotateMcapKeys(enc, keysWrong.privateKeyPem, keysB.publicKeyPem),
    ).rejects.toThrow(/old private key|recipient/);
  });

  it("X25519 round-trip: encrypt with X25519 A, rotate to X25519 B, decrypt with B", async () => {
    const kA: X25519KeyPair = await generateX25519KeyPair();
    const kB: X25519KeyPair = await generateX25519KeyPair();

    const enc = await encryptMcap(testMcap, kA.publicKeyPem);
    const rotated = await rotateMcapKeys(enc, kA.privateKeyPem, kB.publicKeyPem);
    const dec = await decryptMcap(rotated, kB.privateKeyPem);

    const orig = collectMessages(testMcap);
    const got = collectMessages(dec);
    expect(got).toHaveLength(orig.length);
    for (let i = 0; i < orig.length; i++) {
      expect(got[i]!.data).toEqual(orig[i]!.data);
    }
  });
});

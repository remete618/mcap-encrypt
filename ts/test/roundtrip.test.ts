import { describe, it, expect, beforeAll } from "vitest";
import { encryptMcap, decryptMcap, iterateMessages, generateKeyPair, type KeyPair } from "../src/index.js";
import { buildTestMcap, buildNonChunkedMcap, collectMessages } from "./helpers.js";

let keys: KeyPair;
let testMcap: Uint8Array;

beforeAll(async () => {
  keys = await generateKeyPair();
  testMcap = buildTestMcap();
});

describe("encryptMcap / decryptMcap", () => {
  it("round-trips all messages correctly", async () => {
    const enc = await encryptMcap(testMcap, keys.publicKeyPem);
    expect(enc).not.toEqual(testMcap);

    const dec = await decryptMcap(enc, keys.privateKeyPem);
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

  it("fails with the wrong private key", async () => {
    const enc = await encryptMcap(testMcap, keys.publicKeyPem);
    const other = await generateKeyPair();
    await expect(decryptMcap(enc, other.privateKeyPem)).rejects.toThrow();
  });

  it("encrypted output contains opcode 0x81 and differs from plaintext", async () => {
    const enc = await encryptMcap(testMcap, keys.publicKeyPem);
    expect(enc).not.toEqual(testMcap);
    expect(Array.from(enc.slice(8)).includes(0x81)).toBe(true);
  });
});

describe("iterateMessages", () => {
  it("yields all messages with correct schema and channel", async () => {
    const enc = await encryptMcap(testMcap, keys.publicKeyPem);
    const results: { topic: string; seq: number }[] = [];
    for await (const { channel, message } of iterateMessages(enc, keys.privateKeyPem)) {
      results.push({ topic: channel.topic, seq: message.sequence });
    }
    expect(results).toHaveLength(100);
    expect(results.filter((r) => r.topic === "/sensor")).toHaveLength(50);
    expect(results.filter((r) => r.topic === "/cmd")).toHaveLength(50);
  });
});

describe("multi-recipient", () => {
  it("any recipient key can decrypt the same file", async () => {
    const keysA = await generateKeyPair();
    const keysB = await generateKeyPair();

    const enc = await encryptMcap(testMcap, [keysA.publicKeyPem, keysB.publicKeyPem]);

    const decA = await decryptMcap(enc, keysA.privateKeyPem);
    const decB = await decryptMcap(enc, keysB.privateKeyPem);

    const orig = collectMessages(testMcap);
    const gotA = collectMessages(decA);
    const gotB = collectMessages(decB);

    expect(gotA).toHaveLength(orig.length);
    expect(gotB).toHaveLength(orig.length);
    for (let i = 0; i < orig.length; i++) {
      expect(gotA[i]!.data).toEqual(orig[i]!.data);
      expect(gotB[i]!.data).toEqual(orig[i]!.data);
    }
  });

  it("rejects a key that is not a recipient", async () => {
    const keysA = await generateKeyPair();
    const keysB = await generateKeyPair();
    const keysC = await generateKeyPair();

    const enc = await encryptMcap(testMcap, [keysA.publicKeyPem, keysB.publicKeyPem]);
    await expect(decryptMcap(enc, keysC.privateKeyPem)).rejects.toThrow(/2 recipient/);
  });
});

describe("input validation", () => {
  it("rejects non-chunked MCAP input", async () => {
    const nonChunked = buildNonChunkedMcap();
    await expect(encryptMcap(nonChunked, keys.publicKeyPem)).rejects.toThrow(/chunked/);
  });
});

describe("adversarial", () => {
  it("fails when ciphertext is tampered", async () => {
    const enc = await encryptMcap(testMcap, keys.publicKeyPem);
    const tampered = tamperedCiphertext(enc);
    await expect(decryptMcap(tampered, keys.privateKeyPem)).rejects.toThrow();
  });

  it("fails when the wrapped key attachment is absent", async () => {
    const enc = await encryptMcap(testMcap, keys.publicKeyPem);
    const stripped = stripAttachment(enc);
    await expect(decryptMcap(stripped, keys.privateKeyPem)).rejects.toThrow(
      /wrapped key attachment/,
    );
  });
});

function tamperedCiphertext(data: Uint8Array): Uint8Array {
  const view = new DataView(data.buffer, data.byteOffset);
  let pos = 8;
  while (pos + 9 <= data.length) {
    const opcode = data[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    if (opcode === 0x81) {
      const result = new Uint8Array(data);
      result[pos + 9 + length - 1] ^= 0xff;
      return result;
    }
    pos += 9 + length;
  }
  throw new Error("no 0x81 record found");
}

function stripAttachment(data: Uint8Array): Uint8Array {
  const view = new DataView(data.buffer, data.byteOffset);
  const parts: Uint8Array[] = [data.slice(0, 8)];
  let pos = 8;
  while (pos + 9 <= data.length) {
    const opcode = data[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    if (opcode !== 0x09) {
      parts.push(data.slice(pos, pos + 9 + length));
    }
    pos += 9 + length;
  }
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

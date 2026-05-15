import { describe, it, expect, beforeAll } from "vitest";
import { encryptMcap, decryptMcap, iterateMessages, generateKeyPair, type KeyPair } from "../src/index.js";
import { buildTestMcap, collectMessages } from "./helpers.js";

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

import { describe, it, expect, beforeAll } from "vitest";
import { encryptMcap, decryptMcap, iterateMessages, generateKeyPair, type KeyPair } from "../src/index.js";
import { BinaryReader, BinaryWriter } from "../src/binary.js";
import {
  writeMagic,
  writeRecord,
  OP_SCHEMA,
  OP_CHANNEL,
  OP_MESSAGE,
  OP_CHUNK,
  OP_DATA_END,
  OP_FOOTER,
} from "../src/record.js";
import {
  encodeSchema,
  encodeChannel,
  encodeMessage,
  encodeHeader,
  encodeDataEnd,
  encodeFooter,
  parseMessage,
  type Message,
} from "../src/mcap.js";

// Builds a minimal chunked MCAP (no compression) with 2 channels × 50 messages each.
function buildTestMcap(): Uint8Array {
  const w = new BinaryWriter();
  writeMagic(w);
  writeRecord(w, 0x01, encodeHeader("test", ""));

  writeRecord(w, OP_SCHEMA, encodeSchema({
    id: 1, name: "sensor", encoding: "json",
    data: new TextEncoder().encode('{"type":"object"}'),
  }));
  writeRecord(w, OP_SCHEMA, encodeSchema({
    id: 2, name: "cmd", encoding: "json",
    data: new TextEncoder().encode('{"type":"object"}'),
  }));
  writeRecord(w, OP_CHANNEL, encodeChannel({
    id: 1, schemaId: 1, topic: "/sensor", messageEncoding: "json", metadata: new Map(),
  }));
  writeRecord(w, OP_CHANNEL, encodeChannel({
    id: 2, schemaId: 2, topic: "/cmd", messageEncoding: "json", metadata: new Map(),
  }));

  // Build inner message records (flat, no compression).
  const inner = new BinaryWriter();
  let ts = 1_000_000_000n;
  for (let i = 0; i < 50; i++) {
    ts += 1_000_000n;
    writeRecord(inner, OP_MESSAGE, encodeMessage({
      channelId: 1, sequence: i, logTime: ts, publishTime: ts,
      data: new TextEncoder().encode('{"x":1,"y":2}'),
    }));
    writeRecord(inner, OP_MESSAGE, encodeMessage({
      channelId: 2, sequence: i, logTime: ts + 500_000n, publishTime: ts + 500_000n,
      data: new TextEncoder().encode('{"v":42}'),
    }));
  }
  const innerBytes = inner.toUint8Array();

  // Chunk record body: start_time, end_time, uncompressed_size, uncompressed_crc,
  //                    compression (prefixed string), compressed_size (uint64), records.
  const chunkBody = new BinaryWriter();
  chunkBody.writeUint64(1_001_000_000n);
  chunkBody.writeUint64(1_050_500_000n);
  chunkBody.writeUint64(BigInt(innerBytes.length));
  chunkBody.writeUint32(0);
  chunkBody.writeString("");
  chunkBody.writeUint64(BigInt(innerBytes.length));
  chunkBody.writeBytes(innerBytes);
  writeRecord(w, OP_CHUNK, chunkBody.toUint8Array());

  writeRecord(w, OP_DATA_END, encodeDataEnd());
  writeRecord(w, OP_FOOTER, encodeFooter());
  writeMagic(w);
  return w.toUint8Array();
}

// Extracts records bytes from a no-compression Chunk body.
function extractChunkRecords(data: Uint8Array): Uint8Array | null {
  const r = new BinaryReader(data);
  r.readUint64(); r.readUint64(); r.readUint64(); r.readUint32(); // timestamps, sizes, crc
  const compression = r.readString();
  if (compression !== "" && compression !== "none") return null;
  const size = Number(r.readUint64());
  return new Uint8Array(r.readBytes(size));
}

// Reads Message records from a raw record stream (no magic prefix).
function readRecordStream(data: Uint8Array): Message[] {
  const r = new BinaryReader(data);
  const msgs: Message[] = [];
  while (r.remaining >= 9) {
    const opcode = r.readUint8();
    const length = r.readUint64();
    if (Number(length) > r.remaining) break;
    const rec = new Uint8Array(r.readBytes(Number(length)));
    if (opcode === OP_MESSAGE) msgs.push(parseMessage(rec));
  }
  return msgs;
}

// Reads all Message records from a flat or chunked MCAP file (with magic prefix).
function collectMessages(mcap: Uint8Array): Message[] {
  const r = new BinaryReader(mcap);
  r.readBytes(8); // skip magic
  const msgs: Message[] = [];
  while (r.remaining >= 9) {
    const opcode = r.readUint8();
    const length = r.readUint64();
    if (Number(length) > r.remaining) break;
    const data = new Uint8Array(r.readBytes(Number(length)));
    if (opcode === OP_MESSAGE) {
      msgs.push(parseMessage(data));
    } else if (opcode === OP_CHUNK) {
      const inner = extractChunkRecords(data);
      if (inner) msgs.push(...readRecordStream(inner));
    }
  }
  return msgs;
}

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

    expect(got).toHaveLength(orig.length); // 100 messages
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
    // At least one record must have opcode 0x81 (EncryptedChunk).
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

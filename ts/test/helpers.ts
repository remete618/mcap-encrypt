import { BinaryReader, BinaryWriter } from "../src/binary.js";
import { decompressChunkData } from "../src/decompress.js";
import {
  writeMagic,
  writeRecord,
  OP_SCHEMA,
  OP_CHANNEL,
  OP_MESSAGE,
  OP_CHUNK,
  OP_ATTACHMENT,
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

export { type Message };

// Builds a minimal chunked MCAP (no compression) with 2 channels × 50 messages each.
export function buildTestMcap(): Uint8Array {
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

function extractChunkRecords(data: Uint8Array): Uint8Array {
  const r = new BinaryReader(data);
  r.readUint64(); r.readUint64(); r.readUint64(); r.readUint32(); // timestamps, sizes, crc
  const compression = r.readString();
  const size = Number(r.readUint64());
  const compressed = new Uint8Array(r.readBytes(size));
  return decompressChunkData(compressed, compression);
}

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

// Reads all Message records from a flat or chunked MCAP (with magic prefix).
export function collectMessages(mcap: Uint8Array): Message[] {
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
      msgs.push(...readRecordStream(extractChunkRecords(data)));
    }
  }
  return msgs;
}

// Builds a minimal chunked MCAP with profile="ros2", library="test-lib", and a "config.json" attachment.
export function buildTestMcapWithAttachment(): Uint8Array {
  const w = new BinaryWriter();
  writeMagic(w);
  writeRecord(w, 0x01, encodeHeader("ros2", "test-lib"));

  writeRecord(w, OP_SCHEMA, encodeSchema({
    id: 1, name: "sensor", encoding: "json",
    data: new TextEncoder().encode("{}"),
  }));
  writeRecord(w, OP_CHANNEL, encodeChannel({
    id: 1, schemaId: 1, topic: "/sensor", messageEncoding: "json", metadata: new Map(),
  }));

  const inner = new BinaryWriter();
  writeRecord(inner, OP_MESSAGE, encodeMessage({
    channelId: 1, sequence: 0, logTime: 1_000_000n, publishTime: 1_000_000n,
    data: new TextEncoder().encode('{"v":1}'),
  }));
  const innerBytes = inner.toUint8Array();

  const chunkBody = new BinaryWriter();
  chunkBody.writeUint64(1_000_000n);
  chunkBody.writeUint64(1_000_000n);
  chunkBody.writeUint64(BigInt(innerBytes.length));
  chunkBody.writeUint32(0);
  chunkBody.writeString("");
  chunkBody.writeUint64(BigInt(innerBytes.length));
  chunkBody.writeBytes(innerBytes);
  writeRecord(w, OP_CHUNK, chunkBody.toUint8Array());

  const attData = new TextEncoder().encode('{"k":"v"}');
  const attPayload = new BinaryWriter();
  attPayload.writeUint64(500_000n);
  attPayload.writeUint64(0n);
  attPayload.writeString("config.json");
  attPayload.writeString("application/json");
  attPayload.writeUint64(BigInt(attData.length));
  attPayload.writeBytes(attData);
  attPayload.writeUint32(0);
  writeRecord(w, OP_ATTACHMENT, attPayload.toUint8Array());

  writeRecord(w, OP_DATA_END, encodeDataEnd());
  writeRecord(w, OP_FOOTER, encodeFooter());
  writeMagic(w);
  return w.toUint8Array();
}

// Builds a MCAP with header and footer but no messages or chunks.
export function buildEmptyMcap(): Uint8Array {
  const w = new BinaryWriter();
  writeMagic(w);
  writeRecord(w, 0x01, encodeHeader("empty", ""));
  writeRecord(w, OP_DATA_END, encodeDataEnd());
  writeRecord(w, OP_FOOTER, encodeFooter());
  writeMagic(w);
  return w.toUint8Array();
}

// Builds a minimal non-chunked MCAP (raw Message records, no Chunk records).
export function buildNonChunkedMcap(): Uint8Array {
  const w = new BinaryWriter();
  writeMagic(w);
  writeRecord(w, 0x01, encodeHeader("test", ""));
  writeRecord(w, OP_SCHEMA, encodeSchema({
    id: 1, name: "sensor", encoding: "json",
    data: new TextEncoder().encode('{"type":"object"}'),
  }));
  writeRecord(w, OP_CHANNEL, encodeChannel({
    id: 1, schemaId: 1, topic: "/sensor", messageEncoding: "json", metadata: new Map(),
  }));
  writeRecord(w, OP_MESSAGE, encodeMessage({
    channelId: 1, sequence: 0, logTime: 1_000_000_000n, publishTime: 1_000_000_000n,
    data: new TextEncoder().encode('{"x":1}'),
  }));
  writeRecord(w, OP_DATA_END, encodeDataEnd());
  writeRecord(w, OP_FOOTER, encodeFooter());
  writeMagic(w);
  return w.toUint8Array();
}

export function assertMessagesMatch(got: Message[], expected: Message[]): void {
  if (got.length !== expected.length) {
    throw new Error(`message count mismatch: got ${got.length}, expected ${expected.length}`);
  }
  for (let i = 0; i < expected.length; i++) {
    const g = got[i]!;
    const e = expected[i]!;
    if (g.channelId !== e.channelId) throw new Error(`msg[${i}].channelId: ${g.channelId} !== ${e.channelId}`);
    if (g.sequence !== e.sequence) throw new Error(`msg[${i}].sequence: ${g.sequence} !== ${e.sequence}`);
    if (g.logTime !== e.logTime) throw new Error(`msg[${i}].logTime: ${g.logTime} !== ${e.logTime}`);
    if (!bytesEqual(g.data, e.data)) throw new Error(`msg[${i}].data mismatch`);
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return a.every((v, i) => v === b[i]);
}

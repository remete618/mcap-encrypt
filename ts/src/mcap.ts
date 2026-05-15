import { BinaryReader, BinaryWriter } from "./binary.js";

export interface Schema {
  id: number;
  name: string;
  encoding: string;
  data: Uint8Array;
}

export interface Channel {
  id: number;
  schemaId: number;
  topic: string;
  messageEncoding: string;
  metadata: Map<string, string>;
}

export interface Message {
  channelId: number;
  sequence: number;
  logTime: bigint;
  publishTime: bigint;
  data: Uint8Array;
}

export function parseSchema(data: Uint8Array): Schema {
  const r = new BinaryReader(data);
  const id = r.readUint16();
  const name = r.readString();
  const encoding = r.readString();
  const dataLen = r.readUint32();
  return { id, name, encoding, data: new Uint8Array(r.readBytes(dataLen)) };
}

export function encodeSchema(s: Schema): Uint8Array {
  const w = new BinaryWriter();
  w.writeUint16(s.id);
  w.writeString(s.name);
  w.writeString(s.encoding);
  w.writeUint32(s.data.length);
  w.writeBytes(s.data);
  return w.toUint8Array();
}

export function parseChannel(data: Uint8Array): Channel {
  const r = new BinaryReader(data);
  const id = r.readUint16();
  const schemaId = r.readUint16();
  const topic = r.readString();
  const messageEncoding = r.readString();
  const metaCount = r.readUint32();
  const metadata = new Map<string, string>();
  for (let i = 0; i < metaCount; i++) {
    metadata.set(r.readString(), r.readString());
  }
  return { id, schemaId, topic, messageEncoding, metadata };
}

export function encodeChannel(c: Channel): Uint8Array {
  const w = new BinaryWriter();
  w.writeUint16(c.id);
  w.writeUint16(c.schemaId);
  w.writeString(c.topic);
  w.writeString(c.messageEncoding);
  w.writeUint32(c.metadata.size);
  for (const [k, v] of c.metadata) {
    w.writeString(k);
    w.writeString(v);
  }
  return w.toUint8Array();
}

export function parseMessage(data: Uint8Array): Message {
  const r = new BinaryReader(data);
  const channelId = r.readUint16();
  const sequence = r.readUint32();
  const logTime = r.readUint64();
  const publishTime = r.readUint64();
  return { channelId, sequence, logTime, publishTime, data: new Uint8Array(r.readBytes(r.remaining)) };
}

export function encodeMessage(m: Message): Uint8Array {
  const w = new BinaryWriter();
  w.writeUint16(m.channelId);
  w.writeUint32(m.sequence);
  w.writeUint64(m.logTime);
  w.writeUint64(m.publishTime);
  w.writeBytes(m.data);
  return w.toUint8Array();
}

export function encodeHeader(profile: string, library: string): Uint8Array {
  const w = new BinaryWriter();
  w.writeString(profile);
  w.writeString(library);
  return w.toUint8Array();
}

export function encodeDataEnd(): Uint8Array {
  const w = new BinaryWriter();
  w.writeUint32(0); // data_section_crc = 0
  return w.toUint8Array();
}

export function encodeFooter(): Uint8Array {
  const w = new BinaryWriter();
  w.writeUint64(0n); // summary_start = 0 → no summary section
  w.writeUint64(0n); // summary_offset_start
  w.writeUint32(0);  // summary_crc
  return w.toUint8Array();
}

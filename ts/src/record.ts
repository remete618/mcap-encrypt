import { BinaryReader, BinaryWriter, safeBigintToNumber } from "./binary.js";

export const MAGIC = new Uint8Array([0x89, 0x4d, 0x43, 0x41, 0x50, 0x30, 0x0d, 0x0a]);

export const OP_HEADER = 0x01;
export const OP_FOOTER = 0x02;
export const OP_SCHEMA = 0x03;
export const OP_CHANNEL = 0x04;
export const OP_MESSAGE = 0x05;
export const OP_CHUNK = 0x06;
export const OP_ATTACHMENT = 0x09;
export const OP_METADATA = 0x0c;
export const OP_DATA_END = 0x0f;
export const OP_ENCRYPTED_CHUNK = 0x81;
export const OP_ENCRYPTED_ATTACHMENT = 0x82;

export function readMagic(r: BinaryReader): void {
  const magic = r.readBytes(8);
  for (let i = 0; i < 8; i++) {
    if (magic[i] !== MAGIC[i]) {
      throw new Error(`invalid MCAP magic at byte ${i}`);
    }
  }
}

export function writeMagic(w: BinaryWriter): void {
  w.writeBytes(MAGIC);
}

export interface RawRecord {
  opcode: number;
  data: Uint8Array;
}

export function readRecord(r: BinaryReader): RawRecord | null {
  if (r.remaining === 0) return null;
  const opcode = r.readUint8();
  const length = r.readUint64();
  const data = r.readBytes(safeBigintToNumber(length, "record length"));
  return { opcode, data };
}

export function writeRecord(w: BinaryWriter, opcode: number, data: Uint8Array): void {
  w.writeUint8(opcode);
  w.writeUint64(BigInt(data.length));
  w.writeBytes(data);
}

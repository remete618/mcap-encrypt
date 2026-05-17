import { BinaryReader, BinaryWriter } from "./binary.js";

export interface EncryptedChunk {
  messageStartTime: bigint;
  messageEndTime: bigint;
  uncompressedSize: bigint;
  uncompressedCrc: number;
  compression: string;
  slotId: string;
  nonce: Uint8Array;
  encryptedData: Uint8Array;
}

export function decodeEncryptedChunk(data: Uint8Array): EncryptedChunk {
  const r = new BinaryReader(data);
  return {
    messageStartTime: r.readUint64(),
    messageEndTime: r.readUint64(),
    uncompressedSize: r.readUint64(),
    uncompressedCrc: r.readUint32(),
    compression: r.readString(),
    slotId: r.readString(),
    nonce: new Uint8Array(r.readPrefixedBytes()),
    encryptedData: new Uint8Array(r.readPrefixedBytes()),
  };
}

export function encodeEncryptedChunk(ec: EncryptedChunk): Uint8Array {
  const w = new BinaryWriter();
  w.writeUint64(ec.messageStartTime);
  w.writeUint64(ec.messageEndTime);
  w.writeUint64(ec.uncompressedSize);
  w.writeUint32(ec.uncompressedCrc);
  w.writeString(ec.compression);
  w.writeString(ec.slotId);
  w.writePrefixedBytes(ec.nonce);
  w.writePrefixedBytes(ec.encryptedData);
  return w.toUint8Array();
}

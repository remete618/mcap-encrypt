import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { BinaryReader, BinaryWriter, safeBigintToNumber } from "./binary.js";

const NONCE_SIZE = 24;

export interface EncryptedAttachment {
  name: string;
  mediaType: string;
  logTime: bigint;
  createTime: bigint;
  nonce: Uint8Array;
  encryptedData: Uint8Array;
}

// attachmentAAD builds the AEAD additional data for one encrypted attachment.
// It binds file identity, attachment name, media type, and both timestamps.
export function attachmentAAD(
  fileId: Uint8Array,
  name: string,
  mediaType: string,
  logTime: bigint,
  createTime: bigint,
): Uint8Array {
  const w = new BinaryWriter();
  w.writeBytes(fileId); // 16 bytes, no length prefix
  w.writeString(name);
  w.writeString(mediaType);
  w.writeUint64(logTime);
  w.writeUint64(createTime);
  return w.toUint8Array();
}

export function encodeEncryptedAttachment(a: EncryptedAttachment): Uint8Array {
  const w = new BinaryWriter();
  w.writeString(a.name);
  w.writeString(a.mediaType);
  w.writeUint64(a.logTime);
  w.writeUint64(a.createTime);
  w.writePrefixedBytes(a.nonce);
  w.writePrefixedBytes(a.encryptedData);
  return w.toUint8Array();
}

export function decodeEncryptedAttachment(data: Uint8Array): EncryptedAttachment {
  const r = new BinaryReader(data);
  const name = r.readString();
  const mediaType = r.readString();
  const logTime = r.readUint64();
  const createTime = r.readUint64();
  const nonce = new Uint8Array(r.readPrefixedBytes());
  const encryptedData = new Uint8Array(r.readPrefixedBytes());
  return { name, mediaType, logTime, createTime, nonce, encryptedData };
}

export function encryptAttachmentData(
  data: Uint8Array,
  symKey: Uint8Array,
  fileId: Uint8Array,
  name: string,
  mediaType: string,
  logTime: bigint,
  createTime: bigint,
): EncryptedAttachment {
  const nonce = new Uint8Array(NONCE_SIZE);
  crypto.getRandomValues(nonce);
  const aad = attachmentAAD(fileId, name, mediaType, logTime, createTime);
  const encryptedData = xchacha20poly1305(symKey, nonce, aad).encrypt(data);
  return { name, mediaType, logTime, createTime, nonce, encryptedData };
}

export function decryptAttachmentData(
  ea: EncryptedAttachment,
  symKey: Uint8Array,
  fileId: Uint8Array,
): Uint8Array {
  if (ea.nonce.length !== NONCE_SIZE) {
    throw new Error(`attachment "${ea.name}": nonce length ${ea.nonce.length} invalid (want ${NONCE_SIZE})`);
  }
  if (ea.encryptedData.length < 16) {
    throw new Error(`attachment "${ea.name}": ciphertext too short (${ea.encryptedData.length} bytes, minimum 16)`);
  }
  const aad = attachmentAAD(fileId, ea.name, ea.mediaType, ea.logTime, ea.createTime);
  try {
    return xchacha20poly1305(symKey, ea.nonce, aad).decrypt(ea.encryptedData);
  } catch {
    throw new Error(`decrypt attachment "${ea.name}": authentication failed`);
  }
}

// parseAttachmentFields extracts name, mediaType, logTime, createTime, and data
// from a raw MCAP Attachment record payload.
export function parseAttachmentFields(data: Uint8Array): {
  name: string;
  mediaType: string;
  logTime: bigint;
  createTime: bigint;
  attData: Uint8Array;
} {
  const r = new BinaryReader(data);
  const logTime = r.readUint64();
  const createTime = r.readUint64();
  const name = r.readString();
  const mediaType = r.readString();
  const dataSize = r.readUint64();
  const attData = new Uint8Array(r.readBytes(safeBigintToNumber(dataSize, "attachment data size")));
  return { name, mediaType, logTime, createTime, attData };
}

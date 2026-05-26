import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { BinaryReader, BinaryWriter } from "./binary.js";

// MetadataMode controls how Metadata records are handled during encryption.
export type MetadataMode = "plaintext" | "encrypt" | "encrypt-all";

const NONCE_SIZE = 24;
const FLAG_ENCRYPT = 0x00;     // name plaintext, map encrypted
const FLAG_ENCRYPT_ALL = 0x01; // name + map both encrypted

export interface EncryptedMetadata {
  flags: number;
  name: string;   // plaintext name (empty when flags = FLAG_ENCRYPT_ALL)
  nonce: Uint8Array;
  encryptedData: Uint8Array;
}

// metadataAAD builds AEAD additional data for one encrypted metadata record.
// flags=0x00: AAD = fileId + uint32LE(len(name)) + nameBytes
// flags=0x01: AAD = fileId only
function metadataAAD(fileId: Uint8Array, flags: number, name: string): Uint8Array {
  const w = new BinaryWriter();
  w.writeBytes(fileId);
  if (flags === FLAG_ENCRYPT) {
    w.writeString(name); // 4-byte LE prefix + utf8
  }
  return w.toUint8Array();
}

export function encodeEncryptedMetadata(m: EncryptedMetadata): Uint8Array {
  const w = new BinaryWriter();
  w.writeUint8(m.flags);
  w.writeString(m.name);
  w.writePrefixedBytes(m.nonce);
  w.writePrefixedBytes(m.encryptedData);
  return w.toUint8Array();
}

export function decodeEncryptedMetadata(data: Uint8Array): EncryptedMetadata {
  const r = new BinaryReader(data);
  if (r.remaining < 1) throw new Error("encrypted metadata record too short");
  const flags = r.readUint8();
  if (flags !== FLAG_ENCRYPT && flags !== FLAG_ENCRYPT_ALL) {
    throw new Error(`unknown encrypted metadata flags 0x${flags.toString(16).padStart(2, "0")}`);
  }
  const name = r.readString();
  const nonce = new Uint8Array(r.readPrefixedBytes());
  const encryptedData = new Uint8Array(r.readPrefixedBytes());
  return { flags, name, nonce, encryptedData };
}

// encryptMetadata encrypts one raw MCAP Metadata record payload according to mode.
// metadataPayload is the raw bytes of the Metadata record (name + map).
export function encryptMetadata(
  metadataPayload: Uint8Array,
  symKey: Uint8Array,
  fileId: Uint8Array,
  mode: MetadataMode,
): EncryptedMetadata {
  const nonce = new Uint8Array(NONCE_SIZE);
  crypto.getRandomValues(nonce);

  if (mode === "encrypt") {
    // Extract name from the payload (uint32 LE prefix + utf8 bytes).
    const r = new BinaryReader(metadataPayload);
    const name = r.readString(); // advances r.offset past the name field
    // Map bytes = everything after the name field.
    const mapBytes = metadataPayload.subarray(r.offset);
    const aad = metadataAAD(fileId, FLAG_ENCRYPT, name);
    const encryptedData = xchacha20poly1305(symKey, nonce, aad).encrypt(mapBytes);
    return { flags: FLAG_ENCRYPT, name, nonce, encryptedData };
  }

  // encrypt-all: encrypt the full payload
  const aad = metadataAAD(fileId, FLAG_ENCRYPT_ALL, "");
  const encryptedData = xchacha20poly1305(symKey, nonce, aad).encrypt(metadataPayload);
  return { flags: FLAG_ENCRYPT_ALL, name: "", nonce, encryptedData };
}

// decryptMetadata decrypts one EncryptedMetadata and returns the plaintext
// MCAP Metadata record payload (name + map bytes).
export function decryptMetadata(
  em: EncryptedMetadata,
  symKey: Uint8Array,
  fileId: Uint8Array,
): Uint8Array {
  if (em.nonce.length !== NONCE_SIZE) {
    throw new Error(`encrypted metadata: nonce length ${em.nonce.length} invalid (want ${NONCE_SIZE})`);
  }
  if (em.encryptedData.length < 16) {
    throw new Error(`encrypted metadata: ciphertext too short (${em.encryptedData.length} bytes, minimum 16)`);
  }
  const aad = metadataAAD(fileId, em.flags, em.name);
  let plain: Uint8Array;
  try {
    plain = xchacha20poly1305(symKey, em.nonce, aad).decrypt(em.encryptedData);
  } catch {
    throw new Error("decrypt metadata: AEAD authentication failed");
  }

  if (em.flags === FLAG_ENCRYPT_ALL) {
    return plain; // full metadata payload
  }

  // flags === FLAG_ENCRYPT: plain is map bytes only; prepend the plaintext name
  const nameBytes = new TextEncoder().encode(em.name);
  const out = new Uint8Array(4 + nameBytes.length + plain.length);
  new DataView(out.buffer).setUint32(0, nameBytes.length, true);
  out.set(nameBytes, 4);
  out.set(plain, 4 + nameBytes.length);
  return out;
}

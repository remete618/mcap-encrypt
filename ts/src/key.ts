import { BinaryReader, BinaryWriter } from "./binary.js";

export const ATTACHMENT_NAME = "mcap_encryption_key";
export const ATTACHMENT_MEDIA_TYPE = "application/x-mcap-wrapped-key";

export const MANIFEST_ATTACHMENT_NAME = "mcap_encryption_manifest";
export const MANIFEST_ATTACHMENT_MEDIA_TYPE = "application/x-mcap-manifest";
// manifestPayloadSize: chunk_count (uint64 LE) + HMAC-SHA256 (32 bytes)
export const MANIFEST_PAYLOAD_SIZE = 8 + 32;

const FILE_ID_SIZE = 16;
const WRAPPED_KEY_VERSION = 2;

export interface WrappedKeyData {
  fileId: Uint8Array; // 16 random bytes, same for every recipient of a given file
  keyId: string;
  algorithm: string;
  kekAlg: string;
  wrappedKey: Uint8Array;
}

export function decodeWrappedKeyData(data: Uint8Array): WrappedKeyData {
  if (data.length < 1) throw new Error("wrapped key data too short");
  if (data[0] !== WRAPPED_KEY_VERSION) {
    throw new Error(`unsupported wrapped key version ${data[0]} (want ${WRAPPED_KEY_VERSION})`);
  }
  if (data.length < 1 + FILE_ID_SIZE) throw new Error("wrapped key data too short for file_id");
  const fileId = new Uint8Array(data.subarray(1, 1 + FILE_ID_SIZE));
  const r = new BinaryReader(data.subarray(1 + FILE_ID_SIZE));
  const wkd: WrappedKeyData = {
    fileId,
    keyId: r.readString(),
    algorithm: r.readString(),
    kekAlg: r.readString(),
    wrappedKey: new Uint8Array(r.readPrefixedBytes()),
  };
  if (wkd.algorithm !== "xchacha20poly1305") {
    throw new Error(`unsupported encryption algorithm "${wkd.algorithm}" (want xchacha20poly1305)`);
  }
  if (wkd.kekAlg !== "rsa-oaep-sha256" && wkd.kekAlg !== "x25519-hkdf-xchacha20poly1305") {
    throw new Error(`unsupported key-wrapping algorithm "${wkd.kekAlg}"`);
  }
  return wkd;
}

export function encodeWrappedKeyData(wkd: WrappedKeyData): Uint8Array {
  const w = new BinaryWriter();
  w.writeUint8(WRAPPED_KEY_VERSION);
  w.writeBytes(wkd.fileId);
  w.writeString(wkd.keyId);
  w.writeString(wkd.algorithm);
  w.writeString(wkd.kekAlg);
  w.writePrefixedBytes(wkd.wrappedKey);
  return w.toUint8Array();
}

function pemToDer(pem: string): Uint8Array<ArrayBuffer> {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  const binStr = atob(body);
  const buf = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) buf[i] = binStr.charCodeAt(i);
  return buf;
}

export function derToPem(label: string, der: ArrayBuffer): string {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(der)));
  const lines = base64.match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

// spkiFingerprint returns the lowercase hex SHA-256 of the SPKI bytes of a
// public key PEM. Used as the key_id in WrappedKeyData so decoders can
// identify which attachment belongs to their private key without trying every one.
export async function spkiFingerprint(publicKeyPem: string): Promise<string> {
  const der = pemToDer(publicKeyPem);
  const hashBuf = await crypto.subtle.digest("SHA-256", der);
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function wrapSymmetricKey(symKey: Uint8Array, publicKeyPem: string): Promise<Uint8Array> {
  const der = pemToDer(publicKeyPem);
  const key = await crypto.subtle.importKey(
    "spki",
    der,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
  const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, new Uint8Array(symKey));
  return new Uint8Array(wrapped);
}

export async function unwrapSymmetricKey(wrappedKey: Uint8Array, privateKeyPem: string): Promise<Uint8Array> {
  const der = pemToDer(privateKeyPem);
  const key = await crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"],
  );
  const symKey = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, key, new Uint8Array(wrappedKey));
  return new Uint8Array(symKey);
}

// computeManifestHMAC returns HMAC-SHA256(symKey, chunkCount_le8 || fileId).
// Mirrors the Go ComputeManifestHMAC function for cross-language compatibility.
export async function computeManifestHMAC(
  symKey: Uint8Array,
  chunkCount: bigint,
  fileId: Uint8Array,
): Promise<Uint8Array> {
  const keyBuf = new ArrayBuffer(symKey.length);
  new Uint8Array(keyBuf).set(symKey);
  const hmacKey = await crypto.subtle.importKey(
    "raw", keyBuf, { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const dataBuf = new ArrayBuffer(8 + fileId.length);
  new DataView(dataBuf).setBigUint64(0, chunkCount, true);
  new Uint8Array(dataBuf, 8).set(fileId);
  const mac = await crypto.subtle.sign("HMAC", hmacKey, dataBuf);
  return new Uint8Array(mac);
}

export interface KeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
}

export async function generateKeyPair(): Promise<KeyPair> {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"],
  );
  const pubDer = await crypto.subtle.exportKey("spki", publicKey);
  const privDer = await crypto.subtle.exportKey("pkcs8", privateKey);
  return {
    publicKeyPem: derToPem("PUBLIC KEY", pubDer),
    privateKeyPem: derToPem("PRIVATE KEY", privDer),
  };
}

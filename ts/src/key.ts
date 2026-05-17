import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha256.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { BinaryReader, BinaryWriter } from "./binary.js";

export const ATTACHMENT_NAME = "mcap_encryption_key";
export const ATTACHMENT_MEDIA_TYPE = "application/x-mcap-wrapped-key";

export const MANIFEST_ATTACHMENT_NAME = "mcap_encryption_manifest";
export const MANIFEST_ATTACHMENT_MEDIA_TYPE = "application/x-mcap-manifest";
// manifestPayloadSize: chunk_count (uint64 LE) + HMAC-SHA256 (32 bytes)
export const MANIFEST_PAYLOAD_SIZE = 8 + 32;

const FILE_ID_SIZE = 16;
// WRAPPED_KEY_VERSION is the version written by this library.
// Version 2 is legacy (manifest optional on decrypt).
// Version 3 requires a manifest during decryption.
const WRAPPED_KEY_VERSION = 3;
const WRAPPED_KEY_VERSION_LEGACY = 2;

export interface WrappedKeyData {
  version: number; // 2 = legacy; 3 = manifest required
  fileId: Uint8Array; // 16 random bytes, same for every recipient of a given file
  keyId: string;
  algorithm: string;
  kekAlg: string;
  wrappedKey: Uint8Array;
}

export function decodeWrappedKeyData(data: Uint8Array): WrappedKeyData {
  if (data.length < 1) throw new Error("wrapped key data too short");
  const ver = data[0];
  if (ver !== WRAPPED_KEY_VERSION && ver !== WRAPPED_KEY_VERSION_LEGACY) {
    throw new Error(
      `unsupported wrapped key version ${ver} (want ${WRAPPED_KEY_VERSION_LEGACY} or ${WRAPPED_KEY_VERSION})`,
    );
  }
  if (data.length < 1 + FILE_ID_SIZE) throw new Error("wrapped key data too short for file_id");
  const fileId = new Uint8Array(data.subarray(1, 1 + FILE_ID_SIZE));
  const r = new BinaryReader(data.subarray(1 + FILE_ID_SIZE));
  const wkd: WrappedKeyData = {
    version: ver,
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
  w.writeUint8(wkd.version ?? WRAPPED_KEY_VERSION);
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
  const arr = new Uint8Array(der);
  let binStr = "";
  for (let i = 0; i < arr.length; i++) binStr += String.fromCharCode(arr[i]);
  const base64 = btoa(binStr);
  const lines = base64.match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

// X25519 SPKI DER header (12 bytes), followed by 32 bytes of raw public key.
// SEQUENCE { SEQUENCE { OID 1.3.101.110 } BIT_STRING { 0x00 <32 bytes> } }
const X25519_SPKI_HEADER = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
]);
// X25519 PKCS8 DER header (16 bytes), followed by 32 bytes of raw private key.
// SEQUENCE { INTEGER 0; SEQUENCE { OID 1.3.101.110 }; OCTET_STRING { OCTET_STRING { <32 bytes> } } }
const X25519_PKCS8_HEADER = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);
// X25519 OID bytes used for key type detection in a SPKI DER blob.
const X25519_OID = new Uint8Array([0x06, 0x03, 0x2b, 0x65, 0x6e]);

function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

// isX25519PublicKeyPem returns true if the PEM encodes an X25519 SPKI public key.
export function isX25519PublicKeyPem(publicKeyPem: string): boolean {
  return containsBytes(pemToDer(publicKeyPem), X25519_OID);
}

function x25519RawPubFromSpkiDer(der: Uint8Array): Uint8Array {
  const expectedLen = X25519_SPKI_HEADER.length + 32;
  if (der.length !== expectedLen) {
    throw new Error(`X25519 SPKI DER must be ${expectedLen} bytes, got ${der.length}`);
  }
  for (let i = 0; i < X25519_SPKI_HEADER.length; i++) {
    if (der[i] !== X25519_SPKI_HEADER[i]) {
      throw new Error("not a valid X25519 SPKI public key");
    }
  }
  return der.slice(X25519_SPKI_HEADER.length);
}

function x25519RawPrivFromPkcs8Der(der: Uint8Array): Uint8Array {
  const expectedLen = X25519_PKCS8_HEADER.length + 32;
  if (der.length !== expectedLen) {
    throw new Error(`X25519 PKCS8 DER must be ${expectedLen} bytes, got ${der.length}`);
  }
  for (let i = 0; i < X25519_PKCS8_HEADER.length; i++) {
    if (der[i] !== X25519_PKCS8_HEADER[i]) {
      throw new Error("not a valid X25519 PKCS8 private key");
    }
  }
  return der.slice(X25519_PKCS8_HEADER.length);
}

function x25519SpkiDerFromRawPub(rawPub: Uint8Array): Uint8Array {
  const der = new Uint8Array(X25519_SPKI_HEADER.length + 32);
  der.set(X25519_SPKI_HEADER);
  der.set(rawPub, X25519_SPKI_HEADER.length);
  return der;
}

function x25519Pkcs8DerFromRawPriv(rawPriv: Uint8Array): Uint8Array {
  const der = new Uint8Array(X25519_PKCS8_HEADER.length + 32);
  der.set(X25519_PKCS8_HEADER);
  der.set(rawPriv, X25519_PKCS8_HEADER.length);
  return der;
}

// The HKDF info label must match the Go constant x25519HKDFInfo exactly.
const X25519_HKDF_INFO = "mcap-encrypt x25519 v1";

function deriveX25519KEK(shared: Uint8Array): Uint8Array {
  // salt=undefined -> HKDF uses HashLen (32) zero bytes, matching Go hkdf.New(... nil ...)
  return hkdf(sha256, shared, undefined, X25519_HKDF_INFO, 32);
}

export async function wrapSymmetricKeyX25519(symKey: Uint8Array, recipientPubPem: string): Promise<Uint8Array> {
  const recipientPubRaw = x25519RawPubFromSpkiDer(pemToDer(recipientPubPem));
  const ephPriv = x25519.utils.randomSecretKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, recipientPubRaw);
  const kek = deriveX25519KEK(shared);
  const nonce = new Uint8Array(24);
  crypto.getRandomValues(nonce);
  const ciphertext = xchacha20poly1305(kek, nonce).encrypt(symKey);
  // Wire format: ephem_pub(32) || nonce(24) || ciphertext(48)
  const result = new Uint8Array(32 + 24 + ciphertext.length);
  result.set(ephPub, 0);
  result.set(nonce, 32);
  result.set(ciphertext, 56);
  return result;
}

export async function unwrapSymmetricKeyX25519(wrappedKey: Uint8Array, privateKeyPem: string): Promise<Uint8Array> {
  // Min length: 32 (ephem_pub) + 24 (nonce) + 32 (ciphertext) + 16 (poly1305 tag) = 104
  if (wrappedKey.length < 104) {
    throw new Error(`x25519 wrapped key too short (${wrappedKey.length} bytes, need 104)`);
  }
  const privRaw = x25519RawPrivFromPkcs8Der(pemToDer(privateKeyPem));
  const ephPub = wrappedKey.slice(0, 32);
  const nonce = wrappedKey.slice(32, 56);
  const ciphertext = wrappedKey.slice(56);
  const shared = x25519.getSharedSecret(privRaw, ephPub);
  const kek = deriveX25519KEK(shared);
  try {
    return xchacha20poly1305(kek, nonce).decrypt(ciphertext);
  } catch {
    throw new Error("x25519 key unwrap: authentication failed");
  }
}

export interface X25519KeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
}

export async function generateX25519KeyPair(): Promise<X25519KeyPair> {
  const privRaw = x25519.utils.randomSecretKey();
  const pubRaw = x25519.getPublicKey(privRaw);
  return {
    publicKeyPem: derToPem("PUBLIC KEY", x25519SpkiDerFromRawPub(pubRaw).buffer as ArrayBuffer),
    privateKeyPem: derToPem("PRIVATE KEY", x25519Pkcs8DerFromRawPriv(privRaw).buffer as ArrayBuffer),
  };
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

export async function unwrapSymmetricKey(
  wrappedKey: Uint8Array,
  privateKeyPem: string,
  kekAlg = "rsa-oaep-sha256",
): Promise<Uint8Array> {
  if (kekAlg === "x25519-hkdf-xchacha20poly1305") {
    return unwrapSymmetricKeyX25519(wrappedKey, privateKeyPem);
  }
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

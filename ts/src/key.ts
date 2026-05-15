import { BinaryReader, BinaryWriter } from "./binary.js";

export const ATTACHMENT_NAME = "mcap_encryption_key";
export const ATTACHMENT_MEDIA_TYPE = "application/x-mcap-wrapped-key";

export interface WrappedKeyData {
  keyId: string;
  algorithm: string;
  kekAlg: string;
  wrappedKey: Uint8Array;
}

const WRAPPED_KEY_VERSION = 1;

export function decodeWrappedKeyData(data: Uint8Array): WrappedKeyData {
  if (data.length < 1) throw new Error("wrapped key data too short");
  if (data[0] !== WRAPPED_KEY_VERSION) {
    throw new Error(`unsupported wrapped key version ${data[0]}`);
  }
  const r = new BinaryReader(data.subarray(1));
  return {
    keyId: r.readString(),
    algorithm: r.readString(),
    kekAlg: r.readString(),
    wrappedKey: new Uint8Array(r.readPrefixedBytes()),
  };
}

export function encodeWrappedKeyData(wkd: WrappedKeyData): Uint8Array {
  const w = new BinaryWriter();
  w.writeUint8(WRAPPED_KEY_VERSION);
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

export interface KeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
}

export async function generateKeyPair(): Promise<KeyPair> {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
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

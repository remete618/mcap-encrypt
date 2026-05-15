import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { BinaryReader, BinaryWriter } from "./binary.js";
import {
  MAGIC,
  OP_HEADER,
  OP_SCHEMA,
  OP_CHANNEL,
  OP_CHUNK,
  OP_ATTACHMENT,
  OP_DATA_END,
  OP_FOOTER,
  OP_ENCRYPTED_CHUNK,
  readMagic,
  readRecord,
  writeRecord,
  writeMagic,
} from "./record.js";
import { encodeEncryptedChunk, type EncryptedChunk } from "./chunk.js";
import {
  wrapSymmetricKey,
  encodeWrappedKeyData,
  ATTACHMENT_NAME,
  ATTACHMENT_MEDIA_TYPE,
} from "./key.js";

const KEY_SIZE = 32;
const NONCE_SIZE = 24;

function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

export function chunkAAD(startTime: bigint, endTime: bigint): Uint8Array {
  const aad = new Uint8Array(16);
  const view = new DataView(aad.buffer);
  view.setBigUint64(0, startTime, true);
  view.setBigUint64(8, endTime, true);
  return aad;
}

function parseStandardChunk(data: Uint8Array): {
  messageStartTime: bigint;
  messageEndTime: bigint;
  uncompressedSize: bigint;
  uncompressedCrc: number;
  compression: string;
  records: Uint8Array;
} {
  const r = new BinaryReader(data);
  const messageStartTime = r.readUint64();
  const messageEndTime = r.readUint64();
  const uncompressedSize = r.readUint64();
  const uncompressedCrc = r.readUint32();
  const compression = r.readString();
  const compressedSize = r.readUint64();
  const records = new Uint8Array(r.readBytes(Number(compressedSize)));
  return { messageStartTime, messageEndTime, uncompressedSize, uncompressedCrc, compression, records };
}

function encodeAttachment(
  logTime: bigint,
  createTime: bigint,
  name: string,
  mediaType: string,
  data: Uint8Array,
): Uint8Array {
  const w = new BinaryWriter();
  w.writeUint64(logTime);
  w.writeUint64(createTime);
  w.writeString(name);
  w.writeString(mediaType);
  w.writeUint64(BigInt(data.length));
  w.writeBytes(data);
  w.writeUint32(0); // crc = 0
  return w.toUint8Array();
}

export async function encryptMcap(input: Uint8Array, publicKeyPem: string): Promise<Uint8Array> {
  const symKey = randomBytes(KEY_SIZE);
  const wrappedKey = await wrapSymmetricKey(symKey, publicKeyPem);
  const wkdBytes = encodeWrappedKeyData({
    keyId: "key-1",
    algorithm: "xchacha20poly1305",
    kekAlg: "rsa-oaep-sha256",
    wrappedKey,
  });
  const keyAttachment = encodeAttachment(
    BigInt(Date.now()) * 1_000_000n,
    0n,
    ATTACHMENT_NAME,
    ATTACHMENT_MEDIA_TYPE,
    wkdBytes,
  );

  const reader = new BinaryReader(input);
  const writer = new BinaryWriter();

  readMagic(reader);
  writeMagic(writer);

  // Buffer schema and channel records. They are written together with the
  // wrapped key attachment immediately before the first encrypted chunk,
  // so decoders can start streaming decryption in a single pass.
  const pendingSchemas: Uint8Array[] = [];
  const pendingChannels: Uint8Array[] = [];
  let flushed = false;

  const flushPending = (): void => {
    if (flushed) return;
    flushed = true;
    for (const s of pendingSchemas) writeRecord(writer, OP_SCHEMA, s);
    for (const c of pendingChannels) writeRecord(writer, OP_CHANNEL, c);
    writeRecord(writer, OP_ATTACHMENT, keyAttachment);
  };

  outer: while (reader.remaining > 0) {
    const rec = readRecord(reader);
    if (!rec) break;
    const { opcode, data } = rec;

    switch (opcode) {
      case OP_HEADER:
        writeRecord(writer, opcode, data);
        break;

      case OP_SCHEMA:
        pendingSchemas.push(new Uint8Array(data));
        break;

      case OP_CHANNEL:
        pendingChannels.push(new Uint8Array(data));
        break;

      case OP_CHUNK: {
        flushPending();
        const chunk = parseStandardChunk(data);
        const nonce = randomBytes(NONCE_SIZE);
        const aad = chunkAAD(chunk.messageStartTime, chunk.messageEndTime);
        const ciphertext = xchacha20poly1305(symKey, nonce, aad).encrypt(chunk.records);
        const ec: EncryptedChunk = {
          messageStartTime: chunk.messageStartTime,
          messageEndTime: chunk.messageEndTime,
          uncompressedSize: chunk.uncompressedSize,
          uncompressedCrc: chunk.uncompressedCrc,
          compression: chunk.compression,
          keyId: "key-1",
          nonce,
          encryptedData: ciphertext,
        };
        writeRecord(writer, OP_ENCRYPTED_CHUNK, encodeEncryptedChunk(ec));
        break;
      }

      case OP_DATA_END:
        flushPending(); // flush in case there were no chunks
        writeRecord(writer, OP_DATA_END, data);
        break;

      case OP_FOOTER:
        writeRecord(writer, OP_FOOTER, new Uint8Array(20));
        break outer;

      default:
        // Drop index records and anything else that references original byte offsets.
        break;
    }
  }

  writeMagic(writer);
  return writer.toUint8Array();
}

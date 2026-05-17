import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { BinaryReader, BinaryWriter, safeBigintToNumber } from "./binary.js";
import {
  OP_HEADER,
  OP_SCHEMA,
  OP_CHANNEL,
  OP_CHUNK,
  OP_MESSAGE,
  OP_ATTACHMENT,
  OP_DATA_END,
  OP_FOOTER,
  OP_METADATA,
  OP_ENCRYPTED_CHUNK,
  OP_ENCRYPTED_ATTACHMENT,
  readMagic,
  readRecord,
  writeRecord,
  writeMagic,
} from "./record.js";
import { encodeEncryptedChunk, type EncryptedChunk } from "./chunk.js";
import {
  encryptAttachmentData,
  encodeEncryptedAttachment,
  parseAttachmentFields,
} from "./attachment.js";
import {
  wrapSymmetricKey,
  spkiFingerprint,
  encodeWrappedKeyData,
  computeManifestHMAC,
  ATTACHMENT_NAME,
  ATTACHMENT_MEDIA_TYPE,
  MANIFEST_ATTACHMENT_NAME,
  MANIFEST_ATTACHMENT_MEDIA_TYPE,
  MANIFEST_PAYLOAD_SIZE,
} from "./key.js";

const KEY_SIZE = 32;
const NONCE_SIZE = 24;

function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

// chunkAAD builds the AEAD additional data for one encrypted chunk.
// It binds: file identity, chunk position, slot identity, compression
// parameters, and time bounds. Any modification to these plaintext fields
// or the ciphertext will cause authentication to fail.
export function chunkAAD(
  fileId: Uint8Array,
  chunkIdx: bigint,
  slotId: string,
  compression: string,
  uncompressedSize: bigint,
  uncompressedCrc: number,
  startTime: bigint,
  endTime: bigint,
): Uint8Array {
  const w = new BinaryWriter();
  w.writeBytes(fileId); // 16 bytes
  w.writeUint64(chunkIdx);
  w.writeString(slotId); // 4-byte length prefix + bytes
  w.writeString(compression);
  w.writeUint64(uncompressedSize);
  w.writeUint32(uncompressedCrc);
  w.writeUint64(startTime);
  w.writeUint64(endTime);
  return w.toUint8Array();
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
  const records = new Uint8Array(r.readBytes(safeBigintToNumber(compressedSize, "compressed size")));
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

export async function encryptMcap(
  input: Uint8Array,
  publicKeyPem: string | string[],
): Promise<Uint8Array> {
  const pubKeys = Array.isArray(publicKeyPem) ? publicKeyPem : [publicKeyPem];
  if (pubKeys.length === 0) throw new Error("at least one public key is required");

  const symKey = randomBytes(KEY_SIZE);
  const fileId = randomBytes(16);
  const now = BigInt(Date.now()) * 1_000_000n;

  // Wrap the symmetric key for each recipient; store as separate attachments.
  const keyAttachments: Uint8Array[] = [];
  for (let i = 0; i < pubKeys.length; i++) {
    const keyId = await spkiFingerprint(pubKeys[i]!);
    const wrappedKey = await wrapSymmetricKey(symKey, pubKeys[i]!);
    const wkdBytes = encodeWrappedKeyData({
      version: 3, // v3: manifest required on decrypt
      fileId,
      keyId,
      algorithm: "xchacha20poly1305",
      kekAlg: "rsa-oaep-sha256",
      wrappedKey,
    });
    keyAttachments.push(encodeAttachment(now, 0n, ATTACHMENT_NAME, ATTACHMENT_MEDIA_TYPE, wkdBytes));
  }

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
    for (const att of keyAttachments) writeRecord(writer, OP_ATTACHMENT, att);
  };

  let chunkIdx = 0n;

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
        if (chunk.compression === "lz4") {
          throw new Error(
            "LZ4-compressed source MCAP is not supported by the TypeScript library. " +
            "Use the Go CLI (mcap-encrypt encrypt) to normalize LZ4 to zstd first.",
          );
        }
        const slotId = "key-1";
        const nonce = randomBytes(NONCE_SIZE);
        const aad = chunkAAD(
          fileId, chunkIdx, slotId, chunk.compression,
          chunk.uncompressedSize, chunk.uncompressedCrc,
          chunk.messageStartTime, chunk.messageEndTime,
        );
        const ciphertext = xchacha20poly1305(symKey, nonce, aad).encrypt(chunk.records);
        chunkIdx++;
        const ec: EncryptedChunk = {
          messageStartTime: chunk.messageStartTime,
          messageEndTime: chunk.messageEndTime,
          uncompressedSize: chunk.uncompressedSize,
          uncompressedCrc: chunk.uncompressedCrc,
          compression: chunk.compression,
          slotId,
          nonce,
          encryptedData: ciphertext,
        };
        writeRecord(writer, OP_ENCRYPTED_CHUNK, encodeEncryptedChunk(ec));
        break;
      }

      case OP_ATTACHMENT: {
        const { name: attName, mediaType: attMediaType, logTime, createTime, attData } =
          parseAttachmentFields(new Uint8Array(data));
        // Drop encryption-framework attachments from previously encrypted inputs.
        if (
          (attName === ATTACHMENT_NAME && attMediaType === ATTACHMENT_MEDIA_TYPE) ||
          (attName === MANIFEST_ATTACHMENT_NAME && attMediaType === MANIFEST_ATTACHMENT_MEDIA_TYPE)
        ) {
          break;
        }
        flushPending();
        const ea = encryptAttachmentData(attData, symKey, fileId, attName, attMediaType, logTime, createTime);
        writeRecord(writer, OP_ENCRYPTED_ATTACHMENT, encodeEncryptedAttachment(ea));
        break;
      }

      case OP_METADATA: {
        flushPending();
        writeRecord(writer, OP_METADATA, data);
        break;
      }

      case OP_DATA_END: {
        flushPending(); // flush in case there were no chunks
        // Write manifest attachment with actual chunk count and HMAC.
        const manifestMac = await computeManifestHMAC(symKey, chunkIdx, fileId);
        const manifestPayload = new Uint8Array(MANIFEST_PAYLOAD_SIZE);
        new DataView(manifestPayload.buffer).setBigUint64(0, chunkIdx, true);
        manifestPayload.set(manifestMac, 8);
        writeRecord(writer, OP_ATTACHMENT, encodeAttachment(now, 0n, MANIFEST_ATTACHMENT_NAME, MANIFEST_ATTACHMENT_MEDIA_TYPE, manifestPayload));
        writeRecord(writer, OP_DATA_END, data);
        break;
      }

      case OP_FOOTER:
        writeRecord(writer, OP_FOOTER, new Uint8Array(20));
        break outer;

      case OP_ENCRYPTED_CHUNK:
      case OP_ENCRYPTED_ATTACHMENT:
        throw new Error(
          `input is already encrypted (found opcode 0x${opcode.toString(16).padStart(2, "0")}); ` +
          "decrypt first before re-encrypting",
        );

      case OP_MESSAGE:
        throw new Error(
          "input MCAP contains raw Message records outside of chunks; only chunked MCAPs are supported",
        );

      default:
        // Drop index records and anything else that references original byte offsets.
        break;
    }
  }

  writeMagic(writer);
  return writer.toUint8Array();
}

import { BinaryReader, BinaryWriter, safeBigintToNumber } from "./binary.js";
import {
  OP_HEADER,
  OP_SCHEMA,
  OP_CHANNEL,
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
import { decodeEncryptedChunk } from "./chunk.js";
import {
  ATTACHMENT_NAME,
  ATTACHMENT_MEDIA_TYPE,
  MANIFEST_ATTACHMENT_NAME,
  MANIFEST_ATTACHMENT_MEDIA_TYPE,
  MANIFEST_PAYLOAD_SIZE,
  computeManifestHMAC,
  decodeWrappedKeyData,
  encodeWrappedKeyData,
  unwrapSymmetricKey,
  wrapSymmetricKey,
  wrapSymmetricKeyX25519,
  isX25519PublicKeyPem,
  spkiFingerprint,
} from "./key.js";
import { encodeAttachment, parseAttachmentFields } from "./attachment.js";

// Additional opcodes for building the summary section.
const OP_CHUNK_INDEX = 0x08;
const OP_STATISTICS = 0x0a;
const OP_SUMMARY_OFFSET = 0x0e;

type ChunkIndexMeta = {
  msgStart: bigint;
  msgEnd: bigint;
  dataBufOffset: bigint; // byte offset within dataBuf; adjusted to file offset in pass-B
  recordLen: bigint;
  compression: string;
  compressedSize: bigint;
  uncompSize: bigint;
};

/**
 * rotateMcapKeys re-wraps the symmetric key for a new set of recipients without
 * decrypting any chunk data. O(file size) I/O with zero message decryption.
 *
 * @param input          - encrypted MCAP bytes
 * @param oldPrivateKeyPem - PEM of the private key that can currently decrypt
 * @param newPublicKeyPems - PEM(s) of the new recipient public keys
 * @returns              - new encrypted MCAP bytes readable by any newPublicKeyPem
 */
export async function rotateMcapKeys(
  input: Uint8Array,
  oldPrivateKeyPem: string,
  newPublicKeyPems: string | string[],
): Promise<Uint8Array> {
  const pubKeys = Array.isArray(newPublicKeyPems)
    ? newPublicKeyPems
    : [newPublicKeyPems];
  if (pubKeys.length === 0) throw new Error("at least one new public key is required");

  const r = new BinaryReader(input);
  readMagic(r);

  // headerBuf: Header, Schema, Channel records (appear before key attachments in output)
  const headerBuf = new BinaryWriter();
  // dataBuf: everything after key attachments (Metadata, EncryptedChunk, etc.)
  const dataBuf = new BinaryWriter();

  const schemaRecs: Uint8Array[] = [];
  const channelRecs: Uint8Array[] = [];
  const chunkMetas: ChunkIndexMeta[] = [];

  let symKey: Uint8Array | undefined;
  let fileId: Uint8Array | undefined;
  let wkaCount = 0;
  let seenFirstChunk = false;

  // ----------------------------------------------------------------- scan
  scan: while (r.remaining > 0) {
    const rec = readRecord(r);
    if (!rec) break;
    const { opcode, data } = rec;

    switch (opcode) {
      case OP_HEADER:
        writeRecord(headerBuf, opcode, new Uint8Array(data));
        break;

      case OP_SCHEMA: {
        const raw = new Uint8Array(data);
        writeRecord(headerBuf, opcode, raw);
        schemaRecs.push(raw);
        break;
      }

      case OP_CHANNEL: {
        const raw = new Uint8Array(data);
        writeRecord(headerBuf, opcode, raw);
        channelRecs.push(raw);
        break;
      }

      case OP_METADATA:
        writeRecord(dataBuf, opcode, new Uint8Array(data));
        break;

      case OP_ATTACHMENT: {
        const { name, mediaType, attData } = parseAttachmentFields(
          new Uint8Array(data),
        );
        if (name === ATTACHMENT_NAME && mediaType === ATTACHMENT_MEDIA_TYPE) {
          // Wrapped-key attachment: try to unwrap; skip (will be replaced).
          wkaCount++;
          if (!symKey) {
            try {
              const wkd = decodeWrappedKeyData(attData);
              const candidate = await unwrapSymmetricKey(
                wkd.wrappedKey,
                oldPrivateKeyPem,
                wkd.kekAlg,
              );
              if (candidate.length === 32) {
                symKey = candidate;
                fileId = wkd.fileId;
              }
            } catch {
              // wrong key or malformed; try next attachment
            }
          }
          break; // skip; regenerated below
        }
        if (
          name === MANIFEST_ATTACHMENT_NAME &&
          mediaType === MANIFEST_ATTACHMENT_MEDIA_TYPE
        ) {
          break; // skip; regenerated below
        }
        // User attachment: keep verbatim.
        writeRecord(dataBuf, opcode, new Uint8Array(data));
        break;
      }

      case OP_ENCRYPTED_CHUNK: {
        seenFirstChunk = true;
        const ec = decodeEncryptedChunk(new Uint8Array(data));
        chunkMetas.push({
          msgStart: ec.messageStartTime,
          msgEnd: ec.messageEndTime,
          dataBufOffset: BigInt(dataBuf.length), // relative; fixed in pass-B
          recordLen: BigInt(9 + data.length),
          compression: ec.compression,
          compressedSize: BigInt(ec.encryptedData.length),
          uncompSize: ec.uncompressedSize,
        });
        writeRecord(dataBuf, opcode, new Uint8Array(data));
        break;
      }

      case OP_ENCRYPTED_ATTACHMENT:
        seenFirstChunk = true;
        writeRecord(dataBuf, opcode, new Uint8Array(data));
        break;

      case OP_DATA_END:
        break scan;

      case OP_FOOTER:
        break scan;

      default:
        // Unknown records: route to the appropriate buffer.
        if (!seenFirstChunk) {
          writeRecord(headerBuf, opcode, new Uint8Array(data));
        } else {
          writeRecord(dataBuf, opcode, new Uint8Array(data));
        }
        break;
    }
  }

  if (!symKey || !fileId) {
    if (wkaCount === 0) {
      throw new Error("no wrapped key attachment found: is this an encrypted MCAP file?");
    }
    throw new Error(
      `old private key does not match any of the ${wkaCount} recipient key(s) in this file`,
    );
  }

  // ----------------------------------------------------------------- wrap
  const now = BigInt(Date.now()) * 1_000_000n;
  const newKeyRecords: Uint8Array[] = [];
  for (let i = 0; i < pubKeys.length; i++) {
    const pubPem = pubKeys[i]!;
    const keyId = await spkiFingerprint(pubPem);
    const isX25519 = isX25519PublicKeyPem(pubPem);
    const wrappedKey = isX25519
      ? await wrapSymmetricKeyX25519(symKey, pubPem)
      : await wrapSymmetricKey(symKey, pubPem);
    const wkdBytes = encodeWrappedKeyData({
      version: 3,
      fileId,
      keyId,
      algorithm: "xchacha20poly1305",
      kekAlg: isX25519 ? "x25519-hkdf-xchacha20poly1305" : "rsa-oaep-sha256",
      wrappedKey,
    });
    const attBytes = encodeAttachment(
      now, 0n, ATTACHMENT_NAME, ATTACHMENT_MEDIA_TYPE, wkdBytes,
    );
    const rec = new BinaryWriter();
    writeRecord(rec, OP_ATTACHMENT, attBytes);
    newKeyRecords.push(rec.toUint8Array());
  }

  // Manifest
  const chunkCount = BigInt(chunkMetas.length);
  const mac = await computeManifestHMAC(symKey, chunkCount, fileId);
  const manifestPayload = new Uint8Array(MANIFEST_PAYLOAD_SIZE);
  new DataView(manifestPayload.buffer).setBigUint64(0, chunkCount, true);
  manifestPayload.set(mac, 8);
  const manifestAttBytes = encodeAttachment(
    now, 0n, MANIFEST_ATTACHMENT_NAME, MANIFEST_ATTACHMENT_MEDIA_TYPE, manifestPayload,
  );
  const manifestRecordBuf = new BinaryWriter();
  writeRecord(manifestRecordBuf, OP_ATTACHMENT, manifestAttBytes);
  const manifestRecord = manifestRecordBuf.toUint8Array();

  // ----------------------------------------------------------------- pass-B
  // Compute prefix size: magic(8) + headerBuf + newKeyRecords + manifestRecord
  const MAGIC_SIZE = 8n;
  let prefixSize = MAGIC_SIZE + BigInt(headerBuf.length);
  for (const kr of newKeyRecords) prefixSize += BigInt(kr.length);
  prefixSize += BigInt(manifestRecord.length);

  // Fix chunk offsets from dataBuf-relative to absolute file offsets.
  for (const m of chunkMetas) {
    m.dataBufOffset += prefixSize;
  }

  // ----------------------------------------------------------------- assemble
  const out = new BinaryWriter();

  writeMagic(out);
  out.writeBytes(headerBuf.toUint8Array());
  for (const kr of newKeyRecords) out.writeBytes(kr);
  out.writeBytes(manifestRecord);
  const dataBytes = dataBuf.toUint8Array();
  out.writeBytes(dataBytes);

  // DataEnd: 4 zero bytes (data_end_data_length per spec).
  writeRecord(out, OP_DATA_END, new Uint8Array(4));

  // ----------------------------------------------------------------- summary
  const summaryStart =
    prefixSize + BigInt(dataBytes.length) + 9n + 4n; // DataEnd: 9-byte hdr + 4-byte payload

  const sumBuf = new BinaryWriter();
  let written = 0n;

  const emitSumRec = (opcode: number, data: Uint8Array): void => {
    const hdr = new Uint8Array(9);
    hdr[0] = opcode;
    new DataView(hdr.buffer).setBigUint64(1, BigInt(data.length), true);
    sumBuf.writeBytes(hdr);
    sumBuf.writeBytes(data);
    written += BigInt(9 + data.length);
  };

  type SumGroup = { opcode: number; absStart: bigint; absLength: bigint };
  const groups: SumGroup[] = [];

  // Schema group
  const schemaGroupStart = summaryStart + written;
  for (const raw of schemaRecs) emitSumRec(OP_SCHEMA, raw);
  const schemaGroupLength = summaryStart + written - schemaGroupStart;
  if (schemaGroupLength > 0n) groups.push({ opcode: OP_SCHEMA, absStart: schemaGroupStart, absLength: schemaGroupLength });

  // Channel group
  const channelGroupStart = summaryStart + written;
  for (const raw of channelRecs) emitSumRec(OP_CHANNEL, raw);
  const channelGroupLength = summaryStart + written - channelGroupStart;
  if (channelGroupLength > 0n) groups.push({ opcode: OP_CHANNEL, absStart: channelGroupStart, absLength: channelGroupLength });

  // Statistics
  const statsGroupStart = summaryStart + written;
  let globalMsgStart = 0xffffffffffffffffn;
  let globalMsgEnd = 0n;
  for (const m of chunkMetas) {
    if (m.msgStart < globalMsgStart) globalMsgStart = m.msgStart;
    if (m.msgEnd > globalMsgEnd) globalMsgEnd = m.msgEnd;
  }
  if (chunkMetas.length === 0) {
    globalMsgStart = 0n;
  }
  const statsBuf = new BinaryWriter();
  statsBuf.writeUint64(0n); // message_count (unknown for encrypted files)
  statsBuf.writeUint16(schemaRecs.length);
  statsBuf.writeUint32(channelRecs.length);
  statsBuf.writeUint32(0); // attachment_count
  statsBuf.writeUint32(0); // metadata_count
  statsBuf.writeUint32(chunkMetas.length);
  statsBuf.writeUint64(globalMsgStart);
  statsBuf.writeUint64(globalMsgEnd);
  statsBuf.writeUint32(0); // channel_message_counts: empty map
  emitSumRec(OP_STATISTICS, statsBuf.toUint8Array());
  groups.push({
    opcode: OP_STATISTICS,
    absStart: statsGroupStart,
    absLength: summaryStart + written - statsGroupStart,
  });

  // ChunkIndex
  const chunkIdxGroupStart = summaryStart + written;
  for (const m of chunkMetas) {
    const ci = new BinaryWriter();
    ci.writeUint64(m.msgStart);
    ci.writeUint64(m.msgEnd);
    ci.writeUint64(m.dataBufOffset);
    ci.writeUint64(m.recordLen);
    ci.writeUint32(0); // message_index_offsets: empty
    ci.writeUint64(0n); // message_index_length: 0
    ci.writeString(m.compression);
    ci.writeUint64(m.compressedSize);
    ci.writeUint64(m.uncompSize);
    emitSumRec(OP_CHUNK_INDEX, ci.toUint8Array());
  }
  const chunkIdxGroupLength = summaryStart + written - chunkIdxGroupStart;
  if (chunkIdxGroupLength > 0n) {
    groups.push({
      opcode: OP_CHUNK_INDEX,
      absStart: chunkIdxGroupStart,
      absLength: chunkIdxGroupLength,
    });
  }

  // SummaryOffset records
  const summaryOffsetStart = summaryStart + written;
  for (const g of groups) {
    const so = new BinaryWriter();
    so.writeUint8(g.opcode);
    so.writeUint64(g.absStart);
    so.writeUint64(g.absLength);
    emitSumRec(OP_SUMMARY_OFFSET, so.toUint8Array());
  }

  out.writeBytes(sumBuf.toUint8Array());

  // Footer
  const footerBuf = new BinaryWriter();
  footerBuf.writeUint64(summaryStart);
  footerBuf.writeUint64(summaryOffsetStart);
  footerBuf.writeUint32(0); // summary_crc
  writeRecord(out, OP_FOOTER, footerBuf.toUint8Array());

  // Trailing magic
  writeMagic(out);

  return out.toUint8Array();
}

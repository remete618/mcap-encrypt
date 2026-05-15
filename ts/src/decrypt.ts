import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { BinaryReader, BinaryWriter, safeBigintToNumber } from "./binary.js";
import {
  OP_HEADER,
  OP_SCHEMA,
  OP_CHANNEL,
  OP_CHUNK,
  OP_ATTACHMENT,
  OP_DATA_END,
  OP_FOOTER,
  OP_MESSAGE,
  OP_ENCRYPTED_CHUNK,
  readMagic,
  readRecord,
} from "./record.js";
import { decodeEncryptedChunk } from "./chunk.js";
import {
  ATTACHMENT_NAME,
  ATTACHMENT_MEDIA_TYPE,
  decodeWrappedKeyData,
  unwrapSymmetricKey,
} from "./key.js";
import {
  parseSchema,
  parseChannel,
  parseMessage,
  parseHeader,
  encodeSchema,
  encodeChannel,
  encodeMessage,
  type Schema,
  type Channel,
  type Message,
} from "./mcap.js";
import { decompressChunkData } from "./decompress.js";
import { chunkAAD } from "./encrypt.js";
import { crc32 } from "./crc32.js";

// Additional opcodes used for building the indexed output (not exported by record.ts)
const OP_MESSAGE_INDEX = 0x07;
const OP_CHUNK_INDEX = 0x08;
const OP_STATISTICS = 0x0a;
const OP_SUMMARY_OFFSET = 0x0e;

const MCAP_MAGIC = new Uint8Array([0x89, 0x4d, 0x43, 0x41, 0x50, 0x30, 0x0d, 0x0a]);

function parseAttachment(data: Uint8Array): {
  name: string;
  mediaType: string;
  data: Uint8Array;
} {
  const r = new BinaryReader(data);
  r.readUint64(); // log_time
  r.readUint64(); // create_time
  const name = r.readString();
  const mediaType = r.readString();
  const dataSize = r.readUint64();
  const attData = new Uint8Array(r.readBytes(safeBigintToNumber(dataSize, "attachment data size")));
  return { name, mediaType, data: attData };
}

function parseInnerRecords(decompressed: Uint8Array): Message[] {
  const r = new BinaryReader(decompressed);
  const msgs: Message[] = [];
  while (r.remaining > 0) {
    const opcode = r.readUint8();
    const length = r.readUint64();
    const data = r.readBytes(safeBigintToNumber(length, "inner record length"));
    if (opcode === OP_MESSAGE) {
      msgs.push(parseMessage(new Uint8Array(data)));
    }
  }
  return msgs;
}

// buildIndexedMcap produces a fully-indexed, seekable MCAP file from the given
// schemas, channels, and messages. All messages are placed in a single
// uncompressed chunk followed by MessageIndex records, then a complete summary
// section with ChunkIndex, Statistics, and SummaryOffset records.
function buildIndexedMcap(schemas: Schema[], channels: Channel[], messages: Message[], profile = "", library = "mcap-encrypt"): Uint8Array {
  const parts: Uint8Array[] = [];
  let pos = 0n;

  const emit = (data: Uint8Array): void => {
    parts.push(data);
    pos += BigInt(data.length);
  };

  // Emits a complete MCAP record (opcode + uint64 length + data) and returns
  // the file offset of the opcode byte.
  const emitRecord = (opcode: number, data: Uint8Array): bigint => {
    const startPos = pos;
    const hdr = new Uint8Array(9);
    hdr[0] = opcode;
    new DataView(hdr.buffer).setBigUint64(1, BigInt(data.length), true);
    emit(hdr);
    emit(data);
    return startPos;
  };

  const w = (fn: (b: BinaryWriter) => void): Uint8Array => {
    const b = new BinaryWriter();
    fn(b);
    return b.toUint8Array();
  };

  // Magic
  emit(MCAP_MAGIC.slice());

  // Header
  emitRecord(OP_HEADER, w((b) => { b.writeString(profile); b.writeString(library); }));

  // Data section: schemas and channels
  for (const s of schemas) emitRecord(OP_SCHEMA, encodeSchema(s));
  for (const c of channels) emitRecord(OP_CHANNEL, encodeChannel(c));

  // Build chunk body: all message records laid out sequentially, uncompressed.
  const chunkBody = new BinaryWriter();
  // msgIndexEntries maps channelId → list of {logTime, offset-within-chunk-body}
  const msgIndexEntries = new Map<number, Array<{ logTime: bigint; offset: bigint }>>();

  let chunkMsgStart = 18446744073709551615n; // u64 max
  let chunkMsgEnd = 0n;

  for (const msg of messages) {
    const offsetWithinChunk = BigInt(chunkBody.length);
    if (!msgIndexEntries.has(msg.channelId)) msgIndexEntries.set(msg.channelId, []);
    msgIndexEntries.get(msg.channelId)!.push({ logTime: msg.logTime, offset: offsetWithinChunk });

    if (msg.logTime < chunkMsgStart) chunkMsgStart = msg.logTime;
    if (msg.logTime > chunkMsgEnd) chunkMsgEnd = msg.logTime;

    const msgData = encodeMessage(msg);
    const recHdr = new Uint8Array(9);
    recHdr[0] = OP_MESSAGE;
    new DataView(recHdr.buffer).setBigUint64(1, BigInt(msgData.length), true);
    chunkBody.writeBytes(recHdr);
    chunkBody.writeBytes(msgData);
  }

  const uncompressedData = chunkBody.toUint8Array();
  const uncompressedSize = BigInt(uncompressedData.length);

  const hasMessages = messages.length > 0;
  const msgStart = hasMessages ? chunkMsgStart : 0n;
  const msgEnd = hasMessages ? chunkMsgEnd : 0n;

  // Chunk record
  let chunkStartOffset = 0n;
  let chunkTotalLength = 0n;
  let messageIndexTotalLength = 0n;
  const messageIndexOffsets = new Map<number, bigint>();

  if (hasMessages) {
    chunkStartOffset = pos;
    emitRecord(
      OP_CHUNK,
      w((b) => {
        b.writeUint64(msgStart);
        b.writeUint64(msgEnd);
        b.writeUint64(uncompressedSize);
        b.writeUint32(0); // uncompressed_crc = 0
        b.writeString(""); // no compression
        b.writeUint64(uncompressedSize); // compressed_size = uncompressed_size
        b.writeBytes(uncompressedData);
      }),
    );
    chunkTotalLength = pos - chunkStartOffset;

    // MessageIndex records: one per channel in this chunk
    const messageIndexStart = pos;
    for (const [channelId, records] of msgIndexEntries) {
      messageIndexOffsets.set(channelId, pos);
      emitRecord(
        OP_MESSAGE_INDEX,
        w((b) => {
          b.writeUint16(channelId);
          const pairs = new BinaryWriter();
          for (const { logTime, offset } of records) {
            pairs.writeUint64(logTime);
            pairs.writeUint64(offset);
          }
          const pairsBytes = pairs.toUint8Array();
          b.writeUint32(pairsBytes.length);
          b.writeBytes(pairsBytes);
        }),
      );
    }
    messageIndexTotalLength = pos - messageIndexStart;
  }

  // DataEnd
  emitRecord(OP_DATA_END, w((b) => b.writeUint32(0)));

  // --- Summary section ---
  const summaryStart = pos;

  // Repeat schemas in summary (so the summary section is self-contained)
  const sumSchemaStart = pos;
  for (const s of schemas) emitRecord(OP_SCHEMA, encodeSchema(s));
  const sumSchemaLength = pos - sumSchemaStart;

  // Repeat channels in summary
  const sumChannelStart = pos;
  for (const c of channels) emitRecord(OP_CHANNEL, encodeChannel(c));
  const sumChannelLength = pos - sumChannelStart;

  // Statistics
  const statsStart = pos;
  emitRecord(
    OP_STATISTICS,
    w((b) => {
      b.writeUint64(BigInt(messages.length)); // message_count
      b.writeUint16(schemas.length);          // schema_count
      b.writeUint32(channels.length);         // channel_count
      b.writeUint32(0);                       // attachment_count
      b.writeUint32(0);                       // metadata_count
      b.writeUint32(hasMessages ? 1 : 0);    // chunk_count
      b.writeUint64(msgStart);               // message_start_time
      b.writeUint64(msgEnd);                 // message_end_time
      // channel_message_counts: uint32 byte_length + (uint16 channelId + uint64 count)*
      const mapBuf = new BinaryWriter();
      for (const [channelId, records] of msgIndexEntries) {
        mapBuf.writeUint16(channelId);
        mapBuf.writeUint64(BigInt(records.length));
      }
      const mapBytes = mapBuf.toUint8Array();
      b.writeUint32(mapBytes.length);
      b.writeBytes(mapBytes);
    }),
  );
  const statsLength = pos - statsStart;

  // ChunkIndex (one per chunk)
  const chunkIndexStart = pos;
  if (hasMessages) {
    emitRecord(
      OP_CHUNK_INDEX,
      w((b) => {
        b.writeUint64(msgStart);           // message_start_time
        b.writeUint64(msgEnd);             // message_end_time
        b.writeUint64(chunkStartOffset);   // chunk_start_offset
        b.writeUint64(chunkTotalLength);   // chunk_length (record header + data)
        // message_index_offsets: uint32 byte_length + (uint16 channelId + uint64 offset)*
        const mapBuf = new BinaryWriter();
        for (const [channelId, offset] of messageIndexOffsets) {
          mapBuf.writeUint16(channelId);
          mapBuf.writeUint64(offset);
        }
        const mapBytes = mapBuf.toUint8Array();
        b.writeUint32(mapBytes.length);
        b.writeBytes(mapBytes);
        b.writeUint64(messageIndexTotalLength); // message_index_length
        b.writeString("");                       // compression = ""
        b.writeUint64(uncompressedSize);        // compressed_size
        b.writeUint64(uncompressedSize);        // uncompressed_size
      }),
    );
  }
  const chunkIndexLength = pos - chunkIndexStart;

  // SummaryOffset records
  const summaryOffsetStart = pos;
  const emitSO = (opcode: number, start: bigint, length: bigint): void => {
    if (length === 0n) return;
    emitRecord(OP_SUMMARY_OFFSET, w((b) => { b.writeUint8(opcode); b.writeUint64(start); b.writeUint64(length); }));
  };
  emitSO(OP_SCHEMA, sumSchemaStart, sumSchemaLength);
  emitSO(OP_CHANNEL, sumChannelStart, sumChannelLength);
  emitSO(OP_STATISTICS, statsStart, statsLength);
  if (hasMessages) emitSO(OP_CHUNK_INDEX, chunkIndexStart, chunkIndexLength);

  // Footer
  emitRecord(
    OP_FOOTER,
    w((b) => {
      b.writeUint64(summaryStart);
      b.writeUint64(summaryOffsetStart);
      b.writeUint32(0); // summary_crc = 0
    }),
  );

  // Trailing magic
  emit(MCAP_MAGIC.slice());

  // Assemble
  const total = Number(pos);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

// decryptAndVerifyChunk decrypts one EncryptedChunk, validates CRC, and
// returns the decompressed message records.
async function decryptAndVerifyChunk(
  data: Uint8Array,
  symKey: Uint8Array,
  fileId: Uint8Array,
  chunkIdx: bigint,
): Promise<Message[]> {
  const ec = decodeEncryptedChunk(data);
  if (ec.nonce.length !== 24) {
    throw new Error(
      `chunk [${ec.messageStartTime}–${ec.messageEndTime}]: nonce length ${ec.nonce.length} invalid (want 24)`,
    );
  }
  if (ec.encryptedData.length < 16) {
    throw new Error(
      `chunk [${ec.messageStartTime}–${ec.messageEndTime}]: ciphertext too short (${ec.encryptedData.length} bytes, minimum 16)`,
    );
  }
  const aad = chunkAAD(
    fileId, chunkIdx, ec.keyId, ec.compression,
    ec.uncompressedSize, ec.uncompressedCrc,
    ec.messageStartTime, ec.messageEndTime,
  );
  let plaintext: Uint8Array;
  try {
    plaintext = xchacha20poly1305(symKey, ec.nonce, aad).decrypt(ec.encryptedData);
  } catch {
    throw new Error(
      `decrypt chunk [${ec.messageStartTime}–${ec.messageEndTime}]: authentication failed`,
    );
  }
  const decompressed = decompressChunkData(plaintext, ec.compression);
  if (ec.uncompressedSize !== 0n && BigInt(decompressed.length) !== ec.uncompressedSize) {
    throw new Error(
      `uncompressed size mismatch in chunk [${ec.messageStartTime}–${ec.messageEndTime}]: ` +
        `got ${decompressed.length}, want ${ec.uncompressedSize}`,
    );
  }
  if (ec.uncompressedCrc !== 0) {
    const got = crc32(decompressed);
    if (got !== ec.uncompressedCrc) {
      throw new Error(
        `CRC mismatch in chunk [${ec.messageStartTime}–${ec.messageEndTime}]: ` +
          `got 0x${got.toString(16).padStart(8, "0")}, ` +
          `want 0x${ec.uncompressedCrc.toString(16).padStart(8, "0")}`,
      );
    }
  }
  return parseInnerRecords(decompressed);
}

// tryUnwrapKey attempts to unwrap the sym key from one wrapped-key attachment.
// Returns undefined if the key does not match (wrong recipient).
async function tryUnwrapKey(
  attData: Uint8Array,
  privateKeyPem: string,
): Promise<{ symKey: Uint8Array; fileId: Uint8Array } | undefined> {
  try {
    const wkd = decodeWrappedKeyData(attData);
    const symKey = await unwrapSymmetricKey(wkd.wrappedKey, privateKeyPem);
    if (symKey.length !== 32) return undefined;
    return { symKey, fileId: wkd.fileId };
  } catch {
    return undefined;
  }
}

// streamMessages performs a single-pass stream over the encrypted MCAP,
// yielding decrypted messages immediately as each chunk is processed.
async function* streamMessages(
  input: Uint8Array,
  privateKeyPem: string,
): AsyncGenerator<{ schema: Schema; channel: Channel; message: Message }> {
  const r = new BinaryReader(input);
  readMagic(r);

  let unwrapped: { symKey: Uint8Array; fileId: Uint8Array } | undefined;
  let chunkIdx = 0n;
  let wkaCount = 0;
  const schemaMap = new Map<number, Schema>();
  const channelMap = new Map<number, Channel>();

  scan: while (r.remaining > 0) {
    const rec = readRecord(r);
    if (!rec) break;
    const { opcode, data } = rec;

    switch (opcode) {
      case OP_SCHEMA: {
        const s = parseSchema(new Uint8Array(data));
        schemaMap.set(s.id, s);
        break;
      }
      case OP_CHANNEL: {
        const c = parseChannel(new Uint8Array(data));
        channelMap.set(c.id, c);
        break;
      }
      case OP_ATTACHMENT: {
        const att = parseAttachment(new Uint8Array(data));
        if (att.name === ATTACHMENT_NAME && att.mediaType === ATTACHMENT_MEDIA_TYPE) {
          wkaCount++;
          if (!unwrapped) {
            unwrapped = await tryUnwrapKey(att.data, privateKeyPem);
          }
        }
        break;
      }
      case OP_ENCRYPTED_CHUNK: {
        if (!unwrapped) {
          if (wkaCount === 0) throw new Error("encountered encrypted chunk before wrapped key attachment");
          throw new Error(`private key does not match any of the ${wkaCount} recipient key(s) in this file`);
        }
        for (const msg of await decryptAndVerifyChunk(new Uint8Array(data), unwrapped.symKey, unwrapped.fileId, chunkIdx)) {
          chunkIdx++;
          const channel = channelMap.get(msg.channelId);
          const schema = channel ? schemaMap.get(channel.schemaId) : undefined;
          if (channel && schema) yield { schema, channel, message: msg };
        }
        break;
      }
      case OP_FOOTER:
        break scan;
    }
  }

  if (!unwrapped) {
    if (wkaCount === 0) throw new Error("no wrapped key attachment found: is this an encrypted MCAP file?");
    throw new Error(`private key does not match any of the ${wkaCount} recipient key(s) in this file`);
  }
}

// decryptMcap decrypts an encrypted MCAP and returns a fully-indexed,
// seekable standard MCAP with ChunkIndex and summary section.
export async function decryptMcap(input: Uint8Array, privateKeyPem: string): Promise<Uint8Array> {
  const r = new BinaryReader(input);
  readMagic(r);

  let unwrapped: { symKey: Uint8Array; fileId: Uint8Array } | undefined;
  let chunkIdx = 0n;
  let wkaCount = 0;
  let inputProfile = "";
  let inputLibrary = "mcap-encrypt";
  const schemas: Schema[] = [];
  const channels: Channel[] = [];
  const messages: Message[] = [];

  scan: while (r.remaining > 0) {
    const rec = readRecord(r);
    if (!rec) break;
    const { opcode, data } = rec;

    switch (opcode) {
      case OP_HEADER: {
        try {
          const hdr = parseHeader(new Uint8Array(data));
          inputProfile = hdr.profile;
          inputLibrary = hdr.library;
        } catch { /* ignore malformed header; fall back to defaults */ }
        break;
      }
      case OP_SCHEMA:
        schemas.push(parseSchema(new Uint8Array(data)));
        break;
      case OP_CHANNEL:
        channels.push(parseChannel(new Uint8Array(data)));
        break;
      case OP_ATTACHMENT: {
        const att = parseAttachment(new Uint8Array(data));
        if (att.name === ATTACHMENT_NAME && att.mediaType === ATTACHMENT_MEDIA_TYPE) {
          wkaCount++;
          if (!unwrapped) {
            unwrapped = await tryUnwrapKey(att.data, privateKeyPem);
          }
        }
        break;
      }
      case OP_ENCRYPTED_CHUNK: {
        if (!unwrapped) {
          if (wkaCount === 0) throw new Error("encountered encrypted chunk before wrapped key attachment");
          throw new Error(`private key does not match any of the ${wkaCount} recipient key(s) in this file`);
        }
        messages.push(...(await decryptAndVerifyChunk(new Uint8Array(data), unwrapped.symKey, unwrapped.fileId, chunkIdx)));
        chunkIdx++;
        break;
      }
      case OP_FOOTER:
        break scan;
    }
  }

  if (!unwrapped) {
    if (wkaCount === 0) throw new Error("no wrapped key attachment found: is this an encrypted MCAP file?");
    throw new Error(`private key does not match any of the ${wkaCount} recipient key(s) in this file`);
  }

  return buildIndexedMcap(schemas, channels, messages, inputProfile, inputLibrary);
}

export async function* iterateMessages(
  input: Uint8Array,
  privateKeyPem: string,
): AsyncGenerator<{ schema: Schema; channel: Channel; message: Message }> {
  yield* streamMessages(input, privateKeyPem);
}

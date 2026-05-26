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
  OP_METADATA,
  OP_ENCRYPTED_CHUNK,
  OP_ENCRYPTED_ATTACHMENT,
  OP_ENCRYPTED_METADATA,
  readMagic,
  readRecord,
} from "./record.js";
import { decodeEncryptedChunk } from "./chunk.js";
import { decodeEncryptedAttachment, decryptAttachmentData } from "./attachment.js";
import { decodeEncryptedMetadata, decryptMetadata } from "./metadata.js";
import {
  ATTACHMENT_NAME,
  ATTACHMENT_MEDIA_TYPE,
  MANIFEST_ATTACHMENT_NAME,
  MANIFEST_ATTACHMENT_MEDIA_TYPE,
  MANIFEST_PAYLOAD_SIZE,
  computeManifestHMAC,
  decodeWrappedKeyData,
  unwrapSymmetricKey,
} from "./key.js";
import {
  parseSchema,
  parseChannel,
  parseMessage,
  parseMetadata,
  parseHeader,
  encodeSchema,
  encodeChannel,
  encodeMessage,
  encodeHeader,
  encodeMetadata,
  encodeDataEnd,
  encodeFooter,
  type Schema,
  type Channel,
  type Message,
  type Metadata,
} from "./mcap.js";
import { decompressChunkData } from "./decompress.js";
import { chunkAAD } from "./encrypt.js";
import { crc32 } from "./crc32.js";

// Additional opcodes used for building the indexed output (not exported by record.ts)
const OP_MESSAGE_INDEX = 0x07;
const OP_CHUNK_INDEX = 0x08;
const OP_STATISTICS = 0x0a;
const OP_METADATA_INDEX = 0x0d;
const OP_SUMMARY_OFFSET = 0x0e;

const MCAP_MAGIC = new Uint8Array([0x89, 0x4d, 0x43, 0x41, 0x50, 0x30, 0x0d, 0x0a]);

// MAX_CHUNK_BYTES is the target uncompressed size for each output chunk.
const MAX_CHUNK_BYTES = 4 * 1024 * 1024;

// timingSafeEqual compares two Uint8Arrays in constant time to prevent
// timing side-channel attacks in HMAC verification.
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

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

// ─── McapStreamBuilder ────────────────────────────────────────────────────────
//
// Builds a fully-indexed, seekable MCAP output without accumulating all messages
// in memory. Each decrypted chunk's messages are written immediately. At most
// MAX_CHUNK_BYTES of message data is held in the accumulator at any time.
// Attachments and metadata are buffered until finalize() since they must appear
// after all chunks in the data section.

type ChunkMeta = {
  startOffset: bigint;
  totalLength: bigint;
  msgStart: bigint;
  msgEnd: bigint;
  uncompressedSize: bigint;
  messageIndexOffsets: Map<number, bigint>;
  messageIndexTotalLength: bigint;
};

class McapStreamBuilder {
  private parts: Uint8Array[] = [];
  private pos = 0n;

  private schemas: Schema[] = [];
  private channels: Channel[] = [];
  private profile: string;
  private library: string;
  private headerFlushed = false;

  // Current output chunk accumulator — at most MAX_CHUNK_BYTES of message data
  private chunkBuf = new BinaryWriter();
  private chunkMsgStart = 0xffffffffffffffffn;
  private chunkMsgEnd = 0n;
  private chunkMsgIndexEntries = new Map<number, Array<{ logTime: bigint; offset: bigint }>>();

  // Per-chunk and global tracking for the summary section
  private chunkMetas: ChunkMeta[] = [];
  private globalMsgStart = 0xffffffffffffffffn;
  private globalMsgEnd = 0n;
  private globalMsgCounts = new Map<number, bigint>();
  private totalMsgCount = 0;

  // Buffered until finalize() because they follow all chunks in the data section
  private pendingAttachments: Uint8Array[] = [];
  private pendingMetadata: Metadata[] = [];

  constructor(profile = "", library = "mcap-encrypt") {
    this.profile = profile;
    this.library = library;
  }

  addSchema(s: Schema): void { this.schemas.push(s); }
  addChannel(c: Channel): void { this.channels.push(c); }

  // Process the decompressed bytes of one decrypted EncryptedChunk immediately.
  // Messages are parsed, written into the current output chunk accumulator, and
  // flushed to the parts buffer when the accumulator reaches MAX_CHUNK_BYTES.
  processDecryptedChunk(decompressed: Uint8Array): void {
    this.ensureHeader();
    const r = new BinaryReader(decompressed);
    while (r.remaining > 0) {
      const opcode = r.readUint8();
      const length = r.readUint64();
      const msgData = new Uint8Array(r.readBytes(safeBigintToNumber(length, "inner record length")));
      if (opcode !== OP_MESSAGE) continue;

      const msg = parseMessage(msgData);
      const offsetInChunk = BigInt(this.chunkBuf.length);

      const encoded = encodeMessage(msg);
      const hdr = new Uint8Array(9);
      hdr[0] = OP_MESSAGE;
      new DataView(hdr.buffer).setBigUint64(1, BigInt(encoded.length), true);
      this.chunkBuf.writeBytes(hdr);
      this.chunkBuf.writeBytes(encoded);

      if (!this.chunkMsgIndexEntries.has(msg.channelId)) {
        this.chunkMsgIndexEntries.set(msg.channelId, []);
      }
      this.chunkMsgIndexEntries.get(msg.channelId)!.push({ logTime: msg.logTime, offset: offsetInChunk });

      if (msg.logTime < this.chunkMsgStart) this.chunkMsgStart = msg.logTime;
      if (msg.logTime > this.chunkMsgEnd) this.chunkMsgEnd = msg.logTime;
      if (msg.logTime < this.globalMsgStart) this.globalMsgStart = msg.logTime;
      if (msg.logTime > this.globalMsgEnd) this.globalMsgEnd = msg.logTime;
      this.globalMsgCounts.set(msg.channelId, (this.globalMsgCounts.get(msg.channelId) ?? 0n) + 1n);
      this.totalMsgCount++;

      if (this.chunkBuf.length >= MAX_CHUNK_BYTES) this.flushChunk();
    }
  }

  addRawAttachment(raw: Uint8Array): void {
    this.pendingAttachments.push(raw);
  }

  addMetadata(rec: Metadata): void {
    this.pendingMetadata.push(rec);
  }

  // Flushes the current message accumulator as one output Chunk + MessageIndex records.
  private flushChunk(): void {
    if (this.chunkBuf.length === 0) return;

    const chunkData = this.chunkBuf.toUint8Array();
    const chunkStartOffset = this.pos;

    const cb = new BinaryWriter();
    cb.writeUint64(this.chunkMsgStart);
    cb.writeUint64(this.chunkMsgEnd);
    cb.writeUint64(BigInt(chunkData.length)); // uncompressed_size
    cb.writeUint32(0);                        // uncompressed_crc
    cb.writeString("");                       // compression = none
    cb.writeUint64(BigInt(chunkData.length)); // compressed_size
    cb.writeBytes(chunkData);
    this.emitRecord(OP_CHUNK, cb.toUint8Array());

    const chunkTotalLength = this.pos - chunkStartOffset;

    const messageIndexOffsets = new Map<number, bigint>();
    const messageIndexStart = this.pos;
    for (const [channelId, records] of this.chunkMsgIndexEntries) {
      messageIndexOffsets.set(channelId, this.pos);
      const mi = new BinaryWriter();
      mi.writeUint16(channelId);
      const pairs = new BinaryWriter();
      for (const { logTime, offset } of records) {
        pairs.writeUint64(logTime);
        pairs.writeUint64(offset);
      }
      const pairsBytes = pairs.toUint8Array();
      mi.writeUint32(pairsBytes.length);
      mi.writeBytes(pairsBytes);
      this.emitRecord(OP_MESSAGE_INDEX, mi.toUint8Array());
    }

    this.chunkMetas.push({
      startOffset: chunkStartOffset,
      totalLength: chunkTotalLength,
      msgStart: this.chunkMsgStart,
      msgEnd: this.chunkMsgEnd,
      uncompressedSize: BigInt(chunkData.length),
      messageIndexOffsets,
      messageIndexTotalLength: this.pos - messageIndexStart,
    });

    this.chunkBuf = new BinaryWriter();
    this.chunkMsgStart = 0xffffffffffffffffn;
    this.chunkMsgEnd = 0n;
    this.chunkMsgIndexEntries = new Map();
  }

  // Finalizes the output: flushes remaining messages, writes attachments,
  // metadata, DataEnd, and the full summary section.
  finalize(): Uint8Array {
    this.ensureHeader();
    this.flushChunk();

    // Attachments and metadata follow all chunks, before DataEnd.
    for (const raw of this.pendingAttachments) {
      this.emitRecord(OP_ATTACHMENT, raw);
    }

    const metadataIndexEntries: { offset: bigint; length: bigint; name: string }[] = [];
    for (const m of this.pendingMetadata) {
      const mStart = this.pos;
      this.emitRecord(OP_METADATA, encodeMetadata(m));
      metadataIndexEntries.push({ offset: mStart, length: this.pos - mStart, name: m.name });
    }

    this.emitRecord(OP_DATA_END, encodeDataEnd());

    // ── Summary section ───────────────────────────────────────────────────────

    const summaryStart = this.pos;

    const sumSchemaStart = this.pos;
    for (const s of this.schemas) this.emitRecord(OP_SCHEMA, encodeSchema(s));
    const sumSchemaLength = this.pos - sumSchemaStart;

    const sumChannelStart = this.pos;
    for (const c of this.channels) this.emitRecord(OP_CHANNEL, encodeChannel(c));
    const sumChannelLength = this.pos - sumChannelStart;

    const hasMessages = this.totalMsgCount > 0;
    const msgStart = hasMessages ? this.globalMsgStart : 0n;
    const msgEnd = hasMessages ? this.globalMsgEnd : 0n;

    const statsStart = this.pos;
    const statsBuf = new BinaryWriter();
    statsBuf.writeUint64(BigInt(this.totalMsgCount));
    statsBuf.writeUint16(this.schemas.length);
    statsBuf.writeUint32(this.channels.length);
    statsBuf.writeUint32(this.pendingAttachments.length);
    statsBuf.writeUint32(this.pendingMetadata.length);
    statsBuf.writeUint32(this.chunkMetas.length);
    statsBuf.writeUint64(msgStart);
    statsBuf.writeUint64(msgEnd);
    const mapBuf = new BinaryWriter();
    for (const [channelId, count] of this.globalMsgCounts) {
      mapBuf.writeUint16(channelId);
      mapBuf.writeUint64(count);
    }
    const mapBytes = mapBuf.toUint8Array();
    statsBuf.writeUint32(mapBytes.length);
    statsBuf.writeBytes(mapBytes);
    this.emitRecord(OP_STATISTICS, statsBuf.toUint8Array());
    const statsLength = this.pos - statsStart;

    const chunkIndexStart = this.pos;
    for (const cm of this.chunkMetas) {
      const ci = new BinaryWriter();
      ci.writeUint64(cm.msgStart);
      ci.writeUint64(cm.msgEnd);
      ci.writeUint64(cm.startOffset);
      ci.writeUint64(cm.totalLength);
      const ciMap = new BinaryWriter();
      for (const [channelId, offset] of cm.messageIndexOffsets) {
        ciMap.writeUint16(channelId);
        ciMap.writeUint64(offset);
      }
      const ciMapBytes = ciMap.toUint8Array();
      ci.writeUint32(ciMapBytes.length);
      ci.writeBytes(ciMapBytes);
      ci.writeUint64(cm.messageIndexTotalLength);
      ci.writeString("");                   // compression = ""
      ci.writeUint64(cm.uncompressedSize);  // uncompressed_size
      ci.writeUint64(cm.uncompressedSize);  // compressed_size (same; no recompression)
      this.emitRecord(OP_CHUNK_INDEX, ci.toUint8Array());
    }
    const chunkIndexLength = this.pos - chunkIndexStart;

    const metaIndexStart = this.pos;
    for (const mi of metadataIndexEntries) {
      const mib = new BinaryWriter();
      mib.writeUint64(mi.offset);
      mib.writeUint64(mi.length);
      mib.writeString(mi.name);
      this.emitRecord(OP_METADATA_INDEX, mib.toUint8Array());
    }
    const metaIndexLength = this.pos - metaIndexStart;

    const summaryOffsetStart = this.pos;
    const emitSO = (opcode: number, start: bigint, length: bigint): void => {
      if (length === 0n) return;
      const so = new BinaryWriter();
      so.writeUint8(opcode);
      so.writeUint64(start);
      so.writeUint64(length);
      this.emitRecord(OP_SUMMARY_OFFSET, so.toUint8Array());
    };
    emitSO(OP_SCHEMA, sumSchemaStart, sumSchemaLength);
    emitSO(OP_CHANNEL, sumChannelStart, sumChannelLength);
    emitSO(OP_STATISTICS, statsStart, statsLength);
    if (hasMessages) emitSO(OP_CHUNK_INDEX, chunkIndexStart, chunkIndexLength);
    if (metaIndexLength > 0n) emitSO(OP_METADATA_INDEX, metaIndexStart, metaIndexLength);

    const footerBuf = new BinaryWriter();
    footerBuf.writeUint64(summaryStart);
    footerBuf.writeUint64(summaryOffsetStart);
    footerBuf.writeUint32(0);
    this.emitRecord(OP_FOOTER, footerBuf.toUint8Array());

    this.emit(MCAP_MAGIC.slice());

    // Assemble all parts into the final output buffer.
    const total = Number(this.pos);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of this.parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  }

  private ensureHeader(): void {
    if (this.headerFlushed) return;
    this.headerFlushed = true;
    this.emit(MCAP_MAGIC.slice());
    this.emitRecord(OP_HEADER, encodeHeader(this.profile, this.library));
    for (const s of this.schemas) this.emitRecord(OP_SCHEMA, encodeSchema(s));
    for (const c of this.channels) this.emitRecord(OP_CHANNEL, encodeChannel(c));
  }

  private emit(data: Uint8Array): void {
    this.parts.push(data);
    this.pos += BigInt(data.length);
  }

  private emitRecord(opcode: number, data: Uint8Array): bigint {
    const startPos = this.pos;
    const hdr = new Uint8Array(9);
    hdr[0] = opcode;
    new DataView(hdr.buffer).setBigUint64(1, BigInt(data.length), true);
    this.emit(hdr);
    this.emit(data);
    return startPos;
  }
}

// ─── Per-chunk decrypt helpers ────────────────────────────────────────────────

// decryptAndDecompressChunk decrypts one EncryptedChunk, validates CRC, and
// returns the raw decompressed inner record bytes. The caller processes those
// bytes chunk-by-chunk; no Message[] accumulation occurs here.
async function decryptAndDecompressChunk(
  data: Uint8Array,
  symKey: Uint8Array,
  fileId: Uint8Array,
  chunkIdx: bigint,
): Promise<Uint8Array> {
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
    fileId, chunkIdx, ec.slotId, ec.compression,
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
  return decompressed;
}

// tryUnwrapKey attempts to unwrap the sym key from one wrapped-key attachment.
// Returns undefined if the key does not match (wrong recipient).
async function tryUnwrapKey(
  attData: Uint8Array,
  privateKeyPem: string,
): Promise<{ symKey: Uint8Array; fileId: Uint8Array } | undefined> {
  try {
    const wkd = decodeWrappedKeyData(attData);
    const symKey = await unwrapSymmetricKey(wkd.wrappedKey, privateKeyPem, wkd.kekAlg);
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
  let dataEndSeen = false;
  const schemaMap = new Map<number, Schema>();
  const channelMap = new Map<number, Channel>();

  scan: while (r.remaining > 0) {
    const rec = readRecord(r);
    if (!rec) break;
    const { opcode, data } = rec;

    switch (opcode) {
      case OP_SCHEMA: {
        if (!dataEndSeen) {
          const s = parseSchema(new Uint8Array(data));
          schemaMap.set(s.id, s);
        }
        break;
      }
      case OP_CHANNEL: {
        if (!dataEndSeen) {
          const c = parseChannel(new Uint8Array(data));
          channelMap.set(c.id, c);
        }
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
      case OP_DATA_END:
        dataEndSeen = true;
        break;
      case OP_ENCRYPTED_CHUNK: {
        if (!unwrapped) {
          if (wkaCount === 0) throw new Error("encountered encrypted chunk before wrapped key attachment");
          throw new Error(`private key does not match any of the ${wkaCount} recipient key(s) in this file`);
        }
        const decompressed = await decryptAndDecompressChunk(
          new Uint8Array(data), unwrapped.symKey, unwrapped.fileId, chunkIdx,
        );
        const ir = new BinaryReader(decompressed);
        while (ir.remaining > 0) {
          const innerOpcode = ir.readUint8();
          const length = ir.readUint64();
          const msgData = new Uint8Array(ir.readBytes(safeBigintToNumber(length, "inner record length")));
          if (innerOpcode === OP_MESSAGE) {
            const msg = parseMessage(msgData);
            const channel = channelMap.get(msg.channelId);
            const schema = channel ? schemaMap.get(channel.schemaId) : undefined;
            if (channel && schema) yield { schema, channel, message: msg };
          }
        }
        chunkIdx++;
        break;
      }
      case OP_ENCRYPTED_ATTACHMENT:
      case OP_ENCRYPTED_METADATA:
        // Neither attachments nor metadata records are messages; skip.
        break;
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
//
// Memory usage: schemas, channels, and attachment data are held in memory
// throughout. Message data is processed one chunk at a time (at most
// MAX_CHUNK_BYTES = 4 MiB in the current accumulator); no Message[] is
// accumulated across chunks, so large files do not require proportional RAM.
//
// The optional onWarn callback is called with a human-readable message when a
// non-fatal issue is encountered, such as a wrapped-key attachment that cannot
// be parsed. If omitted, such issues are silently skipped (backward compatible).
export async function decryptMcap(
  input: Uint8Array,
  privateKeyPem: string,
  onWarn?: (msg: string) => void,
): Promise<Uint8Array> {
  const r = new BinaryReader(input);
  readMagic(r);

  let unwrapped: { symKey: Uint8Array; fileId: Uint8Array } | undefined;
  let chunkIdx = 0n;
  let wkaCount = 0;
  let manifestRequired = false;
  let dataEndSeen = false;
  let manifestPayload: Uint8Array | undefined;

  const builder = new McapStreamBuilder();

  scan: while (r.remaining > 0) {
    const rec = readRecord(r);
    if (!rec) break;
    const { opcode, data } = rec;

    switch (opcode) {
      case OP_HEADER: {
        try {
          const hdr = parseHeader(new Uint8Array(data));
          // McapStreamBuilder defaults to "" / "mcap-encrypt"; only override if non-empty.
          if (hdr.profile || hdr.library) {
            // Re-create builder with the correct header fields.
            // This is safe because schemas/channels/chunks have not been added yet.
            const rebuilt = new McapStreamBuilder(hdr.profile, hdr.library);
            Object.assign(builder, rebuilt);
          }
        } catch { /* ignore malformed header */ }
        break;
      }
      case OP_SCHEMA:
        if (!dataEndSeen) builder.addSchema(parseSchema(new Uint8Array(data)));
        break;
      case OP_CHANNEL:
        if (!dataEndSeen) builder.addChannel(parseChannel(new Uint8Array(data)));
        break;
      case OP_METADATA:
        if (!dataEndSeen) builder.addMetadata(parseMetadata(new Uint8Array(data)));
        break;
      case OP_ATTACHMENT: {
        const att = parseAttachment(new Uint8Array(data));
        if (att.name === ATTACHMENT_NAME && att.mediaType === ATTACHMENT_MEDIA_TYPE) {
          wkaCount++;
          try {
            const wkd = decodeWrappedKeyData(att.data);
            if (wkd.version >= 3) manifestRequired = true;
          } catch (e) {
            onWarn?.(`wrapped-key attachment #${wkaCount} could not be parsed: ${e instanceof Error ? e.message : String(e)}`);
          }
          if (!unwrapped) {
            unwrapped = await tryUnwrapKey(att.data, privateKeyPem);
          }
        } else if (att.name === MANIFEST_ATTACHMENT_NAME && att.mediaType === MANIFEST_ATTACHMENT_MEDIA_TYPE) {
          manifestPayload = new Uint8Array(att.data);
        } else if (!dataEndSeen) {
          builder.addRawAttachment(new Uint8Array(data));
        }
        break;
      }
      case OP_DATA_END:
        dataEndSeen = true;
        break;
      case OP_ENCRYPTED_CHUNK: {
        if (!unwrapped) {
          if (wkaCount === 0) throw new Error("encountered encrypted chunk before wrapped key attachment");
          throw new Error(`private key does not match any of the ${wkaCount} recipient key(s) in this file`);
        }
        const decompressed = await decryptAndDecompressChunk(
          new Uint8Array(data), unwrapped.symKey, unwrapped.fileId, chunkIdx,
        );
        builder.processDecryptedChunk(decompressed);
        chunkIdx++;
        break;
      }
      case OP_ENCRYPTED_ATTACHMENT: {
        if (!unwrapped) break; // key not yet found; skip (error raised after scan)
        const ea = decodeEncryptedAttachment(new Uint8Array(data));
        const plain = decryptAttachmentData(ea, unwrapped.symKey, unwrapped.fileId);
        const w = new BinaryWriter();
        w.writeUint64(ea.logTime);
        w.writeUint64(ea.createTime);
        w.writeString(ea.name);
        w.writeString(ea.mediaType);
        w.writeUint64(BigInt(plain.length));
        w.writeBytes(plain);
        w.writeUint32(0); // crc = 0
        builder.addRawAttachment(w.toUint8Array());
        break;
      }
      case OP_ENCRYPTED_METADATA: {
        if (!unwrapped) break; // key not yet found; decoded in second pass below
        const em = decodeEncryptedMetadata(new Uint8Array(data));
        const metaPayload = decryptMetadata(em, unwrapped.symKey, unwrapped.fileId);
        builder.addMetadata(parseMetadata(metaPayload));
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

  // v3+ files always write a manifest; reject if it was stripped.
  if (manifestRequired && manifestPayload == null) {
    throw new Error(
      "manifest attachment missing: file may have been tampered with (strip attack)",
    );
  }

  // Verify manifest if present.
  if (manifestPayload != null) {
    if (manifestPayload.length < MANIFEST_PAYLOAD_SIZE) {
      throw new Error(`manifest payload too short (${manifestPayload.length} bytes, need ${MANIFEST_PAYLOAD_SIZE})`);
    }
    const storedCount = new DataView(manifestPayload.buffer, manifestPayload.byteOffset).getBigUint64(0, true);
    const storedHmac = manifestPayload.slice(8, 8 + 32);
    const expectedHmac = await computeManifestHMAC(unwrapped.symKey, storedCount, unwrapped.fileId);
    if (!timingSafeEqual(storedHmac, expectedHmac)) {
      throw new Error("manifest HMAC verification failed: file may be corrupted or tampered");
    }
    if (storedCount !== chunkIdx) {
      throw new Error(
        `manifest chunk count mismatch: file declares ${storedCount} chunk(s), decrypted ${chunkIdx} (file may be truncated or padded)`,
      );
    }
  }

  return builder.finalize();
}

export async function* iterateMessages(
  input: Uint8Array,
  privateKeyPem: string,
): AsyncGenerator<{ schema: Schema; channel: Channel; message: Message }> {
  yield* streamMessages(input, privateKeyPem);
}

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { BinaryReader, BinaryWriter } from "./binary.js";
import {
  OP_SCHEMA,
  OP_CHANNEL,
  OP_ATTACHMENT,
  OP_DATA_END,
  OP_FOOTER,
  OP_MESSAGE,
  OP_ENCRYPTED_CHUNK,
  readMagic,
  readRecord,
  writeRecord,
  writeMagic,
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
  encodeSchema,
  encodeChannel,
  encodeMessage,
  encodeHeader,
  encodeDataEnd,
  encodeFooter,
  type Schema,
  type Channel,
  type Message,
} from "./mcap.js";
import { decompressChunkData } from "./decompress.js";
import { chunkAAD } from "./encrypt.js";
import { crc32 } from "./crc32.js";

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
  const attData = new Uint8Array(r.readBytes(Number(dataSize)));
  return { name, mediaType, data: attData };
}

function parseInnerRecords(decompressed: Uint8Array): Message[] {
  const r = new BinaryReader(decompressed);
  const msgs: Message[] = [];
  while (r.remaining > 0) {
    const opcode = r.readUint8();
    const length = r.readUint64();
    const data = r.readBytes(Number(length));
    if (opcode === OP_MESSAGE) {
      msgs.push(parseMessage(new Uint8Array(data)));
    }
  }
  return msgs;
}

// Performs a single-pass stream over the encrypted MCAP, yielding decrypted
// messages immediately as each chunk is processed. No chunk buffering required
// because the wrapped key attachment appears before the first encrypted chunk.
async function* streamMessages(
  input: Uint8Array,
  privateKeyPem: string,
): AsyncGenerator<{ schema: Schema; channel: Channel; message: Message }> {
  const r = new BinaryReader(input);
  readMagic(r);

  let symKey: Uint8Array | null = null;
  const schemas: Schema[] = [];
  const channels: Channel[] = [];
  const schemaMap = new Map<number, Schema>();
  const channelMap = new Map<number, Channel>();

  scan: while (r.remaining > 0) {
    const rec = readRecord(r);
    if (!rec) break;
    const { opcode, data } = rec;

    switch (opcode) {
      case OP_SCHEMA: {
        const s = parseSchema(new Uint8Array(data));
        schemas.push(s);
        schemaMap.set(s.id, s);
        break;
      }
      case OP_CHANNEL: {
        const c = parseChannel(new Uint8Array(data));
        channels.push(c);
        channelMap.set(c.id, c);
        break;
      }
      case OP_ATTACHMENT: {
        const att = parseAttachment(new Uint8Array(data));
        if (att.name === ATTACHMENT_NAME && att.mediaType === ATTACHMENT_MEDIA_TYPE) {
          const wkd = decodeWrappedKeyData(att.data);
          symKey = await unwrapSymmetricKey(wkd.wrappedKey, privateKeyPem);
        }
        break;
      }
      case OP_ENCRYPTED_CHUNK: {
        if (!symKey) {
          throw new Error("encountered encrypted chunk before wrapped key attachment");
        }
        const ec = decodeEncryptedChunk(new Uint8Array(data));
        const aad = chunkAAD(ec.messageStartTime, ec.messageEndTime);
        let plaintext: Uint8Array;
        try {
          plaintext = xchacha20poly1305(symKey, ec.nonce, aad).decrypt(ec.encryptedData);
        } catch {
          throw new Error(
            `decrypt chunk [${ec.messageStartTime}–${ec.messageEndTime}]: authentication failed`,
          );
        }
        const decompressed = decompressChunkData(plaintext, ec.compression);
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
        for (const msg of parseInnerRecords(decompressed)) {
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

  if (!symKey) {
    throw new Error("no wrapped key attachment found, is this an encrypted MCAP file?");
  }
}

export async function decryptMcap(input: Uint8Array, privateKeyPem: string): Promise<Uint8Array> {
  // Single-pass: collect schemas/channels first, then write output.
  // Because the wrapped key precedes chunks, we can write messages as we decrypt.
  const r = new BinaryReader(input);
  readMagic(r);

  let symKey: Uint8Array | null = null;
  const schemas: Schema[] = [];
  const channels: Channel[] = [];
  const messages: Message[] = [];

  scan: while (r.remaining > 0) {
    const rec = readRecord(r);
    if (!rec) break;
    const { opcode, data } = rec;

    switch (opcode) {
      case OP_SCHEMA:
        schemas.push(parseSchema(new Uint8Array(data)));
        break;
      case OP_CHANNEL:
        channels.push(parseChannel(new Uint8Array(data)));
        break;
      case OP_ATTACHMENT: {
        const att = parseAttachment(new Uint8Array(data));
        if (att.name === ATTACHMENT_NAME && att.mediaType === ATTACHMENT_MEDIA_TYPE) {
          const wkd = decodeWrappedKeyData(att.data);
          symKey = await unwrapSymmetricKey(wkd.wrappedKey, privateKeyPem);
        }
        break;
      }
      case OP_ENCRYPTED_CHUNK: {
        if (!symKey) throw new Error("encountered encrypted chunk before wrapped key attachment");
        const ec = decodeEncryptedChunk(new Uint8Array(data));
        const aad = chunkAAD(ec.messageStartTime, ec.messageEndTime);
        let plaintext: Uint8Array;
        try {
          plaintext = xchacha20poly1305(symKey, ec.nonce, aad).decrypt(ec.encryptedData);
        } catch {
          throw new Error(
            `decrypt chunk [${ec.messageStartTime}–${ec.messageEndTime}]: authentication failed`,
          );
        }
        const decompressed = decompressChunkData(plaintext, ec.compression);
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
        messages.push(...parseInnerRecords(decompressed));
        break;
      }
      case OP_FOOTER:
        break scan;
    }
  }

  if (!symKey) throw new Error("no wrapped key attachment found, is this an encrypted MCAP file?");

  const w = new BinaryWriter();
  writeMagic(w);
  writeRecord(w, 0x01, encodeHeader("", ""));
  for (const s of schemas) writeRecord(w, OP_SCHEMA, encodeSchema(s));
  for (const c of channels) writeRecord(w, OP_CHANNEL, encodeChannel(c));
  for (const m of messages) writeRecord(w, OP_MESSAGE, encodeMessage(m));
  writeRecord(w, OP_DATA_END, encodeDataEnd());
  writeRecord(w, OP_FOOTER, encodeFooter());
  writeMagic(w);
  return w.toUint8Array();
}

export async function* iterateMessages(
  input: Uint8Array,
  privateKeyPem: string,
): AsyncGenerator<{ schema: Schema; channel: Channel; message: Message }> {
  yield* streamMessages(input, privateKeyPem);
}

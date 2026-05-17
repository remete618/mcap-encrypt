import { BinaryReader, safeBigintToNumber } from "./binary.js";
import {
  ATTACHMENT_NAME,
  ATTACHMENT_MEDIA_TYPE,
  MANIFEST_ATTACHMENT_NAME,
  MANIFEST_ATTACHMENT_MEDIA_TYPE,
  decodeWrappedKeyData,
} from "./key.js";
import { readMagic, readRecord, OP_FOOTER, OP_ATTACHMENT, OP_ENCRYPTED_CHUNK, OP_ENCRYPTED_ATTACHMENT } from "./record.js";
import { parseAttachmentFields } from "./attachment.js";

export interface RecipientInfo {
  keyId: string;
  kekAlg: string;
  algorithm: string;
}

export interface InspectResult {
  isEncrypted: boolean;
  formatVersion: number; // from WrappedKeyData.version (2 or 3)
  fileId: Uint8Array | null; // 16-byte random file identifier
  chunkCount: number; // declared in manifest attachment
  encryptedChunkCount: number; // actual 0x81 records scanned
  encryptedAttachmentCount: number; // actual 0x82 records scanned
  compression: string; // from first EncryptedChunk header
  recipients: RecipientInfo[];
}

// inspectMcap scans an MCAP (encrypted or plain) and returns its metadata
// without decrypting any chunk data. No private key is required.
export function inspectMcap(input: Uint8Array): InspectResult {
  const r = new BinaryReader(input);
  readMagic(r);

  const result: InspectResult = {
    isEncrypted: false,
    formatVersion: 0,
    fileId: null,
    chunkCount: 0,
    encryptedChunkCount: 0,
    encryptedAttachmentCount: 0,
    compression: "",
    recipients: [],
  };

  let compressionSet = false;

  while (r.remaining > 0) {
    const rec = readRecord(r);
    if (rec === null) break;
    const { opcode, data } = rec;

    if (opcode === OP_FOOTER) {
      break;
    } else if (opcode === OP_ATTACHMENT) {
      let fields: ReturnType<typeof parseAttachmentFields>;
      try {
        fields = parseAttachmentFields(data);
      } catch {
        continue;
      }
      const { name, mediaType, attData } = fields;

      if (name === ATTACHMENT_NAME && mediaType === ATTACHMENT_MEDIA_TYPE) {
        try {
          const wk = decodeWrappedKeyData(attData);
          result.isEncrypted = true;
          if (result.fileId === null) {
            result.fileId = wk.fileId;
            result.formatVersion = wk.version;
          }
          result.recipients.push({
            keyId: wk.keyId,
            kekAlg: wk.kekAlg,
            algorithm: wk.algorithm,
          });
        } catch {
          continue;
        }
      } else if (name === MANIFEST_ATTACHMENT_NAME && mediaType === MANIFEST_ATTACHMENT_MEDIA_TYPE) {
        if (attData.length >= 8) {
          const view = new DataView(attData.buffer, attData.byteOffset, attData.byteLength);
          result.chunkCount = safeBigintToNumber(view.getBigUint64(0, true), "manifest chunk count");
        }
      }
    } else if (opcode === OP_ENCRYPTED_CHUNK) {
      result.isEncrypted = true;
      result.encryptedChunkCount++;
      if (!compressionSet) {
        // EncryptedChunk layout: 3×uint64 (24) + uint32 (4) = 28 fixed bytes,
        // then string compression = uint32 length (4) + bytes.
        try {
          const cr = new BinaryReader(data);
          cr.readUint64(); // messageStartTime
          cr.readUint64(); // messageEndTime
          cr.readUint64(); // uncompressedSize
          cr.readUint32(); // uncompressedCrc
          result.compression = cr.readString();
          compressionSet = true;
        } catch {
          // malformed chunk header; skip
        }
      }
    } else if (opcode === OP_ENCRYPTED_ATTACHMENT) {
      result.isEncrypted = true;
      result.encryptedAttachmentCount++;
    }
  }

  return result;
}

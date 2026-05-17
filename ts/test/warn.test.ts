import { describe, it, expect, beforeAll } from "vitest";
import { encryptMcap, decryptMcap, generateKeyPair, type KeyPair } from "../src/index.js";
import { BinaryReader } from "../src/binary.js";
import { ATTACHMENT_NAME, ATTACHMENT_MEDIA_TYPE } from "../src/key.js";

let keys: KeyPair;

beforeAll(async () => {
  keys = await generateKeyPair();
});

// Finds the first OP_ATTACHMENT (0x09) record whose name matches the wrapped-key
// name and zeroes out the inner data-field bytes so that decodeWrappedKeyData
// will throw when it is called. The outer record framing (opcode, length, name,
// mediaType, dataSize) is left intact so that parseAttachmentRecord still works.
function corruptWrappedKeyAttachmentData(mcap: Uint8Array): Uint8Array {
  const view = new DataView(mcap.buffer, mcap.byteOffset);
  const copy = mcap.slice();
  const copyView = new DataView(copy.buffer, copy.byteOffset);

  let pos = 8; // skip magic
  while (pos + 9 <= copy.length) {
    const opcode = copy[pos]!;
    const recLen = Number(view.getBigUint64(pos + 1, true));
    if (opcode === 0x09) {
      const payloadStart = pos + 9;
      const r = new BinaryReader(copy.slice(payloadStart, payloadStart + recLen));
      r.readUint64(); // log_time
      r.readUint64(); // create_time
      const name = r.readString();
      const mediaType = r.readString();
      if (name === ATTACHMENT_NAME && mediaType === ATTACHMENT_MEDIA_TYPE) {
        const dataSizeOffset = payloadStart + r.offset;
        const dataSize = Number(copyView.getBigUint64(dataSizeOffset, true));
        const dataStart = dataSizeOffset + 8;
        // Zero out the wrapped-key data bytes so decodeWrappedKeyData throws.
        for (let i = dataStart; i < dataStart + dataSize; i++) {
          copy[i] = 0x00;
        }
        return copy;
      }
    }
    pos += 9 + recLen;
  }
  throw new Error("no wrapped-key attachment (0x09) found to corrupt");
}

// A minimal plain MCAP (no messages, minimal structure) is enough — we only
// need the wrapped-key attachment to be present in the encrypted output.
function buildMinimalMcap(): Uint8Array {
  // Re-use the encryptMcap helper which requires a valid MCAP input.
  // Build the raw bytes manually: magic + Header + DataEnd + Footer + magic.
  const w: number[] = [];
  const push = (...bytes: number[]) => bytes.forEach((b) => w.push(b));
  const pushU64 = (v: bigint) => {
    for (let i = 0; i < 8; i++) push(Number((v >> BigInt(i * 8)) & 0xffn));
  };
  const pushU32 = (v: number) => {
    for (let i = 0; i < 4; i++) push((v >> (i * 8)) & 0xff);
  };
  const pushStr = (s: string) => {
    const enc = new TextEncoder().encode(s);
    pushU32(enc.length);
    enc.forEach((b) => push(b));
  };
  const pushRecord = (opcode: number, body: number[]) => {
    push(opcode);
    pushU64(BigInt(body.length));
    body.forEach((b) => push(b));
  };

  // MCAP magic
  push(0x89, 0x4d, 0x43, 0x41, 0x50, 0x30, 0x0d, 0x0a);

  // Header record (opcode 0x01): profile="" library=""
  const hdrBody: number[] = [];
  const pushToArr = (arr: number[]) => {
    const origPush = w.push.bind(w);
    const oldLen = w.length;
    pushStr(""); // profile
    pushStr(""); // library
    const added = w.splice(oldLen, w.length - oldLen);
    added.forEach((b) => arr.push(b));
  };
  {
    const tmpBuf: number[] = [];
    const enc = new TextEncoder();
    const profile = enc.encode("");
    const library = enc.encode("");
    for (let i = 0; i < 4; i++) tmpBuf.push((profile.length >> (i * 8)) & 0xff);
    profile.forEach((b) => tmpBuf.push(b));
    for (let i = 0; i < 4; i++) tmpBuf.push((library.length >> (i * 8)) & 0xff);
    library.forEach((b) => tmpBuf.push(b));
    pushRecord(0x01, tmpBuf);
  }

  // DataEnd record (opcode 0x0f): data_section_crc=0 (4 bytes)
  pushRecord(0x0f, [0, 0, 0, 0]);

  // Footer record (opcode 0x02): summary_start=0, summary_offset_start=0, summary_crc=0
  pushRecord(0x02, [
    0,0,0,0,0,0,0,0, // summary_start
    0,0,0,0,0,0,0,0, // summary_offset_start
    0,0,0,0,         // summary_crc
  ]);

  // MCAP magic (end)
  push(0x89, 0x4d, 0x43, 0x41, 0x50, 0x30, 0x0d, 0x0a);

  return new Uint8Array(w);
}

describe("warn callback", () => {
  it("onWarn is called when a wrapped-key attachment payload is malformed", async () => {
    // Encrypt a file so we have a real wrapped-key attachment in the output.
    const plain = buildMinimalMcap();
    const enc = await encryptMcap(plain, keys.publicKeyPem);

    // Corrupt the data field of the first wrapped-key attachment.
    const corrupted = corruptWrappedKeyAttachmentData(enc);

    const warnings: string[] = [];
    // Decryption is expected to fail (only one recipient slot, now malformed)
    // but onWarn must be called before the error.
    try {
      await decryptMcap(corrupted, keys.privateKeyPem, (msg) => {
        warnings.push(msg);
      });
    } catch {
      // Expected: no valid key slot remains after corruption.
    }

    expect(warnings.length).toBeGreaterThan(0);
    expect(warnings[0]).toMatch(/could not be parsed/);
  });

  it("onWarn is not called on a clean decrypt", async () => {
    const plain = buildMinimalMcap();
    const enc = await encryptMcap(plain, keys.publicKeyPem);

    const warnings: string[] = [];
    await decryptMcap(enc, keys.privateKeyPem, (msg) => {
      warnings.push(msg);
    });

    expect(warnings).toHaveLength(0);
  });
});

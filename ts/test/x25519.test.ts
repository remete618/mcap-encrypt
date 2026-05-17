/**
 * Tests for X25519-HKDF-XChaCha20Poly1305 key wrapping.
 *
 * Structure:
 *  Part 1 – KDF test vector: anchors HKDF parameters against the Go reference
 *  Part 2 – wrapSymmetricKeyX25519 / unwrapSymmetricKeyX25519 unit tests
 *  Part 3 – generateX25519KeyPair
 *  Part 4 – encryptMcap / decryptMcap with X25519 key
 *  Part 5 – multi-recipient (RSA + X25519)
 */
import { describe, it, expect, beforeAll } from "vitest";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha256.js";
import {
  encryptMcap,
  decryptMcap,
  generateKeyPair,
  generateX25519KeyPair,
  type KeyPair,
  type X25519KeyPair,
} from "../src/index.js";
import {
  wrapSymmetricKeyX25519,
  unwrapSymmetricKeyX25519,
  isX25519PublicKeyPem,
} from "../src/key.js";
import { buildTestMcap, buildMultiChunkMcap, collectMessages } from "./helpers.js";

let rsaKeys: KeyPair;
let x25519Keys: X25519KeyPair;

beforeAll(async () => {
  [rsaKeys, x25519Keys] = await Promise.all([generateKeyPair(), generateX25519KeyPair()]);
});

// ─── Part 1: KDF test vector ──────────────────────────────────────────────────
//
// Mirrors Go TestX25519KDFTestVector in pkg/mcapencrypt/kdf_test.go.
// shared = [0x01, 0x02, ..., 0x20] (bytes 1–32).
// Expected computed once with: hkdf.New(sha256.New, shared, nil, "mcap-encrypt x25519 v1")

describe("X25519 KDF test vector", () => {
  it("HKDF output matches Go reference vector", () => {
    const shared = new Uint8Array(32);
    for (let i = 0; i < 32; i++) shared[i] = i + 1;

    // salt=undefined → @noble/hashes uses 32 zero bytes (RFC 5869 default),
    // which matches Go's hkdf.New(sha256.New, shared, nil, info).
    const kek = hkdf(sha256, shared, undefined, "mcap-encrypt x25519 v1", 32);

    const expected = new Uint8Array([
      0xce, 0x10, 0x14, 0x08, 0x49, 0x24, 0x09, 0x58,
      0x06, 0x93, 0x0f, 0x17, 0xa6, 0xf6, 0xab, 0x8a,
      0x0d, 0x85, 0x00, 0x44, 0xbc, 0xc0, 0x90, 0x38,
      0xf6, 0x40, 0x74, 0x55, 0xae, 0x9b, 0xa9, 0x00,
    ]);
    expect(kek).toEqual(expected);
  });
});

// ─── Part 2: wrapSymmetricKeyX25519 / unwrapSymmetricKeyX25519 ────────────────

describe("wrapSymmetricKeyX25519 / unwrapSymmetricKeyX25519", () => {
  it("wraps and unwraps a 32-byte symmetric key", async () => {
    const symKey = new Uint8Array(32).fill(0xab);
    const wrapped = await wrapSymmetricKeyX25519(symKey, x25519Keys.publicKeyPem);
    // Wire format: ephem_pub(32) || nonce(24) || ciphertext(32 + 16 = 48)
    expect(wrapped.length).toBe(104);
    const recovered = await unwrapSymmetricKeyX25519(wrapped, x25519Keys.privateKeyPem);
    expect(recovered).toEqual(symKey);
  });

  it("each wrap call produces a different ciphertext (ephemeral key is fresh)", async () => {
    const symKey = new Uint8Array(32).fill(0xcd);
    const w1 = await wrapSymmetricKeyX25519(symKey, x25519Keys.publicKeyPem);
    const w2 = await wrapSymmetricKeyX25519(symKey, x25519Keys.publicKeyPem);
    expect(w1).not.toEqual(w2);
  });

  it("wrong private key causes authentication failure", async () => {
    const other = await generateX25519KeyPair();
    const symKey = new Uint8Array(32).fill(0x77);
    const wrapped = await wrapSymmetricKeyX25519(symKey, x25519Keys.publicKeyPem);
    await expect(unwrapSymmetricKeyX25519(wrapped, other.privateKeyPem)).rejects.toThrow(
      /authentication failed/,
    );
  });

  it("RSA private key rejected when trying to unwrap X25519-wrapped key", async () => {
    const symKey = new Uint8Array(32).fill(0x55);
    const wrapped = await wrapSymmetricKeyX25519(symKey, x25519Keys.publicKeyPem);
    await expect(unwrapSymmetricKeyX25519(wrapped, rsaKeys.privateKeyPem)).rejects.toThrow();
  });
});

// ─── Part 3: generateX25519KeyPair ───────────────────────────────────────────

describe("generateX25519KeyPair", () => {
  it("generates PEM-formatted keys", async () => {
    const kp = await generateX25519KeyPair();
    expect(kp.publicKeyPem).toContain("BEGIN PUBLIC KEY");
    expect(kp.privateKeyPem).toContain("BEGIN PRIVATE KEY");
  });

  it("isX25519PublicKeyPem returns true for X25519 public key", async () => {
    expect(isX25519PublicKeyPem(x25519Keys.publicKeyPem)).toBe(true);
  });

  it("isX25519PublicKeyPem returns false for RSA public key", () => {
    expect(isX25519PublicKeyPem(rsaKeys.publicKeyPem)).toBe(false);
  });

  it("generated key pair can round-trip a symmetric key", async () => {
    const kp = await generateX25519KeyPair();
    const symKey = crypto.getRandomValues(new Uint8Array(32));
    const wrapped = await wrapSymmetricKeyX25519(symKey, kp.publicKeyPem);
    const recovered = await unwrapSymmetricKeyX25519(wrapped, kp.privateKeyPem);
    expect(recovered).toEqual(symKey);
  });
});

// ─── Part 4: encryptMcap / decryptMcap with X25519 key ───────────────────────

describe("encryptMcap with X25519 key", () => {
  it("round-trip: encrypt with X25519 pubkey, decrypt with X25519 privkey", async () => {
    const plain = buildTestMcap();
    const originalMessages = collectMessages(plain);

    const enc = await encryptMcap(plain, x25519Keys.publicKeyPem);
    const dec = await decryptMcap(enc, x25519Keys.privateKeyPem);

    const decMessages = collectMessages(dec);
    expect(decMessages.length).toBe(originalMessages.length);
    for (let i = 0; i < originalMessages.length; i++) {
      expect(decMessages[i]!.data).toEqual(originalMessages[i]!.data);
    }
  });

  it("RSA private key cannot decrypt X25519-encrypted file", async () => {
    const enc = await encryptMcap(buildTestMcap(), x25519Keys.publicKeyPem);
    await expect(decryptMcap(enc, rsaKeys.privateKeyPem)).rejects.toThrow(
      /private key does not match/,
    );
  });
});

// ─── Part 5: multi-recipient (RSA + X25519) ───────────────────────────────────

describe("multi-recipient RSA + X25519", () => {
  it("both recipients recover identical messages", async () => {
    const { mcap: plain } = buildMultiChunkMcap(2, 5);
    const enc = await encryptMcap(plain, [rsaKeys.publicKeyPem, x25519Keys.publicKeyPem]);

    const decRsa = await decryptMcap(enc, rsaKeys.privateKeyPem);
    const decX25519 = await decryptMcap(enc, x25519Keys.privateKeyPem);

    const rsaMsgs = collectMessages(decRsa);
    const x25519Msgs = collectMessages(decX25519);

    expect(rsaMsgs.length).toBe(x25519Msgs.length);
    for (let i = 0; i < rsaMsgs.length; i++) {
      expect(rsaMsgs[i]!.data).toEqual(x25519Msgs[i]!.data);
    }
  });

  it("wrong RSA key cannot read X25519-recipient-only file", async () => {
    const other = await generateX25519KeyPair();
    const enc = await encryptMcap(buildTestMcap(), x25519Keys.publicKeyPem);
    await expect(decryptMcap(enc, other.privateKeyPem)).rejects.toThrow(/private key does not match/);
  });
});

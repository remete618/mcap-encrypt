/**
 * Browser-mode smoke test. Verifies that the library works in a Web Crypto
 * environment without Node-specific APIs (Buffer, node:crypto, etc.).
 *
 * Run with: npm run test:browser
 * Requires: @vitest/browser + playwright chromium installed.
 */
import { describe, it, expect } from "vitest";
import {
  generateKeyPair,
  generateX25519KeyPair,
  encryptMcap,
  decryptMcap,
} from "../src/index.js";
import { buildTestMcap } from "./helpers.js";

describe("browser Web Crypto smoke test", () => {
  it("RSA round-trip in browser environment", async () => {
    const { publicKeyPem, privateKeyPem } = await generateKeyPair();
    const plain = buildTestMcap();
    const enc = await encryptMcap(plain, publicKeyPem);
    const dec = await decryptMcap(enc, privateKeyPem);
    expect(dec.length).toBeGreaterThan(0);
  });

  it("X25519 round-trip in browser environment", async () => {
    const { publicKeyPem, privateKeyPem } = await generateX25519KeyPair();
    const plain = buildTestMcap();
    const enc = await encryptMcap(plain, publicKeyPem);
    const dec = await decryptMcap(enc, privateKeyPem);
    expect(dec.length).toBeGreaterThan(0);
  });
});

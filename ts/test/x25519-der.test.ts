/**
 * X25519 DER-encoding assertion test.
 *
 * The TypeScript implementation hardcodes the SPKI/PKCS#8 byte prefixes
 * required by RFC 8410. If those prefixes ever drift from the spec the
 * resulting keys are silently incompatible with every other X25519
 * implementation (Go, Python, OpenSSL). This test pins the contract
 * by generating a key with our public API and verifying the produced
 * DER matches the RFC 8410 structure byte-for-byte.
 */
import { describe, it, expect } from "vitest";
import { generateX25519KeyPair } from "../src/index.js";

function pemToDer(pem: string): Uint8Array {
  const body = pem
    .replace(/-----(BEGIN|END) [A-Z ]+-----/g, "")
    .replace(/\s+/g, "");
  const bin = atob(body);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// RFC 8410 fixed prefixes. These bytes encode the ASN.1 wrappers around a
// 32-byte raw X25519 key. They are normative and cannot change.
const RFC8410_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
]);
const RFC8410_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04,
  0x22, 0x04, 0x20,
]);

describe("X25519 DER encoding matches RFC 8410", () => {
  it("public key SPKI prefix is RFC 8410 compliant", async () => {
    const { publicKeyPem } = await generateX25519KeyPair();
    const der = pemToDer(publicKeyPem);
    expect(der.length).toBe(RFC8410_SPKI_PREFIX.length + 32);
    expect(der.slice(0, RFC8410_SPKI_PREFIX.length)).toEqual(RFC8410_SPKI_PREFIX);
  });

  it("private key PKCS#8 prefix is RFC 8410 compliant", async () => {
    const { privateKeyPem } = await generateX25519KeyPair();
    const der = pemToDer(privateKeyPem);
    expect(der.length).toBe(RFC8410_PKCS8_PREFIX.length + 32);
    expect(der.slice(0, RFC8410_PKCS8_PREFIX.length)).toEqual(RFC8410_PKCS8_PREFIX);
  });

  it("OID 1.3.101.110 appears in both encodings", async () => {
    const { publicKeyPem, privateKeyPem } = await generateX25519KeyPair();
    const oidBytes = new Uint8Array([0x06, 0x03, 0x2b, 0x65, 0x6e]);
    for (const pem of [publicKeyPem, privateKeyPem]) {
      const der = pemToDer(pem);
      let found = false;
      outer: for (let i = 0; i <= der.length - oidBytes.length; i++) {
        for (let j = 0; j < oidBytes.length; j++) {
          if (der[i + j] !== oidBytes[j]) continue outer;
        }
        found = true;
        break;
      }
      expect(found).toBe(true);
    }
  });
});

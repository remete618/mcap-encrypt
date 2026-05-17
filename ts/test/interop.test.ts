/**
 * Cross-language interop tests.
 *
 * Direction A: Go encrypts → TypeScript decrypts
 * Direction B: TypeScript encrypts → Go decrypts
 *
 * Requires Go to be installed (checks for /opt/homebrew/bin/go or PATH).
 * Tests are skipped if the Go binary is not found.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { encryptMcap, decryptMcap, rotateMcapKeys, generateX25519KeyPair } from "../src/index.js";
import { buildTestMcap, buildTestMcapWithAttachment, collectMessages, assertMessagesMatch } from "./helpers.js";
import { BinaryReader } from "../src/binary.js";

// Repo root is two levels up from ts/test/
const REPO_ROOT = resolve(fileURLToPath(import.meta.url), "../../..");

function findGo(): string | null {
  for (const candidate of ["/opt/homebrew/bin/go", "/usr/local/bin/go", "/usr/bin/go"]) {
    const result = spawnSync(candidate, ["version"], { encoding: "utf8" });
    if (result.status === 0) return candidate;
  }
  // Try from PATH
  const result = spawnSync("go", ["version"], { encoding: "utf8" });
  return result.status === 0 ? "go" : null;
}

function runGo(goBin: string, args: string[], opts?: { cwd?: string }): void {
  const result = spawnSync(goBin, args, {
    cwd: opts?.cwd ?? REPO_ROOT,
    encoding: "utf8",
    timeout: 60_000,
    env: { ...process.env, PATH: `/opt/homebrew/bin:${process.env.PATH ?? ""}` },
  });
  if (result.status !== 0) {
    throw new Error(`go ${args.join(" ")} failed:\n${result.stderr}`);
  }
}

let goBin: string | null;
let tmpDir: string;
let testMcap: Uint8Array;
let pubKeyPem: string;
let privKeyPem: string;

beforeAll(async () => {
  goBin = findGo();
  if (!goBin) return;

  tmpDir = mkdtempSync(join(tmpdir(), "mcap-interop-"));
  testMcap = buildTestMcap();

  // Generate key pair via Go CLI.
  runGo(goBin, ["run", "./cmd/mcap-encrypt", "keygen", "--out", join(tmpDir, "key")]);
  pubKeyPem = readFileSync(join(tmpDir, "key.pub.pem"), "utf8");
  privKeyPem = readFileSync(join(tmpDir, "key.priv.pem"), "utf8");

  // Write plain MCAP to disk for Go to read.
  writeFileSync(join(tmpDir, "plain.mcap"), testMcap);
}, 90_000);

afterAll(() => {
  if (tmpDir) {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

describe("interop: Go → TypeScript", () => {
  it("TypeScript decrypts a file encrypted by the Go CLI", async () => {
    if (!goBin) {
      console.warn("Go not found, skipping interop test");
      return;
    }

    // Encrypt with Go.
    runGo(goBin, [
      "run", "./cmd/mcap-encrypt",
      "encrypt", "--key", join(tmpDir, "key.pub.pem"),
      join(tmpDir, "plain.mcap"), join(tmpDir, "enc-go.mcap"),
    ]);

    // Decrypt with TypeScript.
    const encBytes = readFileSync(join(tmpDir, "enc-go.mcap"));
    const decBytes = await decryptMcap(new Uint8Array(encBytes), privKeyPem);

    const got = collectMessages(decBytes);
    const expected = collectMessages(testMcap);
    expect(got).toHaveLength(100);
    assertMessagesMatch(got, expected);
  }, 90_000);
});

describe("interop: TypeScript → Go", () => {
  it("Go CLI decrypts a file encrypted by the TypeScript library", async () => {
    if (!goBin) {
      console.warn("Go not found, skipping interop test");
      return;
    }

    // Encrypt with TypeScript.
    const encBytes = await encryptMcap(testMcap, pubKeyPem);
    writeFileSync(join(tmpDir, "enc-ts.mcap"), encBytes);

    // Decrypt with Go.
    runGo(goBin, [
      "run", "./cmd/mcap-encrypt",
      "decrypt", "--key", join(tmpDir, "key.priv.pem"),
      join(tmpDir, "enc-ts.mcap"), join(tmpDir, "dec-go.mcap"),
    ]);

    // Verify with TypeScript reader.
    const decBytes = readFileSync(join(tmpDir, "dec-go.mcap"));
    const got = collectMessages(new Uint8Array(decBytes));
    const expected = collectMessages(testMcap);
    expect(got).toHaveLength(100);
    assertMessagesMatch(got, expected);
  }, 90_000);
});

describe("interop: attachment round-trip Go → TS", () => {
  it("TypeScript decrypts attachment data encrypted by Go", async () => {
    if (!goBin) {
      console.warn("Go not found, skipping interop test");
      return;
    }

    const plainWithAtt = buildTestMcapWithAttachment();
    writeFileSync(join(tmpDir, "plain-att.mcap"), plainWithAtt);

    runGo(goBin, [
      "run", "./cmd/mcap-encrypt",
      "encrypt", "--key", join(tmpDir, "key.pub.pem"),
      join(tmpDir, "plain-att.mcap"), join(tmpDir, "enc-att-go.mcap"),
    ]);

    const encBytes = readFileSync(join(tmpDir, "enc-att-go.mcap"));
    const decBytes = await decryptMcap(new Uint8Array(encBytes), privKeyPem);

    const names = readDecryptedAttachmentNames(decBytes);
    expect(names).toContain("config.json");
    const attData = readDecryptedAttachmentData(decBytes, "config.json");
    expect(new TextDecoder().decode(attData)).toBe('{"k":"v"}');
  }, 90_000);
});

describe("interop: attachment round-trip TS → Go", () => {
  it("Go decrypts attachment data encrypted by TypeScript", async () => {
    if (!goBin) {
      console.warn("Go not found, skipping interop test");
      return;
    }

    const plainWithAtt = buildTestMcapWithAttachment();
    const encBytes = await encryptMcap(plainWithAtt, pubKeyPem);
    writeFileSync(join(tmpDir, "enc-att-ts.mcap"), encBytes);

    runGo(goBin, [
      "run", "./cmd/mcap-encrypt",
      "decrypt", "--key", join(tmpDir, "key.priv.pem"),
      join(tmpDir, "enc-att-ts.mcap"), join(tmpDir, "dec-att-go.mcap"),
    ]);

    const decBytes = readFileSync(join(tmpDir, "dec-att-go.mcap"));
    const names = readDecryptedAttachmentNames(new Uint8Array(decBytes));
    expect(names).toContain("config.json");
    const attData = readDecryptedAttachmentData(new Uint8Array(decBytes), "config.json");
    expect(new TextDecoder().decode(attData)).toBe('{"k":"v"}');
  }, 90_000);
});

describe("interop X25519: Go → TypeScript", () => {
  it("TypeScript decrypts a file encrypted by Go with an X25519 key", async () => {
    if (!goBin) {
      console.warn("Go not found, skipping interop test");
      return;
    }

    // Generate X25519 key pair in TypeScript, write to disk for Go CLI.
    const x25519Keys = await generateX25519KeyPair();
    const x25519PubPath = join(tmpDir, "x25519-go.pub.pem");
    const x25519PrivPath = join(tmpDir, "x25519-go.priv.pem");
    writeFileSync(x25519PubPath, x25519Keys.publicKeyPem);
    writeFileSync(x25519PrivPath, x25519Keys.privateKeyPem);

    runGo(goBin, [
      "run", "./cmd/mcap-encrypt",
      "encrypt", "--key", x25519PubPath,
      join(tmpDir, "plain.mcap"), join(tmpDir, "enc-go-x25519.mcap"),
    ]);

    const encBytes = readFileSync(join(tmpDir, "enc-go-x25519.mcap"));
    const decBytes = await decryptMcap(new Uint8Array(encBytes), x25519Keys.privateKeyPem);

    const got = collectMessages(decBytes);
    const expected = collectMessages(testMcap);
    expect(got).toHaveLength(100);
    assertMessagesMatch(got, expected);
  }, 90_000);
});

describe("interop X25519: TypeScript → Go", () => {
  it("Go CLI decrypts a file encrypted by TypeScript with an X25519 key", async () => {
    if (!goBin) {
      console.warn("Go not found, skipping interop test");
      return;
    }

    // Generate X25519 key pair in TypeScript, write to disk for Go CLI.
    const x25519Keys = await generateX25519KeyPair();
    const x25519PubPath = join(tmpDir, "x25519-ts.pub.pem");
    const x25519PrivPath = join(tmpDir, "x25519-ts.priv.pem");
    writeFileSync(x25519PubPath, x25519Keys.publicKeyPem);
    writeFileSync(x25519PrivPath, x25519Keys.privateKeyPem);

    const encBytes = await encryptMcap(testMcap, x25519Keys.publicKeyPem);
    writeFileSync(join(tmpDir, "enc-ts-x25519.mcap"), encBytes);

    runGo(goBin, [
      "run", "./cmd/mcap-encrypt",
      "decrypt", "--key", x25519PrivPath,
      join(tmpDir, "enc-ts-x25519.mcap"), join(tmpDir, "dec-go-x25519.mcap"),
    ]);

    const decBytes = readFileSync(join(tmpDir, "dec-go-x25519.mcap"));
    const got = collectMessages(new Uint8Array(decBytes));
    const expected = collectMessages(testMcap);
    expect(got).toHaveLength(100);
    assertMessagesMatch(got, expected);
  }, 90_000);
});

describe("interop rotate: Go rotates → TypeScript decrypts", () => {
  it("TypeScript decrypts a file whose keys were rotated by the Go CLI", async () => {
    if (!goBin) {
      console.warn("Go not found, skipping interop test");
      return;
    }

    // Key A: used for initial encryption (generated by Go CLI).
    // Key B: new recipient after rotation (generated by TypeScript).
    const keyB = await generateX25519KeyPair();
    const keyBPubPath = join(tmpDir, "rotate-keyB.pub.pem");
    const keyBPrivPath = join(tmpDir, "rotate-keyB.priv.pem");
    writeFileSync(keyBPubPath, keyB.publicKeyPem);
    writeFileSync(keyBPrivPath, keyB.privateKeyPem);

    // Go encrypts plain.mcap with key A (the RSA key generated in beforeAll).
    runGo(goBin, [
      "run", "./cmd/mcap-encrypt",
      "encrypt", "--key", join(tmpDir, "key.pub.pem"),
      join(tmpDir, "plain.mcap"), join(tmpDir, "enc-rotate-go.mcap"),
    ]);

    // Go rotates from key A to key B.
    runGo(goBin, [
      "run", "./cmd/mcap-encrypt",
      "rotate",
      "--old-key", join(tmpDir, "key.priv.pem"),
      "--new-key", keyBPubPath,
      join(tmpDir, "enc-rotate-go.mcap"), join(tmpDir, "rotated-go.mcap"),
    ]);

    // TypeScript decrypts with key B.
    const rotatedBytes = readFileSync(join(tmpDir, "rotated-go.mcap"));
    const decBytes = await decryptMcap(new Uint8Array(rotatedBytes), keyB.privateKeyPem);

    const got = collectMessages(decBytes);
    const expected = collectMessages(testMcap);
    expect(got).toHaveLength(100);
    assertMessagesMatch(got, expected);
  }, 90_000);
});

describe("interop rotate: TypeScript rotates → Go decrypts", () => {
  it("Go CLI decrypts a file whose keys were rotated by the TypeScript library", async () => {
    if (!goBin) {
      console.warn("Go not found, skipping interop test");
      return;
    }

    // Key A: the RSA key generated in beforeAll (used for initial encryption by TypeScript).
    // Key B: new X25519 recipient generated by TypeScript.
    const keyB = await generateX25519KeyPair();
    const keyBPubPath = join(tmpDir, "rotate-ts-keyB.pub.pem");
    const keyBPrivPath = join(tmpDir, "rotate-ts-keyB.priv.pem");
    writeFileSync(keyBPubPath, keyB.publicKeyPem);
    writeFileSync(keyBPrivPath, keyB.privateKeyPem);

    // TypeScript encrypts with key A.
    const encBytes = await encryptMcap(testMcap, pubKeyPem);
    // TypeScript rotates from key A to key B.
    const rotatedBytes = await rotateMcapKeys(encBytes, privKeyPem, keyB.publicKeyPem);
    writeFileSync(join(tmpDir, "rotated-ts.mcap"), rotatedBytes);

    // Go decrypts with key B.
    runGo(goBin, [
      "run", "./cmd/mcap-encrypt",
      "decrypt", "--key", keyBPrivPath,
      join(tmpDir, "rotated-ts.mcap"), join(tmpDir, "dec-rotated-ts.mcap"),
    ]);

    const decBytes = readFileSync(join(tmpDir, "dec-rotated-ts.mcap"));
    const got = collectMessages(new Uint8Array(decBytes));
    const expected = collectMessages(testMcap);
    expect(got).toHaveLength(100);
    assertMessagesMatch(got, expected);
  }, 90_000);
});

// Scan a standard (decrypted) MCAP for plaintext Attachment (0x09) record names.
function readDecryptedAttachmentNames(mcap: Uint8Array): string[] {
  const view = new DataView(mcap.buffer, mcap.byteOffset);
  const names: string[] = [];
  let pos = 8;
  while (pos + 9 <= mcap.length) {
    const opcode = mcap[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    if (opcode === 0x09) {
      const r = new BinaryReader(mcap.slice(pos + 9, pos + 9 + length));
      r.readUint64(); r.readUint64(); // log_time, create_time
      names.push(r.readString());
    }
    pos += 9 + length;
  }
  return names;
}

// Returns the data bytes of a named attachment from a standard (decrypted) MCAP.
function readDecryptedAttachmentData(mcap: Uint8Array, targetName: string): Uint8Array {
  const view = new DataView(mcap.buffer, mcap.byteOffset);
  let pos = 8;
  while (pos + 9 <= mcap.length) {
    const opcode = mcap[pos]!;
    const length = Number(view.getBigUint64(pos + 1, true));
    if (opcode === 0x09) {
      const r = new BinaryReader(mcap.slice(pos + 9, pos + 9 + length));
      r.readUint64(); r.readUint64(); // log_time, create_time
      const name = r.readString();
      r.readString(); // media_type
      const dataSize = Number(r.readUint64());
      const data = new Uint8Array(r.readBytes(dataSize));
      if (name === targetName) return data;
    }
    pos += 9 + length;
  }
  throw new Error(`attachment "${targetName}" not found in decrypted MCAP`);
}

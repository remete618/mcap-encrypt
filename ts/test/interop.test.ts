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
import { encryptMcap, decryptMcap } from "../src/index.js";
import { buildTestMcap, collectMessages, assertMessagesMatch } from "./helpers.js";

// Repo root is two levels up from ts/test/
const REPO_ROOT = resolve(fileURLToPath(import.meta.url), "../../..");

function findGo(): string | null {
  for (const candidate of ["/opt/homebrew/bin/go", "/usr/local/bin/go", "/usr/bin/go"]) {
    const result = spawnSync(candidate, ["version"], { encoding: "utf8" });
    if (result.status === 0) return candidate;
  }
  // Try from PATH
  const result = spawnSync("go", ["version"], { encoding: "utf8", shell: true });
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

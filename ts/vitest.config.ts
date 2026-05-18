import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // RSA-4096 keygen + encrypt + decrypt takes 5-15 s per operation on CI.
    // The default 5000 ms timeout is too short for multi-recipient tests.
    testTimeout: 30000,
  },
});

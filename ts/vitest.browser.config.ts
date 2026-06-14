import { defineConfig } from "vitest/config";
import { playwright } from "@vitest/browser-playwright";

// Browser-mode config used only by `npm run test:browser`. Keeps the regular
// `npm test` config untouched so Node-mode tests don't try to launch chromium.
export default defineConfig({
  test: {
    testTimeout: 30000,
    include: ["test/browser.test.ts"],
    browser: {
      enabled: true,
      provider: playwright(),
      headless: true,
      instances: [{ browser: "chromium" }],
    },
  },
});

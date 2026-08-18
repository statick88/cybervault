import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  retries: 1,
  use: {
    headless: true,
  },
  projects: [
    {
      name: "chrome-extension",
      use: {
        browserName: "chromium",
      },
    },
  ],
});

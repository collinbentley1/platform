import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./test/browser", testMatch: process.env.PLATFORM_TEST_ORIGIN ? "live.spec.ts" : "application.spec.ts", workers: 1, retries: process.env.CI ? 1 : 0,
  use: { baseURL: process.env.PLATFORM_TEST_ORIGIN ?? "http://127.0.0.1:8089", trace: process.env.PLATFORM_TEST_ORIGIN ? "off" : "retain-on-failure" },
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : "list",
  ...(!process.env.PLATFORM_TEST_ORIGIN ? { webServer: { command: "bun tools/test-app.ts", url: "http://127.0.0.1:8089/livez", timeout: 180_000 } } : {}),
});

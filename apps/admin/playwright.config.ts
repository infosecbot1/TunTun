import {defineConfig, devices} from "@playwright/test";

export default defineConfig({
  testDir: "../../tests",
  testMatch: ["**/e2e/**/*.spec.ts", "**/ui/**/*.spec.ts", "**/performance/ui/**/*.spec.ts"],
  testIgnore: [
    "**/e2e/ui/subject-*.spec.ts",
    "**/ui/subject-*.spec.ts",
    "**/ui/display-*.spec.ts",
    "**/ui/e2e/display-agent-*.spec.ts",
  ],
  fullyParallel: false,
  workers: 1,
  retries: 0,
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
  },
  webServer: {
    command: "pnpm run dev",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: false,
    timeout: 120_000,
  },
  projects: [{name: "chromium", use: {...devices["Desktop Chrome"]}}],
});

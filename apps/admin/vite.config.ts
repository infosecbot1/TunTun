import react from "@vitejs/plugin-react";
import {defineConfig} from "vitest/config";
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
    include: [
      "src/**/*.{test,spec}.{ts,tsx}",
      "../../tests/unit/admin/**/*.{test,spec}.{ts,tsx}",
      "../../tests/ui/**/*.spec.tsx",
    ],
    exclude: ["../../tests/e2e/**", "../../tests/ui/e2e/**"],
  },
});

import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {basePath: "../..", ignores: ["apps/admin/dist", "apps/admin/playwright-report", "apps/admin/test-results"]},
  {...js.configs.recommended, basePath: "../.."},
  ...tseslint.configs.recommended.map((config) => ({...config, basePath: "../.."})),
  {
    basePath: "../..",
    files: [
      "apps/admin/**/*.{ts,tsx}",
      "tests/unit/admin/**/*.{ts,tsx}",
      "tests/e2e/**/*.{ts,tsx}",
      "tests/ui/**/*.{ts,tsx}",
    ],
    languageOptions: {ecmaVersion: 2022, globals: {...globals.browser, ...globals.node}},
    plugins: {"react-hooks": reactHooks, "react-refresh": reactRefresh},
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["error", {allowConstantExport: true}],
    },
  },
);

import { configDefaults, defineConfig } from "vitest/config";

// Unit tests only (no browser, no Vite plugins); the app build uses vite.config.ts.
export default defineConfig({
  test: { environment: "node", exclude: [...configDefaults.exclude, "**/dist/**"] },
});

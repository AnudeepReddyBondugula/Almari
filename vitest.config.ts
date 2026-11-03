import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      // Same "@/..." shortcut the Next.js app uses (see tsconfig.json).
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      // "server-only" deliberately throws outside the Next.js server. Tests run
      // server code directly, so swap it for an empty file here.
      "server-only": fileURLToPath(new URL("./test/server-only-stub.ts", import.meta.url)),
    },
  },
  test: {
    // Argon2id is slow on purpose (~1 s per run, 64 MB each). Some tests run it several
    // times while other test files run in parallel, so allow well over the 5 s default.
    testTimeout: 30_000,
    env: {
      // Fake values so env() validation passes in tests. Never real secrets.
      GOOGLE_CLIENT_ID: "test",
      GOOGLE_CLIENT_SECRET: "test",
      GOOGLE_REFRESH_TOKEN: "test",
      SESSION_SECRET: "test-secret-that-is-at-least-32-characters-long",
    },
  },
});
import { defineConfig } from "tsup";

export default defineConfig({
  entry: { index: "server/index.ts", "migrate-auth": "scripts/migrate-auth.ts" },
  tsconfig: "tsconfig.sdk.json",
  format: ["esm"],
  platform: "node",
  outDir: "dist/api",
  clean: true,
});

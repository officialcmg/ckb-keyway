import type { NextConfig } from "next";
import { resolve } from "node:path";

const nextConfig: NextConfig = {
  env: { KEYWAY_STAGING_FRONTEND: process.env.KEYWAY_STAGING_BUILD === "1" ? "1" : "0" },
  ...(process.env.KEYWAY_STAGING_BUILD === "1" ? {
    turbopack: { resolveAlias: { "@ckb-keyway/react": "./dist/react-staging/index.js" } },
    webpack: (config: { resolve: { alias: Record<string, string> } }) => {
      config.resolve.alias["@ckb-keyway/react"] = resolve("dist/react-staging/index.js");
      return config;
    },
  } : {}),
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
          { key: "Cross-Origin-Embedder-Policy", value: "require-corp" },
        ],
      },
    ];
  },
};

export default nextConfig;

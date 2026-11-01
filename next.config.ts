import type { NextConfig } from "next";
import { resolve } from "node:path";

const nextConfig: NextConfig = {
  env: { KEYWAY_STAGING_FRONTEND: process.env.KEYWAY_STAGING_BUILD === "1" ? "1" : "0" },
  ...(process.env.KEYWAY_STAGING_BUILD === "1" || process.env.KEYWAY_LOCAL_SDK === "1" ? {
    turbopack: { resolveAlias: { "@ckb-keyway/react": process.env.KEYWAY_STAGING_BUILD === "1" ? "./dist/react-staging/index.js" : "./dist/react/index.js" } },
    webpack: (config: { resolve: { alias: Record<string, string> } }) => {
      config.resolve.alias["@ckb-keyway/react"] = resolve(process.env.KEYWAY_STAGING_BUILD === "1" ? "dist/react-staging/index.js" : "dist/react/index.js");
      return config;
    },
  } : {}),
  // The Content-Security-Policy comes from proxy.ts, which issues a script nonce per request.
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
          { key: "Cross-Origin-Embedder-Policy", value: "require-corp" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()" },
        ],
      },
      {
        // JoyID signs in a popup that answers through window.opener, which same-origin isolation cuts off. The
        // rescue page runs no Fiber node, so it doesn't need cross-origin isolation.
        source: "/rescue",
        headers: [
          { key: "Cross-Origin-Opener-Policy", value: "same-origin-allow-popups" },
          { key: "Cross-Origin-Embedder-Policy", value: "unsafe-none" },
        ],
      },
    ];
  },
};

export default nextConfig;

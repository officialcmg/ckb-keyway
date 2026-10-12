import type { NextConfig } from "next";
import { resolve } from "node:path";

/**
 * Inline scripts stay allowed because Next.js streams inline bootstrap scripts without nonces here;
 * everything else is locked down. The wallet talks to the KeyWay API, CKB RPCs and Fiber peers over
 * HTTPS and WSS, and the in-browser Fiber node needs WebAssembly and blob workers.
 */
const contentSecurityPolicy = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'${process.env.NODE_ENV === "production" ? "" : " 'unsafe-eval'"}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self'",
  "connect-src 'self' https: wss:",
  "worker-src 'self' blob:",
  "frame-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const nextConfig: NextConfig = {
  env: { KEYWAY_STAGING_FRONTEND: process.env.KEYWAY_STAGING_BUILD === "1" ? "1" : "0" },
  ...(process.env.KEYWAY_STAGING_BUILD === "1" || process.env.KEYWAY_LOCAL_SDK === "1" ? {
    turbopack: { resolveAlias: { "@ckb-keyway/react": process.env.KEYWAY_STAGING_BUILD === "1" ? "./dist/react-staging/index.js" : "./dist/react/index.js" } },
    webpack: (config: { resolve: { alias: Record<string, string> } }) => {
      config.resolve.alias["@ckb-keyway/react"] = resolve(process.env.KEYWAY_STAGING_BUILD === "1" ? "dist/react-staging/index.js" : "dist/react/index.js");
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
          { key: "Content-Security-Policy", value: contentSecurityPolicy },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()" },
        ],
      },
    ];
  },
};

export default nextConfig;

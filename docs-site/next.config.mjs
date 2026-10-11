import { fileURLToPath } from 'node:url';
import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX();

/** @type {import('next').NextConfig} */
const config = {
  reactStrictMode: true,
  // The docs are their own app inside the KeyWay repository; keep Next.js from
  // treating the repository root (which has its own lockfile) as the workspace.
  turbopack: {
    root: fileURLToPath(new URL('.', import.meta.url)),
  },
};

export default withMDX(config);

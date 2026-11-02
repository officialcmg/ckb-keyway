"use client";

import dynamic from "next/dynamic";

// Loaded only outside production, so the gallery and its fixtures never reach the deployed site.
const Gallery = process.env.NODE_ENV !== "production"
  ? dynamic(() => import("./gallery").then((module) => module.Gallery), { ssr: false })
  : () => null;

export function ModalGallery({ scene, theme }: { scene?: string; theme: "light" | "dark" }) {
  return <Gallery scene={scene} theme={theme} />;
}

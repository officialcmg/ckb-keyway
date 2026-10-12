import type { Metadata, Viewport } from "next";
import { Albert_Sans, IBM_Plex_Mono } from "next/font/google";
import { connection } from "next/server";
import type { ReactNode } from "react";
import "./styles.css";

const sans = Albert_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700", "800"],
  variable: "--font-sans",
  display: "swap",
});

const mono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "CKB KeyWay",
  description: "Embedded wallets for CKB. Email sign-in, CKB accounts and Fiber payments for your app.",
};

export const viewport: Viewport = {
  themeColor: "#F7F5EB",
};

export default async function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  // Every page renders per request, so Next.js can stamp it with the nonce from proxy.ts.
  await connection();
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body>{children}</body>
    </html>
  );
}

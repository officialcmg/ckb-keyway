import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./styles.css";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "CKB KeyWay",
  description: "Email-authenticated wallet infrastructure for Fiber Network",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body><Providers>{children}</Providers></body>
    </html>
  );
}

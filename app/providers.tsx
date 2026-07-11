"use client";

import { createStytchClient, StytchProvider } from "@stytch/nextjs";
import type { ReactNode } from "react";

const publicToken = process.env.NEXT_PUBLIC_STYTCH_PUBLIC_TOKEN;
const stytch = publicToken ? createStytchClient(publicToken) : null;

export function Providers({ children }: { children: ReactNode }) {
  if (!stytch) return <p>Missing Stytch public token.</p>;
  return <StytchProvider stytch={stytch}>{children}</StytchProvider>;
}

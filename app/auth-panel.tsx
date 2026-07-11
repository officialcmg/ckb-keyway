"use client";

import { Products, StytchLogin, useStytch, useStytchSession, useStytchUser } from "@stytch/nextjs";
import { useState } from "react";

const config = {
  products: [Products.otp],
  otpOptions: { methods: ["email" as const], expirationMinutes: 10 },
  sessionOptions: { sessionDurationMinutes: 60 },
};

export function AuthPanel() {
  const stytch = useStytch();
  const { session, isInitialized } = useStytchSession();
  const { user } = useStytchUser();
  const [verifiedUserId, setVerifiedUserId] = useState<string>();
  const [error, setError] = useState<string>();

  if (!isInitialized) return <p className="status">Loading authentication...</p>;
  if (!session || !user) {
    return <section className="auth"><StytchLogin config={config} /></section>;
  }

  async function verifyBackendSession() {
    setError(undefined);
    const jwt = stytch.session.getTokens()?.session_jwt;
    const response = await fetch("/api/session", { headers: { Authorization: `Bearer ${jwt}` } });
    const body = await response.json();
    if (!response.ok) return setError(body.error ?? "Session verification failed");
    setVerifiedUserId(body.userId);
  }

  return (
    <section className="auth signed-in">
      <p className="status"><span /> Email identity recovered</p>
      <button onClick={verifyBackendSession}>Verify backend session</button>
      <button className="quiet" onClick={() => stytch.session.revoke()}>Log out</button>
      {verifiedUserId && <code>{verifiedUserId}</code>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}

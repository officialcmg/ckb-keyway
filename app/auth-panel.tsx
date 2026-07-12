"use client";

import { Products, StytchLogin, useStytch, useStytchSession, useStytchUser } from "@stytch/nextjs";
import { useRef, useState } from "react";
import {
  bootstrapKeyWay,
  createKeyWay,
  loadFiberKey,
  type KeyWay,
  type PublicWallet,
} from "@/src/sdk/browser";

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
  const [wallet, setWallet] = useState<PublicWallet>();
  const [nodeStatus, setNodeStatus] = useState<string>();
  const [nodePubkey, setNodePubkey] = useState<string>();
  const [error, setError] = useState<string>();
  const keyway = useRef<KeyWay | undefined>(undefined);

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

  async function initializeWallet() {
    setError(undefined);
    const jwt = stytch.session.getTokens()?.session_jwt;
    if (!jwt) return setError("No active Stytch session");
    try {
      setWallet((await bootstrapKeyWay(jwt)).wallet);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Wallet initialization failed");
    }
  }

  async function startNode() {
    setError(undefined);
    const jwt = stytch.session.getTokens()?.session_jwt;
    if (!jwt || !wallet) return setError("Initialize KeyWay first");

    setNodeStatus("Starting Fiber node...");
    try {
      keyway.current ??= createKeyWay({
        identifier: wallet.litPkpId,
        sessionJwt: jwt,
        loadFiberKey: (leaseId) => loadFiberKey(jwt, leaseId),
      });
      const info = await keyway.current.start();
      setNodePubkey(info.pubkey);
      setNodeStatus(`Fiber node running with ${Number.parseInt(info.peers_count, 16)} peer(s)`);
    } catch (cause) {
      setNodeStatus(undefined);
      setError(cause instanceof Error ? cause.message : "Fiber node failed to start");
    }
  }

  async function stopNode() {
    setError(undefined);
    try {
      await keyway.current?.stop();
      keyway.current = undefined;
      setNodePubkey(undefined);
      setNodeStatus("Fiber node stopped");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Fiber node failed to stop");
    }
  }

  async function logOut() {
    await keyway.current?.stop();
    keyway.current = undefined;
    await stytch.session.revoke();
  }

  return (
    <section className="auth signed-in">
      <p className="status"><span /> Email identity recovered</p>
      <button onClick={verifyBackendSession}>Verify backend session</button>
      <button onClick={initializeWallet}>Initialize KeyWay</button>
      <button onClick={startNode} disabled={!wallet}>Start Fiber</button>
      <button className="quiet" onClick={stopNode} disabled={!keyway.current?.isRunning}>Stop Fiber</button>
      <button className="quiet" onClick={logOut}>Log out</button>
      {verifiedUserId && <code>{verifiedUserId}</code>}
      {wallet && <code>{wallet.ckbAddress}</code>}
      {nodeStatus && <p className="node-status">{nodeStatus}</p>}
      {nodePubkey && <code>{nodePubkey}</code>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}

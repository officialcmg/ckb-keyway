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

const TESTNET_RELAYS = [
  "/dns4/thrall.fiber.channel/tcp/443/wss/p2p/Qmes1EBD4yNo9Ywkfe6eRw9tG1nVNGLDmMud1xJMsoYFKy",
  "/dns4/onyxia.fiber.channel/tcp/443/wss/p2p/QmdyQWjPtbK4NWWsvy8s69NGJaQULwgeQDT5ZpNDrTNaeV",
];

export function AuthPanel() {
  const stytch = useStytch();
  const { session, isInitialized } = useStytchSession();
  const { user } = useStytchUser();
  const [verifiedUserId, setVerifiedUserId] = useState<string>();
  const [wallet, setWallet] = useState<PublicWallet>();
  const [nodeStatus, setNodeStatus] = useState<string>();
  const [nodePubkey, setNodePubkey] = useState<string>();
  const [peerPubkey, setPeerPubkey] = useState("");
  const [fundingCkb, setFundingCkb] = useState("100");
  const [fundingResult, setFundingResult] = useState<string>();
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
        ckbPublicKey: wallet.litPublicKey,
        confirmFunding: (preview) => window.confirm(
          `Open a ${preview.amountCkb} CKB Fiber channel?\n\n` +
          `Fee: ${preview.feeCkb} CKB\nDestination: ${preview.destination}`,
        ),
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

  async function openChannel() {
    setError(undefined);
    setFundingResult(undefined);
    if (!keyway.current?.isRunning) return setError("Start the Fiber node first");
    if (!/^0x[0-9a-fA-F]{66}$/.test(peerPubkey)) return setError("Peer public key must be 33-byte hex");
    try {
      const fundingAmount = parseCkb(fundingCkb);
      const result = await keyway.current.openFundedChannel({
        pubkey: peerPubkey as `0x${string}`,
        funding_amount: `0x${fundingAmount.toString(16)}`,
        public: true,
      });
      setFundingResult(`Channel ${result.channelId} funded by ${result.fundingTxHash}`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Channel funding failed");
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

  async function connectRelay() {
    setError(undefined);
    if (!keyway.current?.isRunning) return setError("Start the Fiber node first");
    for (const address of TESTNET_RELAYS) {
      try {
        await keyway.current.connectPeer({ address, save: true });
        const { peers } = await keyway.current.listPeers();
        const peer = peers[0];
        if (!peer) continue;
        setPeerPubkey(peer.pubkey);
        setNodeStatus(`Fiber node connected to ${peers.length} peer(s)`);
        return;
      } catch {
        // Try the next public testnet relay.
      }
    }
    setError("Could not connect to a public Fiber testnet relay");
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
      {nodePubkey && (
        <div className="funding-controls">
          <button className="quiet" onClick={connectRelay}>Connect testnet relay</button>
          <label>Peer public key<input value={peerPubkey} onChange={(event) => setPeerPubkey(event.target.value)} /></label>
          <label>Funding (CKB)<input value={fundingCkb} onChange={(event) => setFundingCkb(event.target.value)} /></label>
          <button onClick={openChannel}>Open funded channel</button>
        </div>
      )}
      {fundingResult && <code>{fundingResult}</code>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}

function parseCkb(value: string): bigint {
  const match = /^(\d{1,4})(?:\.(\d{1,8}))?$/.exec(value.trim());
  if (!match) throw new Error("Funding amount must use at most 8 decimal places");
  const shannons = BigInt(match[1]) * 100_000_000n + BigInt((match[2] ?? "").padEnd(8, "0") || "0");
  if (shannons <= 0n || shannons > 100_000_000_000n) {
    throw new Error("Funding amount must be between 0 and 1000 CKB");
  }
  return shannons;
}

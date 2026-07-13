"use client";

import { Products, StytchLogin, useStytch, useStytchSession, useStytchUser } from "@stytch/nextjs";
import { useEffect, useRef, useState } from "react";
import {
  connectKeyWay,
  formatFiberOutpoint,
  friendlyKeyWayError,
  type ConnectedKeyWay,
  type FundingPreview,
  type ActivationStage,
} from "@/src/sdk/browser";

const authConfig = {
  products: [Products.otp],
  otpOptions: { methods: ["email" as const], expirationMinutes: 10 },
  sessionOptions: { sessionDurationMinutes: 60 },
};

type Phase = "recovering" | "ready" | "activating" | "paying" | "receiving" | "error";

export function AuthPanel() {
  const stytch = useStytch();
  const { session, isInitialized } = useStytchSession();
  const { user } = useStytchUser();
  const connection = useRef<ConnectedKeyWay | undefined>(undefined);
  const connectionRun = useRef(0);
  const confirmation = useRef<((approved: boolean) => void) | undefined>(undefined);
  const [phase, setPhase] = useState<Phase>("recovering");
  const [connected, setConnected] = useState<ConnectedKeyWay>();
  const [channelReady, setChannelReady] = useState(false);
  const [channelEvidence, setChannelEvidence] = useState<{ channelId: string; fundingOutpoint: string }>();
  const [fundingPreview, setFundingPreview] = useState<FundingPreview>();
  const [fundingResult, setFundingResult] = useState<string>();
  const [activationStage, setActivationStage] = useState<ActivationStage>();
  const [invoiceToPay, setInvoiceToPay] = useState("");
  const [paymentPreview, setPaymentPreview] = useState<{ amountCkb: string }>();
  const [paymentResult, setPaymentResult] = useState<string>();
  const [receiveCkb, setReceiveCkb] = useState("1");
  const [receiveDescription, setReceiveDescription] = useState("CKB KeyWay payment");
  const [createdInvoice, setCreatedInvoice] = useState<string>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    if (!session || !user) return;
    void beginConnection();
    return () => {
      connectionRun.current += 1;
      confirmation.current?.(false);
      void connection.current?.keyway.stop();
      connection.current = undefined;
    };
  }, [session?.session_id, user?.user_id]);

  async function beginConnection() {
    const jwt = stytch.session.getTokens()?.session_jwt;
    if (!jwt) return;
    const run = ++connectionRun.current;
    setPhase("recovering");
    setError(undefined);
    try {
      const next = await connectKeyWay({
        sessionJwt: jwt,
        confirmFunding: (preview) => new Promise<boolean>((resolve) => {
          confirmation.current = resolve;
          setFundingPreview(preview);
        }),
      });
      if (run !== connectionRun.current) return void next.keyway.stop();
      const { channels } = await next.keyway.listChannels({ include_closed: false });
      const readyChannel = channels.find(({ state }) => state.state_name === "CHANNEL_READY");
      connection.current = next;
      setConnected(next);
      setChannelReady(Boolean(readyChannel));
      setChannelEvidence(readyChannel ? {
        channelId: readyChannel.channel_id,
        fundingOutpoint: formatFiberOutpoint(readyChannel.channel_outpoint),
      } : undefined);
      setPhase("ready");
      if (!readyChannel) void next.keyway.prepareCkbChannel(parseCkb("1000")).catch(() => undefined);
    } catch (cause) {
      if (run !== connectionRun.current) return;
      setPhase("error");
      setError(cause instanceof Error ? cause.message : "KeyWay recovery failed");
    }
  }

  function answerFundingConfirmation(approved: boolean) {
    confirmation.current?.(approved);
    confirmation.current = undefined;
    setFundingPreview(undefined);
  }

  async function activatePayments() {
    const current = connection.current;
    if (!current) return;
    setPhase("activating");
    setActivationStage("connecting");
    setError(undefined);
    try {
      const result = await current.keyway.activateCkbChannel(parseCkb("1000"), setActivationStage);
      setFundingResult(result.fundingTxHash);
      setActivationStage("waiting");
      await current.keyway.waitForChannelReady(result.channelId, { timeout: 180_000, interval: 3_000 });
      const { channels } = await current.keyway.listChannels({ include_closed: false });
      const readyChannel = channels.find(({ channel_id }) => channel_id === result.channelId);
      setChannelReady(true);
      setChannelEvidence({
        channelId: result.channelId,
        fundingOutpoint: formatFiberOutpoint(readyChannel?.channel_outpoint ?? null, result.fundingTxHash),
      });
      setPhase("ready");
      setActivationStage(undefined);
    } catch (cause) {
      setPhase("ready");
      setActivationStage(undefined);
      setError(cause instanceof Error ? cause.message : "Fiber activation failed");
    }
  }

  async function reviewPayment() {
    const current = connection.current;
    if (!current || !invoiceToPay.trim()) return;
    setError(undefined);
    try {
      const { invoice } = await current.keyway.parseInvoice({ invoice: invoiceToPay.trim() });
      if (!invoice.amount) throw new Error("Enter an invoice with a fixed amount");
      setPaymentPreview({ amountCkb: formatCkb(BigInt(invoice.amount)) });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Invoice could not be read");
    }
  }

  async function confirmPayment() {
    const current = connection.current;
    if (!current || !invoiceToPay.trim()) return;
    setPaymentPreview(undefined);
    setPhase("paying");
    setError(undefined);
    setPaymentResult(undefined);
    try {
      const payment = await current.keyway.sendPayment({
        invoice: invoiceToPay.trim(),
        timeout: "0x1d4c0",
        max_fee_amount: toHex(parseCkb("1")),
      });
      const settled = await current.keyway.waitForPayment(payment.payment_hash, { timeout: 120_000 });
      if (settled.status !== "Success") throw new Error(settled.failed_error ?? "Fiber payment failed");
      setPaymentResult(`Payment ${settled.payment_hash} settled`);
      setInvoiceToPay("");
      setPhase("ready");
    } catch (cause) {
      setPhase("ready");
      setError(cause instanceof Error ? cause.message : "Fiber payment failed");
    }
  }

  async function createInvoice() {
    const current = connection.current;
    if (!current) return;
    setPhase("receiving");
    setError(undefined);
    try {
      const result = await current.keyway.newInvoice({
        amount: toHex(parseCkb(receiveCkb)),
        currency: "Fibt",
        description: receiveDescription.trim() || undefined,
        expiry: "0x36ee80",
      });
      setCreatedInvoice(result.invoice_address);
      setPhase("ready");
    } catch (cause) {
      setPhase("ready");
      setError(cause instanceof Error ? cause.message : "Invoice creation failed");
    }
  }

  async function logOut() {
    connectionRun.current += 1;
    await connection.current?.keyway.stop();
    connection.current = undefined;
    await stytch.session.revoke();
  }

  if (!isInitialized) return <WalletProgress label="Loading secure email login" />;
  if (!session || !user) return <section className="auth"><StytchLogin config={authConfig} /></section>;
  if (!connected) {
    return (
      <section className="wallet-shell">
        <WalletProgress label={phase === "error" ? "Wallet needs attention" : "Recovering your wallet"} />
        {error && <p className="error">{friendlyError(error)}</p>}
        {phase === "error" && <button onClick={beginConnection}>Try again</button>}
        <button className="text-button" onClick={logOut}>Use another email</button>
      </section>
    );
  }

  const balanceCkb = formatCkb(connected.balanceShannons);
  const busy = phase !== "ready" && phase !== "error";

  return (
    <section className="wallet-shell">
      <header className="wallet-header">
        <div>
          <p className="status"><span /> Wallet ready</p>
          <p className="address" title={connected.wallet.ckbAddress}>{shorten(connected.wallet.ckbAddress)}</p>
        </div>
        <button className="text-button" onClick={logOut}>Log out</button>
      </header>

      <div className="balance-card">
        <span>Testnet balance</span>
        <strong>{balanceCkb} CKB</strong>
        <a href={`https://faucet.nervos.org/?address=${connected.wallet.ckbAddress}`} target="_blank" rel="noreferrer">
          Add testnet CKB
        </a>
      </div>

      {!channelReady ? (
        <section className="activation-card">
          <p className="step-label">One-time setup</p>
          <h2>Activate instant payments</h2>
          <p>Lock 1,000 testnet CKB in your Fiber channel. You still own it, and normal payments happen off-chain.</p>
          <button onClick={activatePayments} disabled={busy || connected.balanceShannons < parseCkb("1100")}>
            {phase === "activating" ? activationLabel(activationStage) : "Activate Fiber payments"}
          </button>
          {phase === "activating" && activationStage && <p className="hint" role="status">{activationDetail(activationStage)}</p>}
          {connected.balanceShannons < parseCkb("1100") && <p className="hint">Add testnet CKB before activating.</p>}
          {fundingResult && <p className="hint">Funding submitted: {shorten(fundingResult)}</p>}
        </section>
      ) : (
        <div className="payment-grid">
          <section className="payment-card">
            <p className="step-label">Send</p>
            <h2>Pay an invoice</h2>
            <textarea value={invoiceToPay} onChange={(event) => setInvoiceToPay(event.target.value)} placeholder="Paste a Fiber invoice" />
            <button onClick={reviewPayment} disabled={busy || !invoiceToPay.trim()}>
              {phase === "paying" ? "Paying..." : "Review payment"}
            </button>
          </section>

          <section className="payment-card">
            <p className="step-label">Receive</p>
            <h2>Create an invoice</h2>
            <label>Amount in CKB<input value={receiveCkb} onChange={(event) => setReceiveCkb(event.target.value)} /></label>
            <label>Note<input value={receiveDescription} onChange={(event) => setReceiveDescription(event.target.value)} /></label>
            <button onClick={createInvoice} disabled={busy}>
              {phase === "receiving" ? "Creating..." : "Create invoice"}
            </button>
          </section>
        </div>
      )}

      {createdInvoice && <OutputCard label="Invoice" value={createdInvoice} />}
      {paymentResult && <p className="success">{paymentResult}</p>}
      {error && <p className="error">{friendlyError(error)}</p>}

      <details className="diagnostics">
        <summary>Developer diagnostics</summary>
        <dl>
          <dt>CKB address</dt><dd>{connected.wallet.ckbAddress}</dd>
          <dt>Fiber node</dt><dd>{connected.node.pubkey}</dd>
          <dt>Connected peers</dt><dd>{connected.peers.length}</dd>
          {channelEvidence && <><dt>Channel ID</dt><dd>{channelEvidence.channelId}</dd></>}
          {channelEvidence && <><dt>Funding outpoint</dt><dd>{channelEvidence.fundingOutpoint}</dd></>}
          <dt>Identity storage</dt><dd>This browser</dd>
        </dl>
      </details>

      {fundingPreview && (
        <div className="modal-backdrop" role="presentation">
          <section className="confirm-sheet" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
            <p className="step-label">On-chain confirmation</p>
            <h2 id="confirm-title">Activate Fiber payments?</h2>
            <dl>
              <dt>Channel funding</dt><dd>{fundingPreview.amountCkb} CKB</dd>
              <dt>Network fee</dt><dd>{fundingPreview.feeCkb} CKB</dd>
              <dt>Network</dt><dd>CKB testnet</dd>
            </dl>
            <p className="hint">This locks testnet CKB into a payment channel. It does not send funds to another wallet.</p>
            <div className="confirm-actions">
              <button className="quiet" onClick={() => answerFundingConfirmation(false)}>Cancel</button>
              <button onClick={() => answerFundingConfirmation(true)}>Confirm activation</button>
            </div>
          </section>
        </div>
      )}

      {paymentPreview && (
        <div className="modal-backdrop" role="presentation">
          <section className="confirm-sheet" role="dialog" aria-modal="true" aria-labelledby="payment-confirm-title">
            <p className="step-label">Payment confirmation</p>
            <h2 id="payment-confirm-title">Send {paymentPreview.amountCkb} CKB?</h2>
            <dl>
              <dt>Amount</dt><dd>{paymentPreview.amountCkb} CKB</dd>
              <dt>Maximum fee</dt><dd>1 CKB</dd>
              <dt>Network</dt><dd>Fiber testnet</dd>
            </dl>
            <p className="hint">The payment moves through Fiber and does not create a separate CKB transaction.</p>
            <div className="confirm-actions">
              <button className="quiet" onClick={() => setPaymentPreview(undefined)}>Cancel</button>
              <button onClick={confirmPayment}>Confirm payment</button>
            </div>
          </section>
        </div>
      )}
    </section>
  );
}

function WalletProgress({ label }: { label: string }) {
  return <p className="status loading"><span /> {label}</p>;
}

function activationLabel(stage?: ActivationStage): string {
  if (stage === "confirming") return "Review the transaction";
  if (stage === "signing") return "Authorizing...";
  if (stage === "broadcasting") return "Submitting...";
  if (stage === "waiting") return "Confirming on CKB...";
  if (stage === "negotiating") return "Preparing transaction...";
  return "Connecting to Fiber...";
}

function activationDetail(stage: ActivationStage): string {
  if (stage === "connecting") return "Connecting to an official Fiber testnet channel provider.";
  if (stage === "negotiating") return "Fiber is agreeing the channel details and building the exact CKB transaction.";
  if (stage === "confirming") return "Review the exact funding amount and network fee.";
  if (stage === "signing") return "Lit is authorizing the transaction you approved.";
  if (stage === "waiting") return "The channel transaction was submitted. CKB testnet is confirming it now.";
  return "The signed channel transaction is being submitted to CKB testnet.";
}

function OutputCard({ label, value }: { label: string; value: string }) {
  return <section className="output-card"><span>{label}</span><code>{value}</code></section>;
}

function parseCkb(value: string): bigint {
  const match = /^(\d{1,7})(?:\.(\d{1,8}))?$/.exec(value.trim());
  if (!match) throw new Error("Enter a valid CKB amount with at most 8 decimal places");
  const result = BigInt(match[1]) * 100_000_000n + BigInt((match[2] ?? "").padEnd(8, "0") || "0");
  if (result <= 0n) throw new Error("Amount must be greater than zero");
  return result;
}

function formatCkb(shannons: bigint): string {
  const whole = shannons / 100_000_000n;
  const fraction = (shannons % 100_000_000n).toString().padStart(8, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

function toHex(value: bigint): `0x${string}` {
  return `0x${value.toString(16)}`;
}

function shorten(value: string): string {
  return value.length <= 22 ? value : `${value.slice(0, 12)}…${value.slice(-8)}`;
}

function friendlyError(value: string): string {
  return friendlyKeyWayError(value);
}

"use client";

import { useEffect, useState } from "react";
import {
  formatFiberOutpoint,
  friendlyKeyWayError,
  KeyWayProvider,
  type ActivationStage,
  type KeyWay,
  useKeyWay,
} from "@ckb-keyway/react";

type Phase = "recovering" | "ready" | "activating" | "paying" | "receiving" | "error";
type FiberChannel = Awaited<ReturnType<KeyWay["listChannels"]>>["channels"][number];

export function AuthPanel() {
  return (
    <KeyWayProvider>
      <WalletPanel />
    </KeyWayProvider>
  );
}

function WalletPanel() {
  const {
    ready,
    authenticated,
    connection: connected,
    status,
    error: connectionError,
    login,
    logout,
    connect,
  } = useKeyWay();
  const [phase, setPhase] = useState<Phase>("recovering");
  const [channelReady, setChannelReady] = useState(false);
  const [channelEvidence, setChannelEvidence] = useState<{ channelId: string; fundingOutpoint: string }>();
  const [fundingResult, setFundingResult] = useState<string>();
  const [activationStage, setActivationStage] = useState<ActivationStage>();
  const [invoiceToPay, setInvoiceToPay] = useState("");
  const [paymentPreview, setPaymentPreview] = useState<{ amountCkb: string }>();
  const [paymentResult, setPaymentResult] = useState<string>();
  const [receiveCkb, setReceiveCkb] = useState("1");
  const [receiveDescription, setReceiveDescription] = useState("CKB KeyWay payment");
  const [createdInvoice, setCreatedInvoice] = useState<string>();
  const [error, setError] = useState<string>();
  const [balanceShannons, setBalanceShannons] = useState<bigint>();
  const [channels, setChannels] = useState<FiberChannel[]>([]);

  useEffect(() => {
    if (!connected) {
      setBalanceShannons(undefined);
      setChannels([]);
      return;
    }
    let cancelled = false;
    setBalanceShannons(connected.balanceShannons);
    const refresh = async () => {
      const [balance, channelResult] = await Promise.allSettled([
        connected.keyway.getCkbBalance(),
        connected.keyway.listChannels({ include_closed: false }),
      ]);
      if (cancelled) return;
      if (balance.status === "fulfilled") setBalanceShannons(balance.value);
      if (channelResult.status === "fulfilled") setChannels(channelResult.value.channels);
    };
    void refresh();
    const interval = window.setInterval(refresh, 10_000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [connected]);

  useEffect(() => {
    if (!connected) return;
    let cancelled = false;
    setPhase("recovering");
    setError(undefined);
    void connected.keyway.listChannels({ include_closed: false }).then(({ channels }) => {
      if (cancelled) return;
      const readyChannel = channels.find(({ state }) => state.state_name === "CHANNEL_READY");
      setChannels(channels);
      setChannelReady(Boolean(readyChannel));
      setChannelEvidence(readyChannel ? {
        channelId: readyChannel.channel_id,
        fundingOutpoint: formatFiberOutpoint(readyChannel.channel_outpoint),
      } : undefined);
      setPhase("ready");
      if (!readyChannel) void connected.keyway.prepareCkbChannel(parseCkb("1000")).catch(() => undefined);
    }).catch((cause) => {
      if (cancelled) return;
      setPhase("error");
      setError(cause instanceof Error ? cause.message : "KeyWay recovery failed");
    });
    return () => { cancelled = true; };
  }, [connected]);

  async function activatePayments() {
    const current = connected;
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
      setChannels(channels);
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
    const current = connected;
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
    const current = connected;
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
      const refreshed = await current.keyway.listChannels({ include_closed: false });
      setChannels(refreshed.channels);
      setPaymentResult(`Payment ${settled.payment_hash} settled`);
      setInvoiceToPay("");
      setPhase("ready");
    } catch (cause) {
      setPhase("ready");
      setError(cause instanceof Error ? cause.message : "Fiber payment failed");
    }
  }

  async function createInvoice() {
    const current = connected;
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

  if (!ready) return <WalletProgress label="Loading secure email login" />;
  if (!authenticated) {
    return (
      <section className="activation-card auth">
        <p className="step-label">Email-secured wallet</p>
        <h2>Enter Fiber with just your email.</h2>
        <p>Use a one-time email code. No wallet extension or crypto onboarding required.</p>
        <button onClick={login}>Log in with email</button>
      </section>
    );
  }
  if (!connected) {
    return (
      <section className="wallet-shell">
        <WalletProgress label={status === "error" ? "Wallet needs attention" : "Recovering your wallet"} />
        {(connectionError || error) && <p className="error">{friendlyError(connectionError?.message ?? error ?? "Wallet recovery failed")}</p>}
        {status === "error" && <button onClick={() => void connect()}>Try again</button>}
        <button className="text-button" onClick={() => void logout()}>Use another email</button>
      </section>
    );
  }

  const currentBalance = balanceShannons ?? connected.balanceShannons;
  const balanceCkb = formatCkb(currentBalance);
  const readyChannels = channels.filter(({ state }) => state.state_name === "CHANNEL_READY");
  const fiberBalance = readyChannels.reduce((total, channel) => total + BigInt(channel.local_balance), 0n);
  const busy = phase !== "ready" && phase !== "error";

  return (
    <section className="wallet-shell">
      <header className="wallet-header">
        <div>
          <p className="status"><span /> Wallet ready</p>
          <p className="address" title={connected.wallet.ckbAddress}>{shorten(connected.wallet.ckbAddress)}</p>
        </div>
        <button className="text-button" onClick={() => void logout()}>Log out</button>
      </header>

      <section className="balance-overview" aria-label="Wallet balances">
        <div className="fiber-balance-card">
          <div className="balance-heading"><span>Total Fiber balance</span><span>{readyChannels.length} active {readyChannels.length === 1 ? "channel" : "channels"}</span></div>
          <strong>{formatCkb(fiberBalance)} <small>CKB</small></strong>
          <p>Available inside your payment channels.</p>
        </div>
        <div className="chain-balance-card">
          <span>Available on CKB</span>
          <strong>{balanceCkb} <small>CKB</small></strong>
          <a href={`https://faucet.nervos.org/?address=${connected.wallet.ckbAddress}`} target="_blank" rel="noreferrer">Add testnet CKB</a>
        </div>
      </section>

      {!channelReady ? (
        <section className="activation-card">
          <p className="step-label">One-time setup</p>
          <h2>Activate instant payments</h2>
          <p>Lock 1,000 testnet CKB in your Fiber channel. You still own it, and normal payments happen off-chain.</p>
          <button onClick={activatePayments} disabled={busy || currentBalance < parseCkb("1100")}>
            {phase === "activating" ? activationLabel(activationStage) : "Activate Fiber payments"}
          </button>
          {phase === "activating" && activationStage && <p className="hint" role="status">{activationDetail(activationStage)}</p>}
          {currentBalance < parseCkb("1100") && <p className="hint">Add testnet CKB before activating.</p>}
          {fundingResult && <p className="hint">Funding submitted: {shorten(fundingResult)}</p>}
        </section>
      ) : (
        <>
          <ChannelList channels={channels} />
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
        </>
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

function ChannelList({ channels }: { channels: FiberChannel[] }) {
  return (
    <section className="channel-section">
      <header><div><p className="step-label">Liquidity</p><h2>Your channels</h2></div><span>{channels.length} open</span></header>
      <div className="channel-list">
        {channels.map((channel, index) => {
          const local = BigInt(channel.local_balance);
          const remote = BigInt(channel.remote_balance);
          const capacity = local + remote;
          const share = capacity === 0n ? 0 : Number((local * 10_000n) / capacity) / 100;
          return (
            <article className="channel-row" key={channel.channel_id}>
              <div className="channel-identity">
                <span className="channel-index">{String(index + 1).padStart(2, "0")}</span>
                <div><strong>{shorten(channel.pubkey)}</strong><span>Peer node</span></div>
              </div>
              <div className="channel-liquidity">
                <div className="channel-sides"><span><small>You</small><strong>{formatCkb(local)} CKB</strong></span><span><small>Peer</small><strong>{formatCkb(remote)} CKB</strong></span></div>
                <div className="liquidity-track" aria-label={`${formatCkb(local)} CKB on your side and ${formatCkb(remote)} CKB on the peer side`}>
                  <span style={{ width: `${share}%` }} />
                </div>
                <small className="channel-capacity">{formatCkb(capacity)} CKB total capacity</small>
              </div>
              <span className="channel-state">{formatChannelState(channel.state.state_name)}</span>
            </article>
          );
        })}
      </div>
    </section>
  );
}

function parseCkb(value: string): bigint {
  const match = /^(\d{1,7})(?:\.(\d{1,8}))?$/.exec(value.trim());
  if (!match) throw new Error("Enter a valid CKB amount with at most 8 decimal places");
  const result = BigInt(match[1]) * 100_000_000n + BigInt((match[2] ?? "").padEnd(8, "0") || "0");
  if (result <= 0n) throw new Error("Amount must be greater than zero");
  return result;
}

function formatChannelState(value: string): string {
  if (value === "CHANNEL_READY") return "Ready";
  return value.toLowerCase().replaceAll("_", " ").replace(/^\w/, (letter) => letter.toUpperCase());
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

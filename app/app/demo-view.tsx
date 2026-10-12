"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { encode } from "uqr";
import { AlertIcon, CheckIcon, ChevronDown, CloseIcon, CopyIcon, ExternalIcon, SpinnerIcon } from "../_components/icons";
import { CopyButton } from "../_components/copy-button";
import { TROUBLESHOOTING_URL } from "../_components/links";
import { clockTime, duration, formatBalance, formatCkb, parseCkb, seconds, shortHash } from "./format";

export type NodeMode = "managed" | "browser";
export type ChannelStatus = "pending" | "ready" | "closing" | "closed" | "failed" | "unknown";
export type ActivationStage = "connecting" | "negotiating" | "confirming" | "signing" | "broadcasting" | "waiting";

/** One lifecycle event: a stage that started at `at`, `elapsedMs` after the run began. */
export type LifecycleEvent = { stage: string; at: number; elapsedMs: number };

export type DemoChannel = {
  id: string;
  peer: string;
  status: ChannelStatus;
  local: bigint;
  remote: bigint;
  reserved?: bigint;
  fundingTx?: string;
};

export type DemoActivity = { id: string; kind: "received" | "paid" | "opened"; amount: bigint; at: number };

export type DemoModel = {
  nodeMode: NodeMode;
  auth: "loading" | "signedOut" | "signedIn";
  account: "recovering" | "ready" | "error";
  accountError?: string;
  address?: string;
  balance?: bigint;
  fiber: "disconnected" | "connecting" | "connected" | "error";
  fiberError?: { code: string; message: string };
  /** Wallet recovery measured on this page before Fiber starts. */
  walletRecovery?: { at: number; durationMs?: number };
  /** Events from the SDK's onLifecycle for the latest connect() run. */
  events: LifecycleEvent[];
  /** When the latest run failed, for the failed stage's duration. */
  failedAt?: number;
  /** Fixed clock for previews; live pages tick in real time. */
  clock?: number;
  channels: DemoChannel[];
  activity: DemoActivity[];
};

export type InvoiceCheck = { amount: bigint; description?: string; fee?: bigint; error?: string };
export type CreatedInvoice = { address: string; amount: bigint; description?: string; createdAt: number; paymentHash: string };

export type DemoActions = {
  login: () => void;
  logout: () => Promise<void>;
  setMode: (mode: NodeMode) => void;
  connect: () => Promise<unknown>;
  openChannel: (amount: bigint, peer: string, onStage: (stage: ActivationStage) => void) => Promise<void>;
  closeChannel: (channelId: string) => Promise<void>;
  checkInvoice: (invoice: string) => Promise<InvoiceCheck>;
  pay: (invoice: string, check: InvoiceCheck) => Promise<void>;
  createInvoice: (amount: bigint, description: string) => Promise<CreatedInvoice>;
  invoiceStatus: (paymentHash: string) => Promise<string>;
  /** Plain CCC through the KeyWay signer: build, complete, approve, send. */
  sendCkb: (address: string, amount: bigint) => Promise<string>;
  signMessage: (message: string) => Promise<{ signature: string; verified: boolean }>;
  getEmailThreshold: () => Promise<bigint | null>;
  setEmailThreshold: (shannons: bigint | null) => Promise<void>;
};

/** Initial UI for development screenshots; production always starts closed. */
export type DemoUi = {
  dialog?: "pay" | "receive";
  invoice?: string;
  created?: CreatedInvoice;
  activation?: ActivationStage;
};

/** The public testnet peers the SDK opens channels with. */
export const CHANNEL_PEERS = [
  { label: "bottle.fiber.channel", pubkey: "0x02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71" },
  { label: "bracer.fiber.channel", pubkey: "0x0291a6576bd5a94bd74b27080a48340875338fff9f6d6361fe6b8db8d0d1912fcc" },
];

const STAGES: Record<NodeMode, string[]> = {
  managed: ["recovering_identity", "starting_managed", "synchronizing", "ready"],
  browser: ["recovering_identity", "acquiring_lease", "restoring_database", "starting_wasm", "connecting_peer", "synchronizing", "ready"],
};

const STAGE_LABELS: Record<string, string> = {
  recovering_identity: "Recovering identity",
  starting_managed: "Starting managed node",
  connecting_peer: "Connecting to a Fiber peer",
  synchronizing: "Synchronizing channels",
  ready: "Ready",
  acquiring_lease: "Claiming this device",
  restoring_database: "Restoring channel data",
  starting_wasm: "Starting the in-browser node",
};

const EXPLORER = "https://testnet.explorer.nervos.org";
const NODE_LABEL: Record<NodeMode, string> = { managed: "managed node", browser: "in-browser node" };

const bareKey = (value: string) => value.replace(/^0x/i, "").toLowerCase();

export function peerLabel(pubkey: string): string {
  return CHANNEL_PEERS.find((peer) => bareKey(peer.pubkey) === bareKey(pubkey))?.label ?? shortHash(pubkey);
}

export function DemoView({ model, actions, initialUi }: { model: DemoModel; actions: DemoActions; initialUi?: DemoUi }) {
  const [dialog, setDialog] = useState(initialUi?.dialog);
  const [activation, setActivation] = useState<ActivationStage | undefined>(initialUi?.activation);
  const liveNow = useNow(model.clock === undefined && model.fiber === "connecting");
  const now = model.clock ?? liveNow;
  const signedIn = model.auth === "signedIn";
  const connected = model.fiber === "connected";
  const openChannels = model.channels.filter(({ status }) => status !== "closed");
  const hasChannels = connected && openChannels.length > 0;

  const code = !signedIn ? "login"
    : model.account === "recovering" ? "wallet"
    : dialog === "pay" ? "pay"
    : dialog === "receive" ? "receive"
    : !connected ? "connect"
    : activation ? "funding"
    : hasChannels ? "channels" : "open";

  return (
    <>
      <div className="demo-intro">
        <div className="demo-intro__copy">
          <p className="eyebrow demo-eyebrow"><span className="demo-eyebrow__dot" />Live demo · CKB testnet</p>
          <h1>A KeyWay wallet, running on testnet.</h1>
          <p className="demo-intro__lede">Sign in with any email to get a real CKB testnet account. Every button on this page calls the same SDK you install.</p>
        </div>
        <div className="demo-intro__side">
          <div className="demo-intro__controls">
            <div role="radiogroup" aria-label="Fiber node" aria-describedby="mode-note" className="segmented">
              {(["managed", "browser"] as const).map((mode) => (
                <button key={mode} type="button" role="radio" aria-checked={model.nodeMode === mode} onClick={() => model.nodeMode !== mode && actions.setMode(mode)}>
                  {mode === "managed" ? "Managed node" : "In-browser node"}
                </button>
              ))}
            </div>
            {signedIn && <button type="button" className="demo-signout" onClick={() => void actions.logout()}>Sign out</button>}
          </div>
          <p id="mode-note" className="demo-intro__note">Each mode runs its own Fiber node. Switching doesn&apos;t move open channels.</p>
        </div>
      </div>

      <div className="demo-grid">
        <div className="demo-col">
          {!signedIn ? <SignInCard loading={model.auth === "loading"} onLogin={actions.login} />
            : model.account === "recovering" ? <RecoveringCards />
            : model.account === "error" ? <AccountErrorCard message={model.accountError} />
            : (
              <>
                <AccountCard model={model} />
                {model.balance !== 0n && <SignerCard actions={actions} />}
                <FiberCard model={model} now={now} actions={actions} activation={activation} setActivation={setActivation} onPay={() => setDialog("pay")} onReceive={() => setDialog("receive")} channels={openChannels} />
                {hasChannels && model.activity.length > 0 && <ActivityCard activity={model.activity} />}
              </>
            )}
        </div>

        <aside aria-label="Developer view" className="demo-aside">
          <section className="code-panel demo-code">
            <div className="demo-code__bar"><h2>See the code</h2><span>@ckb-keyway/react</span></div>
            <pre><code>{CODE[code]}</code></pre>
          </section>
          <LifecycleCard model={model} />
        </aside>
      </div>

      {dialog === "pay" && <PayDialog actions={actions} initialInvoice={initialUi?.invoice} onClose={() => setDialog(undefined)} />}
      {dialog === "receive" && <ReceiveDialog actions={actions} initialCreated={initialUi?.created} onClose={() => setDialog(undefined)} />}
    </>
  );
}

function SignInCard({ loading, onLogin }: { loading: boolean; onLogin: () => void }) {
  return (
    <section className="card demo-signin">
      <h2>Sign in to start</h2>
      <p className="demo-signin__lede">We&apos;ll email you a six-digit code. Your account is created the first time you sign in and recovered on every device after that.</p>
      <button type="button" className={`btn btn--route btn--lg demo-signin__button${loading ? " btn--busy" : ""}`} disabled={loading} onClick={onLogin}>Sign in with email</button>
      <ol className="demo-steps">
        <li><span>1</span><span>See your CKB address and balance</span></li>
        <li><span>2</span><span>Start a Fiber node when you choose</span></li>
        <li><span>3</span><span>Open a channel and make a payment</span></li>
      </ol>
      <p className="demo-signin__note">Test CKB has no value. Your session is stored in this browser.</p>
    </section>
  );
}

function CardHead({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="demo-card__head"><h2>{title}</h2>{children}</div>;
}

function RecoveringCards() {
  return (
    <>
      <section aria-busy="true" className="card demo-card demo-card--16">
        <CardHead title="CKB account"><span className="status status--warning"><span className="status__dot" />Recovering</span></CardHead>
        <p className="demo-card__title">Recovering your CKB account…</p>
        <ul className="demo-recover">
          <li><CheckIcon size={18} className="demo-ok" />Session verified</li>
          <li><SpinnerIcon size={18} className="demo-active" />Recovering your signing identity</li>
        </ul>
      </section>
      <section className="card demo-card demo-card--8">
        <h2 className="demo-card__h">Fiber</h2>
        <p className="demo-card__muted">You can connect to Fiber once your account is ready.</p>
      </section>
    </>
  );
}

function AccountErrorCard({ message }: { message?: string }) {
  return (
    <section role="alert" className="card demo-card demo-card--14">
      <CardHead title="CKB account"><span className="status status--danger"><AlertIcon size={14} strokeWidth={2.5} />Not available</span></CardHead>
      <p className="demo-card__title">Couldn&apos;t recover your CKB account</p>
      <p className="demo-card__body">{message ?? "Wallet recovery failed."} Sign out and sign in again to retry.</p>
    </section>
  );
}

function AccountCard({ model }: { model: DemoModel }) {
  const empty = model.balance === 0n;
  return (
    <section className="card demo-card demo-card--14">
      <CardHead title="CKB account">
        {empty ? <span className="status status--success"><span className="status__dot" />Ready</span> : (
          <span className="demo-card__links">
            {model.address && <a href={`${EXPLORER}/address/${model.address}`} target="_blank" rel="noreferrer">View in explorer</a>}
            <span className="status status--success"><span className="status__dot" />Ready</span>
          </span>
        )}
      </CardHead>
      <p className="demo-balance" title={model.balance === undefined ? undefined : `${formatCkb(model.balance)} CKB`}>{model.balance === undefined ? "—" : formatBalance(model.balance)} <span>CKB</span></p>
      <div className="copy-well">
        <span className="copy-well__value">{model.address}</span>
        {model.address && <CopyButton value={model.address} label="Copy address" />}
      </div>
      {empty && model.address && (
        <div className="demo-faucet">
          <p>This account has no CKB yet. Fund it from the testnet faucet to open a channel.</p>
          <a className="demo-faucet__link" href={`https://faucet.nervos.org/?address=${model.address}`} target="_blank" rel="noreferrer">Open the faucet<ExternalIcon size={14} /></a>
        </div>
      )}
    </section>
  );
}

function SignerCard({ actions }: { actions: DemoActions }) {
  const [address, setAddress] = useState("");
  const [amount, setAmount] = useState("100");
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState<string>();
  const [message, setMessage] = useState("Log in to Acme Pay");
  const [signed, setSigned] = useState<{ signature: string; verified: boolean }>();
  const [threshold, setThreshold] = useState<bigint | null | undefined>(undefined);
  const [thresholdInput, setThresholdInput] = useState("500");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState<string>();

  useEffect(() => { void actions.getEmailThreshold().then(setThreshold).catch(() => setThreshold(null)); }, [actions]);

  async function run<T>(label: string, task: () => Promise<T>): Promise<T | undefined> {
    setBusy(label);
    setError(undefined);
    try { return await task(); } catch (cause) { setError(cause instanceof Error ? cause.message : "Something went wrong"); return undefined; } finally { setBusy(undefined); }
  }

  return (
    <section className="card demo-card demo-card--16">
      <CardHead title="Send CKB"><code className="demo-card__code">useCkbWallet().signer</code></CardHead>
      <p className="demo-card__body">Ordinary CCC code against your KeyWay account. You approve every transaction before KeyWay signs it.</p>
      <div className="demo-open">
        <label className="field demo-open__peer">To address<input className="input demo-mono" value={address} spellCheck={false} placeholder="ckt1…" onChange={(event) => setAddress(event.target.value.trim())} /></label>
        <label className="field demo-open__amount">Amount
          <span className="demo-affix"><input value={amount} inputMode="decimal" onChange={(event) => setAmount(event.target.value)} /><span>CKB</span></span>
        </label>
        <button type="button" className={`btn btn--route${sending ? " btn--busy" : ""}`} disabled={sending || !address} onClick={() => void (async () => {
          setSending(true);
          setSent(undefined);
          const hash = await run("send", () => actions.sendCkb(address, parseCkb(amount)));
          if (hash) setSent(hash);
          setSending(false);
        })()}>{sending ? "Sending…" : "Send"}</button>
      </div>
      {sent && <p className="demo-route"><CheckIcon size={16} />Sent. <a className="demo-tx-link" href={`${EXPLORER}/transaction/${sent}`} target="_blank" rel="noreferrer">{shortHash(sent)}</a></p>}

      <div className="demo-signer-row">
        <label className="field demo-signer-row__grow">Message<input className="input" value={message} maxLength={500} onChange={(event) => setMessage(event.target.value)} /></label>
        <button type="button" className={`btn btn--outline${busy === "sign" ? " btn--busy" : ""}`} disabled={Boolean(busy) || !message.trim()} onClick={() => void run("sign", () => actions.signMessage(message)).then((result) => result && setSigned(result))}>Sign message</button>
      </div>
      {signed && <p className={`demo-route${signed.verified ? "" : " demo-route--muted"}`}><CheckIcon size={16} />{signed.verified ? "Signed, and verified with CCC's verifyMessage" : "Signed"} <code className="demo-card__code">{shortHash(signed.signature)}</code></p>}

      <div className="demo-signer-row">
        <label className="field demo-signer-row__grow">Email me a code for transfers of
          <span className="demo-affix"><input value={thresholdInput} inputMode="decimal" onChange={(event) => setThresholdInput(event.target.value)} /><span>CKB or more</span></span>
        </label>
        <button type="button" className={`btn btn--outline${busy === "threshold" ? " btn--busy" : ""}`} disabled={Boolean(busy)} onClick={() => void run("threshold", async () => {
          const next = parseCkb(thresholdInput);
          await actions.setEmailThreshold(next);
          setThreshold(next);
        })}>Save</button>
        {threshold !== null && threshold !== undefined && (
          <button type="button" className="btn btn--outline" disabled={Boolean(busy)} onClick={() => void run("threshold", async () => { await actions.setEmailThreshold(null); setThreshold(null); })}>Turn off</button>
        )}
      </div>
      <p className="demo-card__muted demo-signer-status">{threshold === undefined ? "Checking your email confirmation setting…" : threshold === null ? "Email confirmation is off." : `Transfers of ${formatCkb(threshold)} CKB or more need a code from your email.`}</p>
      {error && <p className="field-error"><AlertIcon />{error}</p>}
    </section>
  );
}

function FiberCard({ model, now, actions, activation, setActivation, onPay, onReceive, channels }: {
  model: DemoModel;
  now: number;
  actions: DemoActions;
  activation?: ActivationStage;
  setActivation: (stage?: ActivationStage) => void;
  onPay: () => void;
  onReceive: () => void;
  channels: DemoChannel[];
}) {
  if (model.fiber === "connecting") return <ConnectingCard model={model} now={now} />;
  if (model.fiber === "error") return <FiberErrorCard model={model} onRetry={() => void actions.connect().catch(() => undefined)} />;
  if (model.fiber === "disconnected") {
    return (
      <section className="card demo-card demo-card--14">
        <CardHead title="Fiber"><span className="status status--muted"><span className="status__ring" />Off</span></CardHead>
        <p className="demo-card__title">Fiber isn&apos;t connected</p>
        <p className="demo-card__body">{model.nodeMode === "managed"
          ? "Connecting starts a managed Fiber node for this account. Signing in never starts one on its own."
          : "Connecting starts a Fiber node in this browser tab. Signing in never starts one on its own."}</p>
        <button type="button" className="btn btn--route demo-card__action" onClick={() => void actions.connect().catch(() => undefined)}>Connect Fiber</button>
      </section>
    );
  }
  const status = <span className="status status--success"><span className="status__dot" />Connected · {NODE_LABEL[model.nodeMode]}</span>;
  if (!channels.length || activation) return <OpenChannelCard status={status} actions={actions} activation={activation} setActivation={setActivation} />;
  return (
    <section className="card demo-card demo-card--18">
      <CardHead title="Fiber">{status}</CardHead>
      <div className="demo-buttons">
        <button type="button" className="btn btn--route" onClick={onPay}>Pay an invoice</button>
        <button type="button" className="btn btn--outline demo-btn-outline" onClick={onReceive}>Receive</button>
      </div>
      {channels.map((channel) => <ChannelBox key={channel.id} channel={channel} actions={actions} />)}
    </section>
  );
}

function ConnectingCard({ model, now }: { model: DemoModel; now: number }) {
  const steps = STAGES[model.nodeMode];
  const reached = model.events.map(({ stage }) => stage);
  const current = reached.at(-1);
  return (
    <section aria-busy="true" className="card demo-card demo-card--16">
      <CardHead title="Fiber"><span className="status status--warning"><span className="status__dot" />Connecting</span></CardHead>
      <p className="demo-card__title">Starting your Fiber node…</p>
      <ol className="demo-progress">
        {steps.map((stage) => {
          const index = model.events.findIndex((event) => event.stage === stage);
          const event = model.events[index];
          const next = model.events[index + 1];
          const state = !event ? "pending" : stage === current ? "active" : "done";
          const ms = event ? (next ? next.at - event.at : now - event.at) : undefined;
          return (
            <li key={stage} className={`is-${state}`}>
              {state === "done" ? <CheckIcon size={18} className="demo-ok" /> : state === "active" ? <SpinnerIcon size={18} className="demo-active" /> : <span className="demo-progress__pending"><span /></span>}
              <span className="demo-progress__label">{STAGE_LABELS[stage] ?? stage}</span>
              {ms !== undefined && <span className="demo-progress__time">{seconds(ms)}</span>}
            </li>
          );
        })}
      </ol>
    </section>
  );
}

function FiberErrorCard({ model, onRetry }: { model: DemoModel; onRetry: () => void }) {
  const last = model.events.at(-1);
  const elapsed = last && model.failedAt ? model.failedAt - last.at : undefined;
  const code = model.fiberError?.code ?? "UNKNOWN";
  return (
    <section role="alert" className="card demo-card demo-card--14">
      <CardHead title="Fiber"><span className="status status--danger"><AlertIcon size={14} strokeWidth={2.5} />Not connected</span></CardHead>
      <p className="demo-card__title">{code === "PEER_OFFLINE" ? "Couldn't reach a Fiber peer" : "Couldn't connect to Fiber"}</p>
      <p className="demo-card__body">{model.fiberError?.message} Your account and balance are unaffected. Try again, or see Troubleshooting if it keeps happening.</p>
      <div className="demo-buttons">
        <button type="button" className="btn btn--route" onClick={onRetry}>Try again</button>
        <a className="btn btn--outline demo-btn-link" href={TROUBLESHOOTING_URL}>Troubleshooting</a>
      </div>
      <p className="demo-error-code">KeyWayError {code}{last ? ` · stage ${last.stage}` : ""}{elapsed !== undefined ? ` · ${seconds(elapsed)}` : ""}</p>
    </section>
  );
}

const ACTIVATION_LABEL: Record<ActivationStage, string> = {
  connecting: "Connecting to peer…",
  negotiating: "Preparing transaction…",
  confirming: "Review the transaction",
  signing: "Signing…",
  broadcasting: "Submitting…",
  waiting: "Confirming on CKB…",
};

function OpenChannelCard({ status, actions, activation, setActivation }: {
  status: ReactNode;
  actions: DemoActions;
  activation?: ActivationStage;
  setActivation: (stage?: ActivationStage) => void;
}) {
  const [amount, setAmount] = useState("1,000");
  const [peer, setPeer] = useState(CHANNEL_PEERS[0].pubkey);
  const [error, setError] = useState<string>();

  async function open() {
    setError(undefined);
    let shannons: bigint;
    try { shannons = parseCkb(amount); } catch (cause) { setError((cause as Error).message); return; }
    setActivation("connecting");
    try {
      await actions.openChannel(shannons, peer, setActivation);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The channel could not be opened");
    } finally {
      setActivation(undefined);
    }
  }

  return (
    <section className="card demo-card demo-card--16">
      <CardHead title="Fiber">{status}</CardHead>
      <p className="demo-card__title">No channels yet</p>
      <p className="demo-card__body">Open a channel to pay over Fiber. It&apos;s funded from your CKB balance, and you approve the exact amount and fee first.</p>
      <div className="demo-open">
        <label className="field demo-open__amount">Amount
          <span className="demo-affix">
            <input value={amount} inputMode="decimal" onChange={(event) => setAmount(event.target.value)} disabled={Boolean(activation)} aria-invalid={Boolean(error) || undefined} />
            <span>CKB</span>
          </span>
        </label>
        <label className="field demo-open__peer">Peer
          <span className="demo-select">
            <select value={peer} onChange={(event) => setPeer(event.target.value)} disabled={Boolean(activation)}>
              {CHANNEL_PEERS.map((option) => <option key={option.pubkey} value={option.pubkey}>{option.label}</option>)}
            </select>
            <ChevronDown />
          </span>
        </label>
        <button type="button" className={`btn btn--route${activation ? " btn--busy" : ""}`} disabled={Boolean(activation)} onClick={() => void open()}>
          {activation ? ACTIVATION_LABEL[activation] : "Open channel"}
        </button>
      </div>
      {error && <p className="field-error"><AlertIcon />{error}</p>}
    </section>
  );
}

function ChannelBox({ channel, actions }: { channel: DemoChannel; actions: DemoActions }) {
  const [confirming, setConfirming] = useState(false);
  const [closing, setClosing] = useState(false);
  const [error, setError] = useState<string>();
  useEffect(() => {
    if (!confirming) return;
    const timer = window.setTimeout(() => setConfirming(false), 5000);
    return () => window.clearTimeout(timer);
  }, [confirming]);
  const reserved = channel.reserved ?? 0n;
  const statusClass = channel.status === "ready" ? "success" : channel.status === "pending" ? "warning" : channel.status === "failed" ? "danger" : "muted";
  const statusLabel = { ready: "Ready", pending: "Opening", closing: "Closing", closed: "Closed", failed: "Failed", unknown: "Unknown" }[channel.status];

  async function close() {
    setConfirming(false);
    setClosing(true);
    setError(undefined);
    try { await actions.closeChannel(channel.id); } catch (cause) { setError(cause instanceof Error ? cause.message : "The channel could not be closed"); } finally { setClosing(false); }
  }

  return (
    <div className="demo-channel">
      <div className="demo-channel__head"><span className="demo-channel__peer">{peerLabel(channel.peer)}</span><span className={`status status--${statusClass}`}><span className="status__dot" />{statusLabel}</span></div>
      <div className="demo-channel__bar" aria-hidden="true">
        <span style={{ flex: Number(channel.local / 1_000_000n) }} className="is-send" />
        {reserved > 0n && <span style={{ flex: Number(reserved / 1_000_000n) }} className="is-reserved" />}
        <span style={{ flex: Number(channel.remote / 1_000_000n) }} className="is-receive" />
      </div>
      <dl className="demo-channel__amounts">
        <div><dt><span className="is-send" />You can send</dt><dd>{formatCkb(channel.local)}</dd></div>
        <div><dt><span className="is-reserved" />Reserved</dt><dd>{channel.reserved === undefined ? "—" : formatCkb(channel.reserved)}</dd></div>
        <div><dt><span className="is-receive" />You can receive</dt><dd>{formatCkb(channel.remote)}</dd></div>
      </dl>
      <div className="demo-channel__foot">
        <span>{channel.fundingTx ? <>Funded by <a href={`${EXPLORER}/transaction/${channel.fundingTx}`} target="_blank" rel="noreferrer">{shortHash(channel.fundingTx)}</a></> : "Funding pending"}</span>
        {channel.status === "ready" && (confirming ? (
          <span className="demo-confirm">
            <button type="button" className="text-button demo-confirm__danger" onClick={() => void close()}>Confirm close</button>
            <button type="button" className="text-button" onClick={() => setConfirming(false)}>Cancel</button>
          </span>
        ) : (
          <button type="button" className="text-button" disabled={closing} onClick={() => setConfirming(true)}>{closing ? "Closing…" : "Close channel"}</button>
        ))}
      </div>
      {error && <p className="field-error"><AlertIcon />{error}</p>}
    </div>
  );
}

function ActivityCard({ activity }: { activity: DemoActivity[] }) {
  const label = { received: "Received over Fiber", paid: "Paid over Fiber", opened: "Channel opened" };
  return (
    <section className="card demo-card demo-activity">
      <h2>Activity</h2>
      {[...activity].sort((a, b) => b.at - a.at).map((item) => (
        <div key={item.id} className="demo-activity__row">
          <span className={`demo-activity__dot is-${item.kind}`} />
          <span className="demo-activity__what">{label[item.kind]}</span>
          <span className="demo-activity__amount">{item.kind === "received" ? "+" : item.kind === "paid" ? "−" : ""}{formatCkb(item.amount)}</span>
          <span className="demo-activity__when">{clockTime(item.at, false)}</span>
        </div>
      ))}
    </section>
  );
}

function LifecycleCard({ model }: { model: DemoModel }) {
  const rows: Array<{ key: string; at: number; stage: string; time: string; tone?: "route" | "danger" | "success" }> = [];
  if (model.events.length) {
    model.events.forEach((event, index) => {
      const next = model.events[index + 1];
      const last = index === model.events.length - 1;
      if (!last) return rows.push({ key: `${event.stage}-${index}`, at: event.at, stage: event.stage, time: duration(next.at - event.at) });
      if (event.stage === "ready") return rows.push({ key: "ready", at: event.at, stage: "ready", time: `${seconds(event.elapsedMs)} total`, tone: "success" });
      if (model.fiber === "error") return rows.push({ key: "failed", at: event.at, stage: `${event.stage} failed`, time: model.failedAt ? seconds(model.failedAt - event.at) : "", tone: "danger" });
      rows.push({ key: "active", at: event.at, stage: event.stage, time: "…", tone: "route" });
    });
  } else if (model.walletRecovery) {
    const { at, durationMs } = model.walletRecovery;
    rows.push({ key: "wallet", at, stage: "recovering_identity", time: durationMs === undefined ? "…" : duration(durationMs) });
  }
  return (
    <section className="card demo-lifecycle">
      <div className="demo-lifecycle__head"><h2>Lifecycle events</h2><code>onLifecycle</code></div>
      {rows.length ? (
        <ol>
          {rows.map((row) => (
            <li key={row.key}><span className="demo-lifecycle__muted">{clockTime(row.at)}</span><span className={`demo-lifecycle__stage${row.tone ? ` is-${row.tone}` : ""}`}>{row.stage}</span><span className="demo-lifecycle__muted">{row.time}</span></li>
          ))}
        </ol>
      ) : <p>Events appear here after you sign in, with the time each stage took.</p>}
    </section>
  );
}

function Dialog({ title, labelId, onClose, children }: { title: string; labelId: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    document.body.classList.add("menu-open");
    return () => { window.removeEventListener("keydown", onKey); document.body.classList.remove("menu-open"); };
  }, [onClose]);
  return (
    <div className="scrim" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <div role="dialog" aria-modal="true" aria-labelledby={labelId} className="dialog">
        <div className="dialog__head"><h2 id={labelId} className="dialog__title">{title}</h2><button type="button" aria-label="Close" className="dialog__close" onClick={onClose}><CloseIcon size={18} /></button></div>
        {children}
      </div>
    </div>
  );
}

function PayDialog({ actions, initialInvoice, onClose }: { actions: DemoActions; initialInvoice?: string; onClose: () => void }) {
  const [invoice, setInvoice] = useState(initialInvoice ?? "");
  const [check, setCheck] = useState<InvoiceCheck>();
  const [checking, setChecking] = useState(false);
  const [paying, setPaying] = useState(false);
  const [error, setError] = useState<string>();
  const run = useRef(0);

  useEffect(() => {
    const value = invoice.trim();
    const id = ++run.current;
    setCheck(undefined);
    setError(undefined);
    if (!value) return;
    setChecking(true);
    const timer = window.setTimeout(() => {
      actions.checkInvoice(value)
        .then((result) => { if (id === run.current) setCheck(result); })
        .catch((cause) => { if (id === run.current) setError(cause instanceof Error ? cause.message : "This invoice could not be read"); })
        .finally(() => { if (id === run.current) setChecking(false); });
    }, 350);
    return () => window.clearTimeout(timer);
  }, [invoice, actions]);

  async function pay() {
    if (!check) return;
    setPaying(true);
    setError(undefined);
    try {
      await actions.pay(invoice.trim(), check);
      onClose();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The payment failed");
    } finally {
      setPaying(false);
    }
  }

  const payable = check && !check.error;
  return (
    <Dialog title="Pay an invoice" labelId="pay-title" onClose={onClose}>
      <label className="field">Fiber invoice
        <textarea className="demo-invoice-input" value={invoice} autoFocus spellCheck={false} placeholder="fibt…" onChange={(event) => setInvoice(event.target.value)} />
      </label>
      {check && (
        <dl className="detail-list">
          <div><dt>Amount</dt><dd className="demo-strong">{formatCkb(check.amount)} CKB</dd></div>
          {check.description && <div><dt>Description</dt><dd>{check.description}</dd></div>}
          {check.fee !== undefined && <div><dt>Routing fee</dt><dd>{formatCkb(check.fee)} CKB</dd></div>}
        </dl>
      )}
      {checking && <p className="demo-route demo-route--muted"><SpinnerIcon size={16} />Checking the invoice…</p>}
      {payable && <p className="demo-route"><CheckIcon size={16} />Route found through your channel</p>}
      {(check?.error || error) && <p className="field-error"><AlertIcon />{check?.error ?? error}</p>}
      <button type="button" className={`btn btn--route btn--lg demo-pay${paying ? " btn--busy" : ""}`} disabled={!payable || paying} onClick={() => void pay()}>
        {paying ? "Paying…" : payable ? `Pay ${formatCkb(check.amount + (check.fee ?? 0n))} CKB` : "Pay"}
      </button>
    </Dialog>
  );
}

function ReceiveDialog({ actions, initialCreated, onClose }: { actions: DemoActions; initialCreated?: CreatedInvoice; onClose: () => void }) {
  const [amount, setAmount] = useState("5");
  const [description, setDescription] = useState("");
  const [created, setCreated] = useState(initialCreated);
  const [status, setStatus] = useState("Open");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    if (!created || status === "Paid") return;
    let cancelled = false;
    const poll = () => actions.invoiceStatus(created.paymentHash).then((next) => { if (!cancelled) setStatus(next); }).catch(() => undefined);
    const timer = window.setInterval(poll, 3000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [created, status, actions]);

  async function create() {
    setError(undefined);
    let shannons: bigint;
    try { shannons = parseCkb(amount); } catch (cause) { setError((cause as Error).message); return; }
    setPending(true);
    try { setCreated(await actions.createInvoice(shannons, description.trim())); } catch (cause) { setError(cause instanceof Error ? cause.message : "The invoice could not be created"); } finally { setPending(false); }
  }

  if (!created) {
    return (
      <Dialog title="Receive" labelId="recv-title" onClose={onClose}>
        <label className="field">Amount
          <span className="demo-affix"><input value={amount} inputMode="decimal" autoFocus onChange={(event) => setAmount(event.target.value)} aria-invalid={Boolean(error) || undefined} /><span>CKB</span></span>
        </label>
        <label className="field">Description<input className="input" value={description} maxLength={120} placeholder="Order #1042" onChange={(event) => setDescription(event.target.value)} /></label>
        {error && <p className="field-error"><AlertIcon />{error}</p>}
        <button type="button" className={`btn btn--route btn--lg demo-pay${pending ? " btn--busy" : ""}`} disabled={pending} onClick={() => void create()}>{pending ? "Creating…" : "Create invoice"}</button>
      </Dialog>
    );
  }

  const paid = status === "Paid";
  const closed = status === "Expired" || status === "Cancelled";
  return (
    <Dialog title={`Receive ${formatCkb(created.amount)} CKB`} labelId="recv-title" onClose={onClose}>
      <div className="demo-receive">
        <div className="demo-qr"><QrCode value={created.address} /></div>
        <div className="demo-receive__meta">
          <span className={`status demo-receive__status status--${paid ? "success" : closed ? "muted" : "warning"}`}><span className="status__dot" />{paid ? "Paid" : closed ? `Invoice ${status.toLowerCase()}` : "Waiting for payment"}</span>
          {created.description && <span>{created.description}</span>}
          <span>Created {clockTime(created.createdAt, false)}</span>
        </div>
      </div>
      <div className="copy-well">
        <span className="copy-well__value">{created.address}</span>
        <CopyButton value={created.address} label="Copy invoice" />
      </div>
      <p className="demo-receive__note">Share this invoice with the payer. It can be paid once, from any wallet on the Fiber network.</p>
    </Dialog>
  );
}

function QrCode({ value }: { value: string }) {
  const { data, size } = encode(value, { border: 0, ecc: "L" });
  const cell = 148 / size;
  return (
    <svg width="148" height="148" viewBox="0 0 148 148" role="img" aria-label="Invoice QR code" shapeRendering="crispEdges">
      <rect width="148" height="148" fill="#FFFFFF" />
      {data.flatMap((row, y) => row.map((dark, x) => dark ? <rect key={`${x}-${y}`} x={x * cell} y={y * cell} width={cell} height={cell} fill="#111B35" /> : null))}
    </svg>
  );
}

function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => setNow(Date.now()), 100);
    return () => window.clearInterval(timer);
  }, [active]);
  return now;
}

const CODE: Record<string, ReactNode> = {
  login: <><span className="tk-k">const</span>{" { authenticated, login } =\n  useKeyWay();\n\n"}<span className="tk-k">if</span>{" (!authenticated) {\n  "}<span className="tk-k">return</span>{" <"}<span className="tk-c">button</span>{" onClick={login}>\n    Sign in with email\n  </"}<span className="tk-c">button</span>{">;\n}"}</>,
  wallet: <><span className="tk-k">const</span>{" { status, address, balance } =\n  useCkbWallet();\n\n"}<span className="tk-m">{"// \"recovering\" until it is ready"}</span>{"\n"}<span className="tk-k">if</span>{" (status === "}<span className="tk-s">&quot;recovering&quot;</span>{") {\n  "}<span className="tk-k">return</span>{" <"}<span className="tk-c">Spinner</span>{" />;\n}"}</>,
  connect: <><span className="tk-k">const</span>{" fiber = useFiber();\n\n"}<span className="tk-m">{"// Fiber starts only when you ask"}</span>{"\n<"}<span className="tk-c">button</span>{" onClick={() => fiber.connect()}>\n  Connect Fiber\n</"}<span className="tk-c">button</span>{">\n\n"}<span className="tk-m">{"// \"disconnected\" | \"connecting\""}</span>{"\n"}<span className="tk-m">{"// | \"connected\" | \"error\""}</span>{"\nfiber.status;"}</>,
  open: <><span className="tk-k">const</span>{" fiber = useFiber();\n\n"}<span className="tk-m">{"// 1,000 CKB, in shannons"}</span>{"\n"}<span className="tk-k">await</span>{" fiber.openChannel({\n  fundingAmount: "}<span className="tk-s">1_000n</span>{" * "}<span className="tk-s">100_000_000n</span>{",\n});"}</>,
  funding: <><span className="tk-m">{"// Built-in dialog by default."}</span>{"\n"}<span className="tk-m">{"// Or bring your own:"}</span>{"\n<"}<span className="tk-c">KeyWayProvider</span>{"\n  appId={APP_ID}\n  confirmFunding={(preview) =>\n    askUser(\n      preview.amountCkb,\n      preview.feeCkb,\n    )\n  }\n/>"}</>,
  channels: <><span className="tk-k">const</span>{" { channels } = useFiber();\n\nchannels.map((c) => (\n  <"}<span className="tk-c">Channel</span>{"\n    key={c.id}\n    peer={c.peer}\n    status={c.status}\n  />\n));"}</>,
  pay: <><span className="tk-k">const</span>{" fiber = useFiber();\n\n"}<span className="tk-k">const</span>{" check = "}<span className="tk-k">await</span>{" fiber\n  .preflightPayment({ invoice });\n\n"}<span className="tk-k">if</span>{" (check.routable) {\n  "}<span className="tk-k">await</span>{" fiber.payInvoice(invoice);\n}"}</>,
  receive: <><span className="tk-k">const</span>{" amount = "}<span className="tk-s">5n</span>{" * "}<span className="tk-s">100_000_000n</span>{";\n\n"}<span className="tk-k">const</span>{" invoice = "}<span className="tk-k">await</span>{" fiber\n  .createInvoice({\n    amount: "}<span className="tk-s">{"`0x${amount.toString(16)}`"}</span>{",\n    currency: "}<span className="tk-s">&quot;Fibt&quot;</span>{",\n    description: "}<span className="tk-s">&quot;Order #1042&quot;</span>{",\n  });"}</>,
};

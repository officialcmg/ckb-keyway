"use client";

import dynamic from "next/dynamic";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ccc } from "@ckb-ccc/core";
import {
  friendlyKeyWayError,
  KeyWayProvider,
  toKeyWayError,
  useCkbWallet,
  useFiber,
  useKeyWay,
  type KeyWayChannel,
  type FiberStartupEvent,
} from "@ckb-keyway/react";
import { DemoView, type DemoBackup, type DemoActions, type DemoActivity, type DemoChannel, type DemoModel, type LifecycleEvent, type NodeMode } from "./app/demo-view";
import { CKB, parseCkb, toHex, type Unit } from "./app/format";

// Tokens the demo names, by type script hash. Stable++ RUSD is the token Fiber's testnet nodes accept.
const TOKENS: Record<string, Unit> = {
  "0x45b32a2bc4285d0a09678eb11960ddc8707bc2779887a09d482e9bfe9a2cdf52": { symbol: "RUSD", decimals: 8 },
};

// Fiber's new_invoice `expiry` is in seconds.
const INVOICE_EXPIRY_SECONDS = 60n * 60n;
const PAYMENT_OPTIONS = { timeout: toHex(120_000n), max_fee_amount: toHex(parseCkb("1")) };

/** Development-only state previews (`/app?screen=…`); never bundled in production. */
const DevScreen = process.env.NODE_ENV !== "production"
  ? dynamic(() => import("./app/dev-screens").then((module) => module.DevScreen), { ssr: false })
  : () => null;

export function AuthPanel({ nodeMode = "hosted", devScreen }: { nodeMode?: NodeMode; devScreen?: string }) {
  const router = useRouter();
  const setMode = useCallback((mode: NodeMode) => router.push(mode === "browser" ? "/app?mode=browser" : "/app"), [router]);
  if (process.env.NODE_ENV !== "production" && devScreen) return <DevScreen screen={devScreen} nodeMode={nodeMode} />;
  return <LiveDemo key={nodeMode} nodeMode={nodeMode} setMode={setMode} />;
}

// The demo asks "Confirm close" in its own channel card, so it replaces KeyWay's close dialog.
const confirmedByDemo = () => true;

function LiveDemo({ nodeMode, setMode }: { nodeMode: NodeMode; setMode: (mode: NodeMode) => void }) {
  const [events, setEvents] = useState<LifecycleEvent[]>([]);
  const onFiberStartup = useCallback((event: FiberStartupEvent) => {
    setEvents((current) => event.stage === "loading_account" ? [event] : [...current, event]);
  }, []);
  return (
    <KeyWayProvider appId={process.env.NEXT_PUBLIC_KEYWAY_APP_ID} fiberNode={nodeMode} theme="light" onFiberStartup={onFiberStartup} approveFiberChannelClose={confirmedByDemo}>
      <LiveWallet nodeMode={nodeMode} events={events} resetEvents={() => setEvents([])} setMode={setMode} />
    </KeyWayProvider>
  );
}

/** `useCkbWallet().recovery`, from @ckb-keyway/react 0.2.5. With an SDK without it the demo hides the card. */
type RecoveryApi = {
  status: "on" | "off";
  backups: DemoBackup[];
  legacyAddress?: string;
  createEvmBackup: () => Promise<unknown>;
  enable: (backups: unknown[]) => Promise<unknown>;
  addBackup: (backup: unknown) => Promise<unknown>;
  removeBackup: (backup: DemoBackup) => Promise<unknown>;
};

function LiveWallet({ nodeMode, events, resetEvents, setMode }: {
  nodeMode: NodeMode;
  events: LifecycleEvent[];
  resetEvents: () => void;
  setMode: (mode: NodeMode) => void;
}) {
  const { ready, authenticated, login, logout } = useKeyWay();
  const account = useCkbWallet();
  const fiber = useFiber();
  const [walletRecovery, setWalletRecovery] = useState<{ at: number; durationMs?: number }>();
  const [failedAt, setFailedAt] = useState<number>();
  const [activity, setActivity] = useState<DemoActivity[]>([]);
  const [payments, setPayments] = useState<DemoActivity[]>([]);
  const reserved = useChannelReserves(fiber.channels);
  const receiving = useRef(new Map<string, bigint>());
  const fiberRef = useRef(fiber);
  fiberRef.current = fiber;
  const refreshBalanceRef = useRef(account.refreshBalance);
  refreshBalanceRef.current = account.refreshBalance;
  const signerRef = useRef(account.signer);
  signerRef.current = account.signer;
  const recovery = (account as { recovery?: RecoveryApi }).recovery;
  const recoveryRef = useRef(recovery);
  recoveryRef.current = recovery;

  // Time the wallet recovery that follows sign-in, so the log has something real to show before Fiber starts.
  useEffect(() => {
    if (account.status === "loading") setWalletRecovery((current) => current ?? { at: Date.now() });
    else if (account.status === "ready") setWalletRecovery((current) => current && current.durationMs === undefined ? { ...current, durationMs: Date.now() - current.at } : current);
    else if (account.status === "disconnected") setWalletRecovery(undefined);
  }, [account.status]);

  useEffect(() => { setFailedAt(fiber.status === "error" ? Date.now() : undefined); }, [fiber.status]);

  // Sent payments come from the node itself (`listPayments`), so they survive reloads and other devices.
  const loadPayments = useCallback(async () => {
    const node = fiberRef.current.node;
    if (!node) return;
    const [{ payments: sent }, { channels }] = await Promise.all([node.listPayments({ limit: toHex(20n) }), node.listChannels({ include_closed: true })]);
    setPayments(sent.flatMap((payment) => {
      const routes = payment.routers ?? [];
      if (payment.status !== "Success" || routes.length === 0) return [];
      // The first hop carries what left the user's channel: the amount plus every routing fee.
      const amount = routes.reduce((total, route) => total + BigInt(route.nodes[0]?.amount ?? 0), 0n);
      const firstHop = fundingOutpoint(routes[0].nodes[0]?.channel_outpoint)?.txHash;
      const channel = channels.find((item) => fundingOutpoint(item.channel_outpoint)?.txHash === firstHop);
      const unit = channel ? channelUnit(channel) : CKB;
      return [{ id: `paid-${payment.payment_hash}`, kind: "paid" as const, amount, unit, at: Number(BigInt(payment.created_at)) }];
    }));
  }, []);

  useEffect(() => {
    if (fiber.status !== "running") { setPayments([]); return; }
    void loadPayments().catch(() => undefined);
    const timer = window.setInterval(() => void loadPayments().catch(() => undefined), 15_000);
    return () => window.clearInterval(timer);
  }, [fiber.status, loadPayments]);

  useEffect(() => {
    if (account.status !== "ready") return;
    const timer = window.setInterval(() => void refreshBalanceRef.current().catch(() => undefined), 15_000);
    return () => window.clearInterval(timer);
  }, [account.status]);

  const actions = useMemo<DemoActions>(() => ({
    login,
    logout: async () => {
      await logout();
      resetEvents();
      setActivity([]);
    },
    setMode,
    startFiber: () => fiberRef.current.start(),
    openChannel: async (amount, peer, onStage) => {
      try {
        const { channelId } = await fiberRef.current.openChannel({ fundingAmount: amount, peer, public: true }, onStage);
        setActivity((current) => [...current, { id: `opened-${channelId}`, kind: "opened", amount, unit: CKB, at: Date.now() }]);
      } catch (cause) {
        throw new Error(readable(cause, "The channel couldn't be opened. Your CKB balance is unaffected."));
      }
      await refreshBalanceRef.current().catch(() => undefined);
    },
    closeChannel: async (channelId) => {
      try {
        await fiberRef.current.closeChannel(channelId as `0x${string}`);
      } catch (cause) {
        throw new Error(readable(cause, "The channel couldn't be closed. Try again in a moment."));
      }
      await refreshBalanceRef.current().catch(() => undefined);
    },
    checkInvoice: async (invoice) => {
      const { invoice: parsed } = await fiberRef.current.parseInvoice({ invoice }).catch(() => { throw new Error("This doesn't look like a valid Fiber invoice."); });
      const udtScript = parsed.data.attrs.flatMap((attr) => "udt_script" in attr ? [attr.udt_script as string] : [])[0];
      const unit = udtScript ? TOKENS[ccc.hashCkb(udtScript)] : CKB;
      if (!unit) return { amount: 0n, unit: CKB, error: "This invoice is for a token this demo doesn't recognize." };
      if (!parsed.amount) return { amount: 0n, unit, error: "This invoice has no amount. Ask the payee for one with a fixed amount." };
      const amount = BigInt(parsed.amount);
      const description = parsed.data.attrs.flatMap((attr) => "description" in attr ? [attr.description] : [])[0];
      const estimate = await fiberRef.current.estimatePayment({ invoice, ...PAYMENT_OPTIONS });
      if (!estimate.routable) return { amount, unit, description, error: readable(estimate.error, "No route was found for this payment.") };
      return { amount, unit, description, fee: estimate.fee };
    },
    pay: async (invoice) => {
      try {
        await fiberRef.current.payInvoice(invoice, PAYMENT_OPTIONS);
      } catch (cause) {
        throw new Error(readable(cause, "The payment didn't go through. Your balance is unchanged."));
      }
      await loadPayments().catch(() => undefined);
    },
    createInvoice: async (amount, description) => {
      const result = await fiberRef.current.createInvoice({ amount: toHex(amount), currency: "Fibt", description: description || undefined, expiry: toHex(INVOICE_EXPIRY_SECONDS) });
      receiving.current.set(result.invoice.data.payment_hash, amount);
      return { address: result.invoice_address, amount, description: description || undefined, createdAt: Date.now(), paymentHash: result.invoice.data.payment_hash };
    },
    sendCkb: async (address, amount) => {
      const signer = requireSigner(signerRef.current);
      const to = await ccc.Address.fromString(address, signer.client).catch(() => { throw new Error("Enter a valid CKB testnet address"); });
      const transaction = ccc.Transaction.from({ outputs: [{ lock: to.script, capacity: amount }] });
      await transaction.completeInputsByCapacity(signer);
      await transaction.completeFeeBy(signer);
      const hash = await signer.sendTransaction(transaction);
      await refreshBalanceRef.current().catch(() => undefined);
      return hash;
    },
    signMessage: async (message) => {
      const signer = requireSigner(signerRef.current);
      const signature = await signer.signMessage(message);
      return { signature: signature.signature, verified: await signer.verifyMessage(message, signature) };
    },
    enableRecovery: async () => {
      const current = requireRecovery(recoveryRef.current);
      await current.enable([await current.createEvmBackup()]);
      await refreshBalanceRef.current().catch(() => undefined);
    },
    addEvmBackup: async () => {
      const current = requireRecovery(recoveryRef.current);
      await current.addBackup(await current.createEvmBackup());
    },
    removeBackup: async (backup) => { await requireRecovery(recoveryRef.current).removeBackup(backup); },
    getEmailThreshold: async () => (await requireSigner(signerRef.current).getDailyConfirmationAmounts()).ckb ?? null,
    setEmailThreshold: (shannons) => requireSigner(signerRef.current).setDailyConfirmationAmount("ckb", shannons),
    invoiceStatus: async (paymentHash) => {
      const { status } = await fiberRef.current.getInvoice({ payment_hash: paymentHash as `0x${string}` });
      const amount = receiving.current.get(paymentHash);
      if (status === "Paid" && amount !== undefined) {
        receiving.current.delete(paymentHash);
        setActivity((current) => [...current, { id: `received-${paymentHash}`, kind: "received", amount, unit: CKB, at: Date.now() }]);
        void fiberRef.current.refreshChannels().catch(() => undefined);
      }
      return status;
    },
  }), [login, logout, resetEvents, setMode, loadPayments]);

  const channels: DemoChannel[] = fiber.channels.map((channel) => ({
    id: channel.id,
    peer: channel.peer,
    status: channel.status,
    local: channel.canSend,
    remote: channel.canReceive,
    reserved: reserved[channel.id],
    fundingTx: fundingOutpoint(channel.raw.channel_outpoint)?.txHash,
    unit: channelUnit(channel.raw),
  }));
  const error = fiber.error ? toKeyWayError(fiber.error) : undefined;

  const model: DemoModel = {
    nodeMode,
    auth: !ready ? "loading" : authenticated ? "signedIn" : "signedOut",
    account: account.status === "ready" ? "ready" : account.status === "error" ? "error" : "loading",
    accountError: account.status === "error" ? readable(account.error, "KeyWay couldn't finish setting up this account.") : undefined,
    address: account.address,
    balance: account.balance,
    fiber: fiber.status,
    fiberError: error ? { code: error.code, message: readable(error, "The Fiber node didn't start.") } : undefined,
    walletRecovery,
    events,
    failedAt,
    channels,
    activity: [...activity, ...payments],
    recovery: recovery && { status: recovery.status, backups: recovery.backups, legacyAddress: recovery.legacyAddress },
  };
  return <DemoView model={model} actions={actions} />;
}

/** Uses the SDK's friendly wording; long or garbled server text is replaced by a plain sentence. */
function readable(cause: unknown, fallback: string): string {
  const raw = cause instanceof Error ? cause.message : typeof cause === "string" ? cause : "";
  if (!raw) return fallback;
  const friendly = friendlyKeyWayError(raw);
  if (friendly !== raw) return friendly;
  return raw.length > 160 || /[\u001b\n]|\[[0-9;]*m/.test(raw) ? fallback : raw;
}

/** CKB, or the channel's token: named when the demo knows it, otherwise by the start of its hash. */
function channelUnit(channel: { funding_udt_type_script?: { code_hash: string; hash_type: string; args: string } | null }): Unit {
  const script = channel.funding_udt_type_script;
  if (!script) return CKB;
  const hash = ccc.Script.from({ codeHash: script.code_hash, hashType: script.hash_type as ccc.HashType, args: script.args }).hash();
  return TOKENS[hash] ?? { symbol: `token ${hash.slice(0, 8)}…`, decimals: 0 };
}

/**
 * Fiber serializes a channel outpoint either as { tx_hash, index } or as 36 molecule bytes:
 * the 32-byte transaction hash followed by a little-endian u32 index.
 */
function fundingOutpoint(value: unknown): { txHash: string; index: number } | undefined {
  if (typeof value === "string") {
    const hex = value.replace(/^0x/i, "");
    if (/^[0-9a-f]{72}$/i.test(hex)) {
      const index = Number.parseInt(hex.slice(64).match(/../g)!.reverse().join(""), 16);
      return { txHash: `0x${hex.slice(0, 64)}`, index };
    }
    return undefined;
  }
  if (value && typeof value === "object" && "tx_hash" in value && "index" in value) {
    const { tx_hash: txHash, index } = value as { tx_hash: string; index: string | number };
    return { txHash, index: Number(index) };
  }
  return undefined;
}

/**
 * The reserve is whatever the funding cell holds beyond the two spendable balances and in-flight TLCs.
 * It is read from the channel's funding cell on CKB testnet.
 */
function useChannelReserves(channels: KeyWayChannel[]): Record<string, bigint> {
  const [capacities, setCapacities] = useState<Record<string, bigint>>({});
  const client = useMemo(() => new ccc.ClientPublicTestnet(), []);
  const outpoints = channels.flatMap((channel) => {
    const outpoint = fundingOutpoint(channel.raw.channel_outpoint);
    return outpoint ? [[channel.id, outpoint] as const] : [];
  });
  const key = outpoints.map(([id]) => id).join(",");

  useEffect(() => {
    let cancelled = false;
    for (const [id, outpoint] of outpoints) {
      if (capacities[id] !== undefined) continue;
      void client.getCell({ txHash: outpoint.txHash, index: outpoint.index })
        .then((cell) => { if (!cancelled && cell) setCapacities((current) => ({ ...current, [id]: cell.cellOutput.capacity })); })
        .catch(() => undefined);
    }
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, client]);

  const reserves: Record<string, bigint> = {};
  for (const channel of channels) {
    const capacity = capacities[channel.id];
    if (capacity === undefined) continue;
    const inFlight = BigInt(channel.raw.offered_tlc_balance) + BigInt(channel.raw.received_tlc_balance);
    const rest = capacity - channel.capacity - inFlight;
    reserves[channel.id] = rest > 0n ? rest : 0n;
  }
  return reserves;
}

function requireSigner<T>(signer: T | undefined): T {
  if (!signer) throw new Error("Your account is still being prepared. Try again in a moment.");
  return signer;
}

function requireRecovery(recovery: RecoveryApi | undefined): RecoveryApi {
  if (!recovery) throw new Error("This KeyWay SDK doesn't support account recovery yet");
  return recovery;
}

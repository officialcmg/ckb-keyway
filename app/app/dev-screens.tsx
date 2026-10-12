"use client";

/**
 * DEVELOPMENT ONLY. Renders the demo in each designed state with the boards' example data so it can be
 * compared with the design canvas (`/app?screen=channel`). It is loaded only when NODE_ENV is not
 * "production", so none of this reaches the deployed site.
 */
import { useRouter } from "next/navigation";
import { DemoView, type CreatedInvoice, type DemoActions, type DemoModel, type DemoUi, type LifecycleEvent, type NodeMode } from "./demo-view";

const ADDRESS = "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqfdlq4x9etd0uj4xnpxzguymra6k6cz5kqg5uk4g";
const CKB = 100_000_000n;
const T0 = new Date(2026, 9, 11, 12, 39, 2).getTime();
const at = (offsetMs: number) => T0 + offsetMs;

const CONNECTED: LifecycleEvent[] = [
  { stage: "recovering_identity", at: at(0), elapsedMs: 0 },
  { stage: "starting_managed", at: at(418), elapsedMs: 418 },
  { stage: "synchronizing", at: at(6118), elapsedMs: 6118 },
  { stage: "ready", at: at(7018), elapsedMs: 7018 },
];

const RECEIVE: CreatedInvoice = {
  address: "fibt500000000001pcsaug0p0exgfw0pnm6vkkya5ul6wxurhh09qf9tuwwaufqnr3uzwpplg",
  amount: 5n * CKB,
  description: "Order #1042",
  createdAt: new Date(2026, 9, 11, 12, 47).getTime(),
  paymentHash: "0x00",
};

function fixture(screen: string, nodeMode: NodeMode): { model: DemoModel; ui?: DemoUi } {
  const base: DemoModel = {
    nodeMode, auth: "signedIn", account: "ready", address: ADDRESS, balance: 10_000n * CKB,
    fiber: "disconnected", events: [], channels: [], activity: [],
  };
  const channel = {
    ...base,
    balance: 899_999n * CKB / 100n,
    fiber: "connected" as const,
    events: CONNECTED,
    channels: [{ id: "0x1", peer: "0x02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71", status: "ready" as const, local: 803n * CKB, remote: 151n * CKB, reserved: 98n * CKB, fundingTx: "0x6cbe00000000000000000000000000000000000000000000000000000000c319" }],
    activity: [
      { id: "a", kind: "received" as const, amount: 1n * CKB, at: new Date(2026, 9, 11, 12, 46).getTime() },
      { id: "b", kind: "paid" as const, amount: 1n * CKB, at: new Date(2026, 9, 11, 12, 44).getTime() },
      { id: "c", kind: "opened" as const, amount: 1000n * CKB, at: new Date(2026, 9, 11, 12, 39).getTime() },
    ],
  };
  switch (screen) {
    case "signedout": return { model: { ...base, auth: "signedOut", address: undefined, balance: undefined } };
    case "recovering": return { model: { ...base, account: "recovering", address: undefined, balance: undefined, walletRecovery: { at: new Date(2026, 9, 11, 12, 38, 41).getTime() } } };
    case "empty": return { model: { ...base, balance: 0n, walletRecovery: { at: new Date(2026, 9, 11, 12, 38, 41).getTime(), durationMs: 412 } } };
    case "connecting": return { model: { ...base, fiber: "connecting", events: CONNECTED.slice(0, 2), clock: at(3518) } };
    case "error": return { model: { ...base, fiber: "error", events: CONNECTED.slice(0, 2), failedAt: at(25_418), fiberError: { code: "PEER_OFFLINE", message: "Your node started, but bottle.fiber.channel didn't answer within 25 seconds." } } };
    case "noChannels": return { model: { ...base, fiber: "connected", events: CONNECTED } };
    case "funding": return { model: { ...base, fiber: "connected", events: CONNECTED }, ui: { activation: "confirming" } };
    case "pay": return { model: channel, ui: { dialog: "pay", invoice: "fibt100000000001pcsaug0p0exgfw0pnm6vk0rnt4xefskmrz0g2vqhe4l3gr9a7hzkm8a" } };
    case "receive": return { model: channel, ui: { dialog: "receive", created: RECEIVE } };
    default: return { model: channel };
  }
}

const noop = async () => undefined;

export function DevScreen({ screen, nodeMode }: { screen: string; nodeMode: NodeMode }) {
  const router = useRouter();
  const { model, ui } = fixture(screen, nodeMode);
  const actions: DemoActions = {
    login: () => undefined,
    logout: noop,
    setMode: (mode) => router.push(`/app?screen=${screen}${mode === "browser" ? "&mode=browser" : ""}`),
    connect: noop,
    openChannel: noop,
    closeChannel: noop,
    checkInvoice: async () => ({ amount: 1n * CKB, description: "Coffee, Bottle Café", fee: CKB / 1000n }),
    pay: noop,
    createInvoice: async () => RECEIVE,
    invoiceStatus: async () => "Open",
    sendCkb: async () => "0x00",
    signMessage: async () => ({ signature: "0x00", verified: true }),
    getEmailThreshold: async () => null,
    setEmailThreshold: noop,
  };
  return (
    <>
      <DemoView model={model} actions={actions} initialUi={ui} />
      {screen === "funding" && <div className="scrim" role="presentation" aria-label="The SDK's funding dialog appears here" />}
    </>
  );
}

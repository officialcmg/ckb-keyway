"use client";

/**
 * DEVELOPMENT ONLY. Renders each SDK dialog with example data, one per `?scene=`, so its states can be
 * checked and screenshotted (`research/ui-audit`). Loaded only when NODE_ENV is not "production".
 */
import { useState, type ReactNode } from "react";
import type { KeyWayApiClient } from "@/src/sdk/browser/api-client";
import type { TransactionPreview } from "@/src/sdk/browser/keyway-signer";
import type { RecoveryPreview, BackupChangePreview } from "@/src/sdk/browser/account-recovery";
import type { FiberChannelOpenPreview } from "@/src/sdk/browser/remote-ckb-signer";
import { KeyWayLoginModal } from "@/src/sdk/react/keyway-provider";
import {
  KeyWayBackupChangeModal,
  KeyWayFundingModal,
  KeyWayChannelCloseModal,
  KeyWayChannelSettingsModal,
  KeyWayEmailCodeModal,
  KeyWayMessageModal,
  KeyWayPeerModal,
  KeyWayRecoveryModal,
  KeyWayTransactionModal,
} from "@/src/sdk/react/signing-modals";

type Theme = "light" | "dark";

const ADDRESS = "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqfdlq4x9etd0uj4xnpxzguymra6k6cz5kqg5uk4g";
const PEER = "0x02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71";
const RUSD = "0x45b32a2bc4285d0a09678eb11960ddc8707bc2779887a09d482e9bfe9a2cdf52";
const HASH = "0x6cbe1a52f0e0d7a6c1b2f3e4d5c6b7a8998877665544332211aabbccddeec319";
const never = () => new Promise<never>(() => undefined);
const later = <T,>(value: T, ms = 600) => new Promise<T>((resolve) => setTimeout(() => resolve(value), ms));
const fail = (message: string, ms = 600) => new Promise<never>((_, reject) => setTimeout(() => reject(new Error(message)), ms));
const ignore = () => undefined;

const TRANSACTION: TransactionPreview = {
  network: "CKB testnet",
  sendingCkb: "0",
  receivingCkb: "0",
  feeCkb: "0.00001432",
  tokens: [{ id: "0x45b32a…df52", asset: RUSD, standard: "xUDT", amount: "-2500000000", amountText: "-25 RUSD" }],
  nfts: [],
  dao: [],
  recipients: [{ address: ADDRESS.replace("zda0", "zdb1"), kind: "wallet", walletType: "standard", ckb: "143", tokens: [{ id: "0x45b32a…df52", asset: RUSD, amount: "2500000000", amountText: "25 RUSD" }], nfts: [] }],
  unrecognized: [],
  otherSigners: 0,
  details: {
    inputs: [{ lock: "you", type: "xUDT", capacityCkb: "143", dataBytes: 16 }, { lock: "you", capacityCkb: "9,000", dataBytes: 0 }],
    outputs: [{ lock: `0x9f2c41${"3".repeat(52)}b0c47a1e`, type: "xUDT", capacityCkb: "143", dataBytes: 16 }, { lock: "you", capacityCkb: "8,999.99998568", dataBytes: 0 }],
  },
  transactionHash: HASH,
  requiresEmailCode: true,
};

const UNKNOWN_TOKEN: TransactionPreview = {
  ...TRANSACTION,
  tokens: [{ id: "0x9a1f03…77c2", asset: `0x9a1f03${"5".repeat(52)}c0de77c2`, standard: "xUDT", amount: "-1000", amountText: `-1000 of token 0x9a1f03${"5".repeat(52)}c0de77c2` }],
  recipients: [{ ...TRANSACTION.recipients[0], tokens: [{ id: "0x9a1f03…77c2", asset: `0x9a1f03${"5".repeat(52)}c0de77c2`, amount: "1000", amountText: `1000 of token 0x9a1f03${"5".repeat(52)}c0de77c2` }] }],
};

const CKB_TRANSACTION: TransactionPreview = {
  ...TRANSACTION,
  sendingCkb: "1,250",
  tokens: [],
  recipients: [{ address: ADDRESS.replace("zda0", "zdb1"), kind: "wallet", walletType: "standard", ckb: "1,250", tokens: [], nfts: [] }],
  requiresEmailCode: false,
};

const RECOVERY: RecoveryPreview = {
  network: "CKB testnet",
  newAddress: "ckt1qrejnmlar3r452tcg57gvq8patctcgy8acync0hxfnyka35ywafvkqgqqywhsqz6a9nuq7n78x78eqrnwzsj37faqxrn7dq20dqufhj5gwyme9azeu9hjf6c4fyrhs5qhgasjkf2vj44ypl035x",
  legacyAddress: ADDRESS,
  backups: [{ kind: "evm", address: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", label: "EVM wallet 0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed" }],
  adminListCkb: "165",
  minimumCellCkb: "61",
  tokenCellsExtraCkb: "0",
  lockedCkb: "165",
  feeCkb: "0.00002",
  movedCkb: "9,834.99998",
  tokens: [],
  cellsLeft: 0,
  transactionHash: HASH,
} as RecoveryPreview;

const BACKUP: BackupChangePreview = {
  network: "CKB testnet",
  change: "add",
  backup: { kind: "evm", address: "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", label: "EVM wallet 0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359" },
  backups: [
    { kind: "evm", address: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", label: "EVM wallet 0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed" },
    { kind: "evm", address: "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", label: "EVM wallet 0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359" },
  ],
  feeCkb: "0.00001",
  transactionHash: HASH,
};

const FUNDING: FiberChannelOpenPreview = {
  amountCkb: "1,000",
  feeCkb: "0.00001",
  destination: ADDRESS,
  transactionHash: HASH,
  peer: PEER,
  feeReserveCkb: "62",
};

/** A login API that never reaches KeyWay: the code step opens at once, and "000000" is the wrong code. */
function loginApi(verify: "ok" | "slow"): KeyWayApiClient {
  return {
    sendCode: () => later({ challengeId: "challenge" }, 150),
    verifyCode: (_id: string, code: string) => verify === "slow" ? never()
      : code === "000000" ? fail("Incorrect or expired code", 300)
      : later({ sessionToken: "token", user: { id: "user" }, expiresAt: new Date(Date.now() + 3600_000).toISOString() }, 300),
  } as unknown as KeyWayApiClient;
}

const SENT_TO = "ana@acmepay.example";
const EXPIRED = "This request expired. Start again.";
const BUSY = { busy: true };
const FAILED = { failure: "The Lit signature service is temporarily unavailable. Try again in a moment." };

function scenes(theme: Theme): Record<string, ReactNode> {
  const common = { theme, appName: "Acme Pay", answer: ignore };
  const close = { channelId: "0x1", peer: PEER, asset: "ckb", returning: "80300000000", returningText: "803 CKB", force: false, network: "CKB testnet" as const };
  const settings = { channelId: "0x1", peer: PEER, asset: "ckb", changes: [
    { setting: "enabled" as const, from: "true", to: "false" },
    { setting: "tlc_expiry_delta" as const, from: "0x5265c00", to: "0x2932e00" },
    { setting: "tlc_minimum_value" as const, from: "0x0", to: "0x5f5e100" },
    { setting: "tlc_fee_proportional_millionths" as const, from: "0x3e8", to: "0x7d0" },
  ] };
  const code = (props: Partial<Parameters<typeof KeyWayEmailCodeModal>[0]>) => (
    <KeyWayEmailCodeModal theme={theme} reason="transaction" sentTo={SENT_TO} resend={() => later(undefined, 200)} verify={() => never()} answer={ignore} {...props} />
  );
  const approval = (name: string, render: (step?: { busy?: boolean; failure?: string }) => ReactNode) => ({
    [name]: render(), [`${name}-busy`]: render(BUSY), [`${name}-failed`]: render(FAILED),
  });
  return {
    ...approval("transaction", (step) => <KeyWayTransactionModal {...common} preview={TRANSACTION} step={step} />),
    "transaction-ckb": <KeyWayTransactionModal {...common} preview={CKB_TRANSACTION} />,
    "transaction-unknown-token": <KeyWayTransactionModal {...common} preview={UNKNOWN_TOKEN} />,
    ...approval("message", (step) => <KeyWayMessageModal {...common} preview={{ message: "Sign in to Acme Pay\nNonce: 8f3a2c" }} step={step} />),
    "code": code({}),
    "code-checking": code({}),
    "code-wrong": code({ verify: () => fail("That email code isn't right", 300) }),
    "code-success": code({ verify: () => later(undefined, 50) }),
    "code-expired": code({ verify: () => fail(EXPIRED, 300) }),
    "code-resent": code({}),
    "code-resend-error": code({ resend: () => fail("Too many codes sent. Try again in 7 minutes", 200) }),
    "code-settings-no-address": code({ reason: "settings", sentTo: undefined }),
    ...approval("close", (step) => <KeyWayChannelCloseModal {...common} preview={close} step={step} />),
    "close-force": <KeyWayChannelCloseModal {...common} preview={{ ...close, force: true }} />,
    "close-force-browser": <KeyWayChannelCloseModal {...common} fiberNode="browser" preview={{ ...close, force: true }} />,
    ...approval("peer", (step) => <KeyWayPeerModal {...common} preview={{ action: "disconnect", pubkey: PEER, openChannels: 1 }} step={step} />),
    ...approval("settings", (step) => <KeyWayChannelSettingsModal {...common} preview={settings} step={step} />),
    "settings-token": <KeyWayChannelSettingsModal {...common} preview={{ ...settings, asset: RUSD, changes: [{ setting: "tlc_minimum_value", from: "0x0", to: "0x2faf080" }] }} />,
    ...approval("recovery", (step) => <KeyWayRecoveryModal {...common} preview={RECOVERY} step={step} />),
    ...approval("backup", (step) => <KeyWayBackupChangeModal {...common} preview={BACKUP} step={step} />),
    ...approval("funding", (step) => <KeyWayFundingModal {...common} preview={FUNDING} step={step} />),
    "login": <KeyWayLoginModal api={loginApi("ok")} appName="Acme Pay" theme={theme} close={ignore} authenticated={ignore} />,
    "login-code": <KeyWayLoginModal api={loginApi("ok")} appName="Acme Pay" theme={theme} close={ignore} authenticated={ignore} />,
    "login-slow": <KeyWayLoginModal api={loginApi("slow")} appName="Acme Pay" theme={theme} close={ignore} authenticated={ignore} />,
    "login-wrong": <KeyWayLoginModal api={loginApi("ok")} appName="Acme Pay" theme={theme} close={ignore} authenticated={ignore} />,
    "login-success": <KeyWayLoginModal api={loginApi("ok")} appName="Acme Pay" theme={theme} close={ignore} authenticated={ignore} />,
    "login-resent": <KeyWayLoginModal api={loginApi("ok")} appName="Acme Pay" theme={theme} close={ignore} authenticated={ignore} />,
  };
}

/** A transaction from the app's button through approval, the busy step and the code, to check focus comes back. */
function Flow({ theme }: { theme: Theme }) {
  const [stage, setStage] = useState<"none" | "approve" | "busy" | "code">("none");
  return (
    <>
      <p><button type="button" id="flow-open" onClick={() => setStage("approve")}>Send 25 RUSD</button></p>
      {stage === "approve" || stage === "busy" ? (
        <KeyWayTransactionModal theme={theme} appName="Acme Pay" preview={TRANSACTION} step={stage === "busy" ? BUSY : undefined} answer={(approved) => {
          if (!approved) return setStage("none");
          setStage("busy");
          setTimeout(() => setStage("code"), 400);
        }} />
      ) : null}
      {stage === "code" ? <KeyWayEmailCodeModal theme={theme} reason="transaction" sentTo={SENT_TO} resend={() => later(undefined, 200)} verify={() => later(undefined, 200)} answer={() => setStage("none")} /> : null}
    </>
  );
}

export function Gallery({ scene, theme }: { scene?: string; theme: Theme }) {
  const all = scenes(theme);
  const shown = scene ? all[scene] : undefined;
  return (
    <div style={{ minHeight: "100vh", padding: 24, background: theme === "dark" ? "#09090b" : "#f8fafc", color: theme === "dark" ? "#fafafa" : "#111827", fontFamily: "ui-sans-serif, sans-serif" }}>
      <h1 style={{ fontSize: 18 }}>SDK dialogs</h1>
      <p><button type="button" id="page-behind">A button on the page behind</button></p>
      <ul>
        {Object.keys(all).map((name) => <li key={name}><a data-scene={name} href={`?scene=${name}&theme=${theme}`} style={{ color: "inherit" }}>{name}</a></li>)}
      </ul>
      {scene === "flow" ? <Flow theme={theme} /> : shown}
    </div>
  );
}

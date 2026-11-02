"use client";

/**
 * DEVELOPMENT ONLY. Renders each SDK dialog with example data, one per `?scene=`, so its states can be
 * checked and screenshotted (`research/ui-audit`). Loaded only when NODE_ENV is not "production".
 */
import type { ReactNode } from "react";
import type { KeyWayApiClient } from "@/src/sdk/browser/api-client";
import type { TransactionPreview } from "@/src/sdk/browser/keyway-signer";
import type { RecoveryPreview, BackupChangePreview } from "@/src/sdk/browser/account-recovery";
import type { FiberChannelOpenPreview } from "@/src/sdk/browser/remote-ckb-signer";
import { KeyWayFundingModal, KeyWayLoginModal } from "@/src/sdk/react/keyway-provider";
import {
  KeyWayBackupChangeModal,
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
  tokens: [{ id: "0x45b32a…df52", standard: "xUDT", amount: "-2500000000", amountText: "-25 RUSD" }],
  nfts: [],
  dao: [],
  recipients: [{ address: ADDRESS.replace("zda0", "zdb1"), kind: "wallet", walletType: "standard", ckb: "143", tokens: [{ id: "0x45b32a…df52", amount: "2500000000" }], nfts: [] }],
  unrecognized: [],
  otherSigners: 0,
  details: {
    inputs: [{ lock: "you", type: "xUDT 0x45b32a…df52", capacityCkb: "143", dataBytes: 16 }, { lock: "you", capacityCkb: "9,000", dataBytes: 0 }],
    outputs: [{ lock: "0x9f2c41…7a1e", type: "xUDT 0x45b32a…df52", capacityCkb: "143", dataBytes: 16 }, { lock: "you", capacityCkb: "8,999.99998568", dataBytes: 0 }],
  },
  transactionHash: HASH,
  requiresEmailCode: true,
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
  backups: [{ kind: "evm", address: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", label: "EVM wallet 0x5aAeb6…BeAed" }],
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
  backup: { kind: "evm", address: "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", label: "EVM wallet 0xfB6916…5d359" },
  backups: [
    { kind: "evm", address: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", label: "EVM wallet 0x5aAeb6…BeAed" },
    { kind: "evm", address: "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", label: "EVM wallet 0xfB6916…5d359" },
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
function loginApi(verify: "ok" | "wrong" | "slow"): KeyWayApiClient {
  return {
    sendCode: () => later({ challengeId: "challenge" }, 200),
    verifyCode: (_id: string, code: string) => verify === "slow" ? never()
      : verify === "wrong" || code === "000000" ? fail("Invalid OTP")
      : later({ sessionToken: "token", user: { id: "user" }, expiresAt: new Date(Date.now() + 3600_000).toISOString() }),
  } as unknown as KeyWayApiClient;
}

function scenes(theme: Theme): Record<string, ReactNode> {
  const common = { theme, appName: "Acme Pay" };
  return {
    "transaction": <KeyWayTransactionModal {...common} preview={TRANSACTION} answer={ignore} />,
    "transaction-ckb": <KeyWayTransactionModal {...common} preview={CKB_TRANSACTION} answer={ignore} />,
    "message": <KeyWayMessageModal {...common} preview={{ message: "Sign in to Acme Pay\nNonce: 8f3a2c" }} answer={ignore} />,
    "code": <KeyWayEmailCodeModal theme={theme} reason="transaction" resend={() => later(undefined)} answer={ignore} />,
    "code-error": <KeyWayEmailCodeModal theme={theme} reason="transaction" error="That email code isn't right" resend={() => later(undefined)} answer={ignore} />,
    "code-resend-error": <KeyWayEmailCodeModal theme={theme} reason="transaction" resend={() => fail("Too many signing requests. Try again in 412 seconds")} answer={ignore} />,
    "close": <KeyWayChannelCloseModal {...common} preview={{ channelId: "0x1", peer: PEER, asset: "ckb", returning: "80300000000", returningText: "803 CKB", force: false, network: "CKB testnet" }} answer={ignore} />,
    "close-force": <KeyWayChannelCloseModal {...common} preview={{ channelId: "0x1", peer: PEER, asset: "ckb", returning: "80300000000", returningText: "803 CKB", force: true, network: "CKB testnet" }} answer={ignore} />,
    "peer": <KeyWayPeerModal {...common} preview={{ action: "disconnect", pubkey: PEER, openChannels: 1 }} answer={ignore} />,
    "settings": <KeyWayChannelSettingsModal {...common} preview={{ channelId: "0x1", peer: PEER, changes: [
      { setting: "tlc_expiry_delta", from: "0x5265c00", to: "0x2932e00" },
      { setting: "tlc_minimum_value", from: "0x0", to: "0x5f5e100" },
      { setting: "tlc_fee_proportional_millionths", from: "0x3e8", to: "0x7d0" },
    ] }} answer={ignore} />,
    "recovery": <KeyWayRecoveryModal {...common} preview={RECOVERY} answer={ignore} />,
    "backup": <KeyWayBackupChangeModal {...common} preview={BACKUP} answer={ignore} />,
    "funding": <KeyWayFundingModal theme={theme} preview={FUNDING} answer={ignore} />,
    "login": <KeyWayLoginModal api={loginApi("ok")} appName="Acme Pay" theme={theme} close={ignore} authenticated={ignore} />,
    "login-wrong": <KeyWayLoginModal api={loginApi("wrong")} appName="Acme Pay" theme={theme} close={ignore} authenticated={ignore} />,
    "login-slow": <KeyWayLoginModal api={loginApi("slow")} appName="Acme Pay" theme={theme} close={ignore} authenticated={ignore} />,
  };
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
      {shown}
    </div>
  );
}

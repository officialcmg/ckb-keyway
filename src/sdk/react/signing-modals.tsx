"use client";

import { useEffect, useRef, useState, type CSSProperties } from "react";
import * as ccc from "@ckb-ccc/core";
import type { BackupChangePreview, RecoveryPreview } from "../browser/account-recovery";
import { canRetryCode, isRequestExpired, type EmailCodeReason } from "../browser/email-code";
import type { MessagePreview, TransactionPreview } from "../browser/keyway-signer";
import type { FiberChannelClosePreview, FiberChannelSettingsPreview, FiberPeerPreview } from "../browser/fiber-actions";
import type { FiberChannelOpenPreview } from "../browser/remote-ckb-signer";
import type { SendLimitOffer } from "../browser/send-limits";
import { formatAsset } from "../browser/tokens";
import { Actions, CodeInput, errorNote, ResendLine, Row, Shell, StatusLine, type ApprovalStep, type Theme } from "./dialog";
import {
  fundingDetails,
  modalActions,
  modalButton,
  modalCopy,
  modalEyebrow,
  modalInput,
  modalLabel,
  modalPrimaryButton,
  modalTitle,
  type ModalPalette,
} from "./modal-styles";

export type { ApprovalStep } from "./dialog";

const note = (palette: ModalPalette): CSSProperties => ({ ...modalCopy, margin: "0 auto 8px", color: palette.muted, fontSize: 13 });
const details: CSSProperties = { textAlign: "left", fontSize: 12, margin: "8px 0 0" };
const detailLine: CSSProperties = { margin: "8px 0 0", fontFamily: "ui-monospace, monospace", overflowWrap: "anywhere" };

/** Escape cancels; while the approved step runs it only hides the dialog, like Close. */
const escape = (_step: ApprovalStep | undefined, answer: (approved: boolean) => void) => () => answer(false);

type ApprovalProps<P> = { theme: Theme; appName: string; preview: P; step?: ApprovalStep; answer: (approved: boolean) => void };

/** A token's change for people: "25 RUSD", or the raw amount with the token's whole ID when KeyWay can't name it. */
function tokenText(token: TransactionPreview["tokens"][number]): string {
  const raw = BigInt(token.amount.replace(/^\+/, ""));
  const size = raw < 0n ? -raw : raw;
  return formatAsset(size, token.asset);
}

/** The built-in approval dialog for a transaction, drawn from the backend's decoding of its effects. */
export function KeyWayTransactionModal({ theme, appName, preview, step, answer }: ApprovalProps<TransactionPreview>) {
  const sending = preview.sendingCkb !== "0";
  // A token leaving is the point of the transaction; the CKB that travels inside its cell is secondary.
  const tokenOut = preview.tokens.find((token) => token.amount.startsWith("-"));
  const title = tokenOut ? `Send ${tokenText(tokenOut)}?` : sending ? `Send ${preview.sendingCkb} CKB?` : "Approve this transaction?";
  return (
    <Shell theme={theme} labelId="keyway-transaction-title" onEscape={escape(step, answer)}>
      {(palette) => (
        <>
          <p style={{ ...modalEyebrow, color: palette.muted }}>{appName} · APPROVE TRANSACTION</p>
          <h2 id="keyway-transaction-title" style={modalTitle}>{title}</h2>
          {preview.unrecognized.length > 0 && (
            <p role="alert" style={errorNote(palette)}>
              This transaction uses {preview.unrecognized.length === 1 ? "a script" : "scripts"} KeyWay doesn&apos;t recognize ({preview.unrecognized.map((item) => `${item.codeHash} (${item.hashType}), ${item.cells} cell${item.cells === 1 ? "" : "s"}`).join("; ")}). Only approve it if you trust {appName}.
            </p>
          )}
          <dl style={{ ...fundingDetails, margin: "16px 0" }}>
            {sending && <Row palette={palette} label="You send" value={`${preview.sendingCkb} CKB`} />}
            {preview.receivingCkb !== "0" && <Row palette={palette} label="You receive" value={`${preview.receivingCkb} CKB`} />}
            {preview.tokens.map((token) => <Row key={`t-${token.asset}`} palette={palette} label={token.amount.startsWith("-") ? "You send" : "You receive"} value={tokenText(token)} />)}
            {preview.nfts.map((nft, index) => <Row key={`n-${index}`} palette={palette} label={`${nft.kind} ${nft.change}`} value={nft.id} />)}
            {preview.dao.map((action, index) => <Row key={`d-${index}`} palette={palette} label={`Nervos DAO ${action.action}`} value={`${action.amountCkb} CKB`} />)}
            {preview.recipients.map((recipient) => (
              <Row
                key={recipient.address}
                palette={palette}
                label={<>To {recipient.kind === "wallet" ? `${recipient.walletType ?? "standard"} wallet` : recipient.kind}</>}
                value={<>
                  {/* The whole address: two look-alike addresses can share their start and their checksum. */}
                  {recipient.address}
                  <span style={{ display: "block", color: palette.muted }}>
                    {[`${recipient.ckb} CKB`, ...recipient.tokens.map((token) => formatAsset(BigInt(token.amount), token.asset)), ...recipient.nfts].join(" · ")}
                  </span>
                </>}
              />
            ))}
            <Row palette={palette} label="Network fee" value={`${preview.feeCkb} CKB`} />
            <Row palette={palette} label="Network" value={preview.network} mono={false} />
          </dl>
          {preview.otherSigners > 0 && <p style={note(palette)}>{preview.otherSigners} input{preview.otherSigners === 1 ? "" : "s"} belong to someone else, who must sign too.</p>}
          {preview.requiresEmailCode && !step?.failure && <p style={note(palette)}>This reaches your email confirmation amount, so we&apos;ll email you a code next.</p>}
          <details style={{ ...details, color: palette.muted }}>
            <summary style={{ cursor: "pointer" }}>Details</summary>
            {preview.tokens.map((token) => <p key={`d-${token.asset}`} style={detailLine}>Token {token.asset} ({token.standard}) {token.amount}</p>)}
            {preview.recipients.map((recipient) => <p key={`r-${recipient.address}`} style={detailLine}>To {recipient.address}</p>)}
            <CellList title="Inputs" cells={preview.details.inputs} />
            <CellList title="Outputs" cells={preview.details.outputs} />
            <p style={detailLine}>Transaction {preview.transactionHash}</p>
          </details>
          <Actions palette={palette} confirm="Approve" busyLabel={preview.requiresEmailCode ? "Sending code…" : "Signing…"} step={step} answer={answer} />
        </>
      )}
    </Shell>
  );
}

function CellList({ title, cells }: { title: string; cells: TransactionPreview["details"]["inputs"] }) {
  return (
    <div style={{ marginTop: 8 }}>
      <p style={{ margin: "0 0 4px", fontWeight: 700 }}>{title}</p>
      <ol style={{ margin: 0, paddingLeft: 18, fontFamily: "ui-monospace, monospace", lineHeight: 1.6, overflowWrap: "anywhere" }}>
        {cells.map((cell, index) => <li key={index}>{cell.capacityCkb} CKB · lock {cell.lock}{cell.type ? ` · type ${cell.type}` : ""}{cell.dataBytes ? ` · ${cell.dataBytes} B data` : ""}</li>)}
      </ol>
    </div>
  );
}

/** The built-in approval dialog for signing a message, which shows the exact text. */
export function KeyWayMessageModal({ theme, appName, preview, step, answer }: ApprovalProps<MessagePreview>) {
  return (
    <Shell theme={theme} labelId="keyway-message-title" onEscape={escape(step, answer)}>
      {(palette) => (
        <>
          <p style={{ ...modalEyebrow, color: palette.muted }}>{appName} · SIGN A MESSAGE</p>
          <h2 id="keyway-message-title" style={modalTitle}>Sign this message?</h2>
          <pre style={{ margin: "16px 0", padding: 14, maxHeight: 220, overflow: "auto", borderRadius: 12, background: palette.surface, border: `1px solid ${palette.border}`, textAlign: "left", whiteSpace: "pre-wrap", overflowWrap: "anywhere", fontFamily: "ui-monospace, monospace", fontSize: 13 }}>{preview.message}</pre>
          <p style={note(palette)}>Signing proves you control this account. It doesn&apos;t move any funds.</p>
          <Actions palette={palette} confirm="Sign" busyLabel="Signing…" step={step} answer={answer} />
        </>
      )}
    </Shell>
  );
}

const CODE_PURPOSE: Record<EmailCodeReason, string> = {
  transaction: "this transaction",
  payment: "this payment",
  recovery: "turning on recovery",
  "recovery-backup": "this backup change",
  settings: "this security change",
};

/**
 * Asks for the code KeyWay emailed the user. Always drawn by the SDK, even when an app brings its own approval
 * UI. With `verify`, it stays open while KeyWay checks each code and shows a wrong one in place.
 */
export function KeyWayEmailCodeModal({ theme, reason, error, sentTo, codeLength = 6, resend, verify, answer }: {
  theme: Theme;
  reason: EmailCodeReason;
  error?: string;
  sentTo?: string;
  codeLength?: 6 | 8;
  resend: () => Promise<void>;
  verify?: (code: string) => Promise<void>;
  answer: (code: string | undefined) => void;
}) {
  const [code, setCode] = useState("");
  const [phase, setPhase] = useState<"idle" | "checking" | "success" | "refused">(error && isRequestExpired(error) ? "refused" : "idle");
  const [message, setMessage] = useState(error);
  const inputRef = useRef<HTMLInputElement>(null);
  const mounted = useRef(true);
  // Set again on mount: React's StrictMode runs this effect's cleanup once before the real mount.
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  const submit = (value: string) => {
    if (value.length !== codeLength || phase !== "idle") return;
    if (!verify) { answer(value); return; }
    setPhase("checking");
    setMessage(undefined);
    verify(value).then(() => {
      if (!mounted.current) return;
      setPhase("success");
      setTimeout(() => answer(value), 700);
    }, (cause) => {
      if (!mounted.current) return;
      const text = cause instanceof Error && cause.message ? cause.message : "KeyWay couldn't check the code. Try again.";
      setMessage(text);
      if (canRetryCode(text)) {
        setPhase("idle");
        setCode("");
        requestAnimationFrame(() => inputRef.current?.focus());
      } else {
        setPhase("refused");
      }
    });
  };

  useEffect(() => { if (code.length === codeLength) submit(code); }, [code]);

  const busy = phase === "checking" || phase === "success";
  return (
    // Closing during a check only hides the prompt: the check that is running still decides the outcome.
    <Shell theme={theme} labelId="keyway-code-title" onEscape={() => answer(undefined)}>
      {(palette) => (
        <form onSubmit={(event) => { event.preventDefault(); submit(code); }}>
          <p style={{ ...modalEyebrow, color: palette.muted }}>EMAIL CONFIRMATION</p>
          <h2 id="keyway-code-title" style={modalTitle}>{phase === "refused" ? "Couldn't confirm" : "Check your email"}</h2>
          {phase !== "refused" ? (
            <p style={{ ...modalCopy, color: palette.muted }}>
              Enter the code we emailed you to confirm {CODE_PURPOSE[reason]}.{" "}
              {sentTo ? <>Sent to <strong style={{ color: palette.text, overflowWrap: "anywhere" }}>{sentTo}</strong>. </> : null}
              It expires in 10 minutes.
            </p>
          ) : null}
          {phase === "refused" ? (
            <>
              <p id="keyway-code-message" role="alert" style={{ ...errorNote(palette), margin: "16px 0 0" }}>{message}</p>
              <div style={modalActions}>
                <button type="button" autoFocus style={{ ...modalButton, ...modalPrimaryButton, background: palette.primary, color: palette.primaryText }} onClick={() => answer(undefined)}>Close</button>
              </div>
            </>
          ) : (
            <>
              <CodeInput
                palette={palette}
                value={code}
                length={codeLength}
                inputRef={inputRef}
                readOnly={busy}
                state={phase === "success" ? "success" : message ? "error" : "idle"}
                describedBy={message ? "keyway-code-message" : undefined}
                onChange={(next) => { setCode(next); if (next) setMessage(undefined); }}
              />
              {phase === "checking" ? <StatusLine palette={palette} tone="muted">Checking code…</StatusLine> : null}
              {phase === "success" ? <StatusLine palette={palette} tone="success">Code confirmed</StatusLine> : null}
              {message ? <p id="keyway-code-message" role="alert" style={{ margin: "12px 0 0", color: palette.error, fontSize: 14, fontWeight: 600 }}>{message}</p> : null}
              <ResendLine palette={palette} resend={async () => {
                try {
                  await resend();
                  setMessage(undefined);
                } catch (cause) {
                  const text = cause instanceof Error ? cause.message : "";
                  if (isRequestExpired(text)) { setMessage(text); setPhase("refused"); }
                  throw cause;
                }
              }} disabled={busy} prompt="Didn't get it?" />
              <div style={modalActions}>
                <button type="button" style={{ ...modalButton, borderColor: palette.border, color: palette.text }} onClick={() => answer(undefined)}>{busy ? "Close" : "Cancel"}</button>
                <button type="submit" disabled={code.length !== codeLength || busy} style={{ ...modalButton, ...modalPrimaryButton, background: palette.primary, color: palette.primaryText, opacity: code.length === codeLength || busy ? 1 : 0.6 }}>
                  {phase === "success" ? "Confirmed" : busy ? "Checking…" : "Confirm"}
                </button>
              </div>
            </>
          )}
        </form>
      )}
    </Shell>
  );
}

/** The built-in dialog for closing a channel. */
export function KeyWayChannelCloseModal({ theme, appName, preview, step, answer, fiberNode = "hosted" }: ApprovalProps<FiberChannelClosePreview> & { fiberNode?: "hosted" | "browser" }) {
  return (
    <Shell theme={theme} labelId="keyway-close-title" onEscape={escape(step, answer)}>
      {(palette) => (
        <>
          <p style={{ ...modalEyebrow, color: palette.muted }}>{appName} · CLOSE CHANNEL</p>
          <h2 id="keyway-close-title" style={modalTitle}>{preview.force ? "Force-close this channel?" : "Close this channel?"}</h2>
          <dl style={{ ...fundingDetails, margin: "16px 0" }}>
            <Row palette={palette} label="Returns to you, before the closing fee" value={preview.returningText} />
            <Row palette={palette} label="Peer" value={preview.peer} />
            <Row palette={palette} label="Network" value={preview.network} mono={false} />
          </dl>
          <p style={note(palette)}>
            {!preview.force
              ? "Your side of the channel, minus the closing fee, goes back to your own account."
              : fiberNode === "browser"
                ? "A force close settles on-chain without the peer, after about 4 hours, while Fiber runs in this browser. KeyWay then moves your side to your account. Use a normal close when the peer is online."
                : "A force close settles on-chain without the peer, after about 4 hours. KeyWay then moves your side to your account the next time you use Fiber. Use a normal close when the peer is online."}
          </p>
          <Actions palette={palette} confirm={preview.force ? "Force close" : "Close channel"} busyLabel="Closing…" step={step} answer={answer} />
        </>
      )}
    </Shell>
  );
}

/** The built-in dialog for connecting to or disconnecting from a Fiber peer. */
export function KeyWayPeerModal({ theme, appName, preview, step, answer }: ApprovalProps<FiberPeerPreview>) {
  const connect = preview.action === "connect";
  return (
    <Shell theme={theme} labelId="keyway-peer-title" onEscape={escape(step, answer)}>
      {(palette) => (
        <>
          <p style={{ ...modalEyebrow, color: palette.muted }}>{appName} · FIBER PEER</p>
          <h2 id="keyway-peer-title" style={modalTitle}>{connect ? "Connect to this peer?" : "Disconnect this peer?"}</h2>
          <dl style={{ ...fundingDetails, margin: "16px 0" }}>
            {preview.pubkey && <Row palette={palette} label="Node ID" value={preview.pubkey} />}
            {preview.address && <Row palette={palette} label="Address" value={preview.address} />}
          </dl>
          <p style={note(palette)}>
            {connect
              ? "Your Fiber node will talk to this node. No funds move."
              : preview.openChannels > 0
                ? `You have ${preview.openChannels} open channel${preview.openChannels === 1 ? "" : "s"} with this peer. ${preview.openChannels === 1 ? "It goes" : "They go"} offline until the peer reconnects.`
                : "No funds move."}
          </p>
          <Actions palette={palette} confirm={connect ? "Connect" : "Disconnect"} busyLabel={connect ? "Connecting…" : "Disconnecting…"} step={step} answer={answer} />
        </>
      )}
    </Shell>
  );
}

const SETTING_LABELS: Record<FiberChannelSettingsPreview["changes"][number]["setting"], string> = {
  enabled: "Forwarding payments",
  tlc_expiry_delta: "Payment expiry",
  tlc_minimum_value: "Smallest payment",
  tlc_fee_proportional_millionths: "Forwarding fee",
};

function integer(value: string): bigint | undefined {
  try { return BigInt(value); } catch { return undefined; }
}

/** "12 hours", "1 hour 30 minutes", "45 seconds". */
export function formatDuration(ms: bigint): string {
  const unit = (count: bigint, name: string) => `${count} ${name}${count === 1n ? "" : "s"}`;
  const hours = ms / 3_600_000n;
  const minutes = (ms % 3_600_000n) / 60_000n;
  const seconds = (ms % 60_000n) / 1000n;
  const parts = [hours ? unit(hours, "hour") : "", minutes ? unit(minutes, "minute") : "", !hours && seconds ? unit(seconds, "second") : ""].filter(Boolean);
  return parts.length ? parts.join(" ") : `${ms} ms`;
}

/** A setting's value for people: on or off, a duration, an amount of the channel's asset, a percentage. */
export function settingText(setting: FiberChannelSettingsPreview["changes"][number]["setting"], value: string | undefined, asset = "ckb"): string {
  if (value === undefined) return "—";
  if (setting === "enabled") return value === "true" ? "on" : value === "false" ? "off" : value;
  const number = integer(value);
  if (number === undefined) return value;
  if (setting === "tlc_expiry_delta") return formatDuration(number);
  if (setting === "tlc_minimum_value") return formatAsset(number, asset);
  // Parts per million, as a percentage of each forwarded payment.
  const hundredths = Number(number) / 10_000;
  return `${hundredths.toLocaleString("en-US", { maximumFractionDigits: 4 })}%`;
}

/** The built-in dialog for changing a channel's forwarding settings. */
export function KeyWayChannelSettingsModal({ theme, appName, preview, step, answer }: ApprovalProps<FiberChannelSettingsPreview>) {
  return (
    <Shell theme={theme} labelId="keyway-settings-title" onEscape={escape(step, answer)}>
      {(palette) => (
        <>
          <p style={{ ...modalEyebrow, color: palette.muted }}>{appName} · CHANNEL SETTINGS</p>
          <h2 id="keyway-settings-title" style={modalTitle}>Change this channel&apos;s settings?</h2>
          <dl style={{ ...fundingDetails, margin: "16px 0" }}>
            {preview.changes.map((change) => (
              <Row key={change.setting} palette={palette} label={SETTING_LABELS[change.setting]} value={`${settingText(change.setting, change.from, preview.asset)} → ${settingText(change.setting, change.to, preview.asset)}`} />
            ))}
            <Row palette={palette} label="Peer" value={preview.peer} />
          </dl>
          <p style={note(palette)}>These settings apply to payments other people route through this channel. No funds move.</p>
          <Actions palette={palette} confirm="Save settings" busyLabel="Saving…" step={step} answer={answer} />
        </>
      )}
    </Shell>
  );
}

/** The built-in dialog for turning account recovery on, drawn from the backend's own plan. */
export function KeyWayRecoveryModal({ theme, appName, preview, step, answer }: ApprovalProps<RecoveryPreview>) {
  return (
    <Shell theme={theme} labelId="keyway-recovery-title" onEscape={escape(step, answer)}>
      {(palette) => (
        <>
          <p style={{ ...modalEyebrow, color: palette.muted }}>{appName} · ACCOUNT RECOVERY</p>
          <h2 id="keyway-recovery-title" style={modalTitle}>Turn on recovery?</h2>
          <p style={{ ...modalCopy, color: palette.muted }}>
            {preview.backups.length === 1 ? "This backup" : "These backups"} can recover your account if you lose access to your email.
          </p>
          <dl style={{ ...fundingDetails, margin: "16px 0" }}>
            {preview.backups.map((backup) => <Row key={`${backup.kind}:${backup.address}`} palette={palette} label="Backup" value={backup.label} />)}
            <Row palette={palette} label="Locked for the recovery list" value={`${preview.adminListCkb} CKB`} />
            {preview.tokenCellsExtraCkb !== "0" && <Row palette={palette} label="Locked in token cells" value={`${preview.tokenCellsExtraCkb} CKB`} />}
            <Row palette={palette} label="Network fee" value={`${preview.feeCkb} CKB`} />
            <Row palette={palette} label="New address" value={preview.newAddress} />
            <Row palette={palette} label="Network" value={preview.network} mono={false} />
          </dl>
          <p role="note" style={errorNote(palette)}>Your address will change because you&apos;re turning on recovery.</p>
          <p style={note(palette)}>
            Your CKB{preview.tokens.length > 0 ? " and tokens" : ""} move to the new address in one transaction. The old address stays yours.
            {preview.cellsLeft > 0 ? ` ${preview.cellsLeft} cell${preview.cellsLeft === 1 ? "" : "s"} that can't be moved stay${preview.cellsLeft === 1 ? "s" : ""} there.` : ""} {step?.failure ? "" : "We'll email you a code next."}
          </p>
          <details style={{ ...details, color: palette.muted }}>
            <summary style={{ cursor: "pointer" }}>Details</summary>
            <p style={detailLine}>Transaction {preview.transactionHash}</p>
          </details>
          <Actions palette={palette} confirm="Turn on recovery" busyLabel="Sending code…" step={step} answer={answer} />
        </>
      )}
    </Shell>
  );
}

/** The built-in dialog for adding or removing a recovery backup, drawn from the backend's own plan. */
export function KeyWayBackupChangeModal({ theme, appName, preview, step, answer }: ApprovalProps<BackupChangePreview>) {
  const adding = preview.change === "add";
  return (
    <Shell theme={theme} labelId="keyway-backup-title" onEscape={escape(step, answer)}>
      {(palette) => (
        <>
          <p style={{ ...modalEyebrow, color: palette.muted }}>{appName} · ACCOUNT RECOVERY</p>
          <h2 id="keyway-backup-title" style={modalTitle}>{adding ? "Add this backup?" : "Remove this backup?"}</h2>
          <p style={{ ...modalCopy, color: palette.muted }}>
            {adding ? "It will be able to move everything in your account without KeyWay." : "It will no longer be able to recover your account."}
          </p>
          <dl style={{ ...fundingDetails, margin: "16px 0" }}>
            <Row palette={palette} label={adding ? "Adding" : "Removing"} value={preview.backup.label} />
            <Row palette={palette} label="Backups after this" value={String(preview.backups.length)} />
            <Row palette={palette} label="Network fee" value={`${preview.feeCkb} CKB`} />
            <Row palette={palette} label="Network" value={preview.network} mono={false} />
          </dl>
          <p style={note(palette)}>Your address doesn&apos;t change.{step?.failure ? "" : " We'll email you a code next."}</p>
          <details style={{ ...details, color: palette.muted }}>
            <summary style={{ cursor: "pointer" }}>Details</summary>
            {preview.backups.map((backup) => <p key={`${backup.kind}:${backup.address}`} style={detailLine}>Backup {backup.address}</p>)}
            <p style={detailLine}>Transaction {preview.transactionHash}</p>
          </details>
          <Actions palette={palette} confirm={adding ? "Add backup" : "Remove backup"} busyLabel="Sending code…" step={step} answer={answer} />
        </>
      )}
    </Shell>
  );
}

/** The built-in dialog for the on-chain transaction that funds a new Fiber channel. */
export function KeyWayFundingModal({ theme, appName, preview, step, answer }: ApprovalProps<FiberChannelOpenPreview>) {
  return (
    <Shell theme={theme} labelId="keyway-funding-title" onEscape={escape(step, answer)}>
      {(palette) => (
        <>
          <p style={{ ...modalEyebrow, color: palette.muted }}>{appName} · ON-CHAIN CONFIRMATION</p>
          <h2 id="keyway-funding-title" style={modalTitle}>Activate Fiber payments?</h2>
          <dl style={{ ...fundingDetails, margin: "16px 0" }}>
            {preview.token && <Row palette={palette} label="Channel funding" value={preview.token.amountText} />}
            <Row palette={palette} label={preview.token ? "CKB reserve" : "Channel funding"} value={`${preview.amountCkb} CKB`} />
            {preview.peer && <Row palette={palette} label="Peer" value={preview.peer} />}
            {preview.feeReserveCkb && <Row palette={palette} label="Fee reserve" value={`${preview.feeReserveCkb} CKB`} />}
            <Row palette={palette} label="Network fee" value={`${preview.feeCkb} CKB`} />
            <Row palette={palette} label="Network" value="CKB testnet" mono={false} />
          </dl>
          <p style={note(palette)}>{preview.token ? "This locks the token, and some CKB as a reserve," : "This locks testnet CKB"} into a payment channel. It does not send funds to another wallet, and a normal close returns your side to your own account.</p>
          {preview.feeReserveCkb && <p style={note(palette)}>The fee reserve stays on your own Fiber node so it can claim your funds if a channel is ever force-closed. You get it back once all your channels are closed.</p>}
          <Actions palette={palette} confirm="Activate" busyLabel="Signing…" step={step} answer={answer} />
        </>
      )}
    </Shell>
  );
}

/** CKB a person typed ("100,000" or "2500.5") in shannons, or undefined if it isn't a positive amount. */
export function parseCkbAmount(text: string): bigint | undefined {
  const value = text.replace(/[\s,_]/g, "");
  if (!/^\d{1,12}(\.\d{1,8})?$/.test(value)) return undefined;
  const shannons = ccc.fixedPointFrom(value);
  return shannons > 0n ? shannons : undefined;
}

/** A CKB amount for the field: whole CKB with thousands separators, decimals kept as they are. */
export function formatCkbInput(shannons: bigint): string {
  const [whole, fraction] = ccc.fixedPointToString(shannons).split(".");
  return `${BigInt(whole).toLocaleString("en-US")}${fraction ? `.${fraction}` : ""}`;
}

/**
 * The built-in dialog before an account's first send: turns daily send limits on, with the amount the user chooses.
 * Anything above it within 24 hours needs the code KeyWay's Lit Action emails, and KeyWay's server can't skip it.
 */
export function KeyWayDailyLimitModal({ theme, appName, offer, answer }: {
  theme: Theme;
  appName: string;
  offer: SendLimitOffer;
  answer: (amount: bigint | null) => void;
}) {
  const [text, setText] = useState(() => formatCkbInput(offer.ckb));
  const [invalid, setInvalid] = useState(false);
  const amount = parseCkbAmount(text);
  const confirm = (approved: boolean) => {
    if (!approved) return answer(null);
    if (amount === undefined) return setInvalid(true);
    answer(amount);
  };
  return (
    <Shell theme={theme} labelId="keyway-limit-title" onEscape={() => answer(null)}>
      {(palette) => (
        <>
          <p style={{ ...modalEyebrow, color: palette.muted }}>{appName} · DAILY LIMIT</p>
          <h2 id="keyway-limit-title" style={modalTitle}>Protect your account</h2>
          <p style={{ ...modalCopy, color: palette.muted }}>
            Sending more than this within 24 hours will need a code from your email.
          </p>
          <form style={{ margin: "20px 0 4px" }} onSubmit={(event) => { event.preventDefault(); confirm(true); }}>
            <label style={{ ...modalLabel, color: palette.muted }}>
              Daily limit
              <span style={{ position: "relative", display: "block" }}>
                <input
                  autoFocus
                  inputMode="decimal"
                  autoComplete="off"
                  aria-invalid={invalid && amount === undefined ? true : undefined}
                  aria-describedby={invalid && amount === undefined ? "keyway-limit-error" : undefined}
                  value={text}
                  onChange={(event) => { setText(event.target.value); setInvalid(false); }}
                  style={{ ...modalInput, paddingRight: 64, background: palette.surface, borderColor: invalid && amount === undefined ? palette.error : palette.border, color: palette.text }}
                />
                <span aria-hidden="true" style={{ position: "absolute", right: 16, top: "50%", transform: "translateY(-50%)", color: palette.muted, fontSize: 15, fontWeight: 600 }}>CKB</span>
              </span>
            </label>
            {invalid && amount === undefined && (
              <p id="keyway-limit-error" role="alert" style={{ ...errorNote(palette), margin: "10px 0 0" }}>Enter an amount above 0 CKB.</p>
            )}
          </form>
          <p style={{ ...note(palette), margin: "16px auto 0" }}>
            This keeps 174 CKB of your balance in a small record on CKB. It stays yours. We&apos;ll email you a code next.
          </p>
          <Actions palette={palette} confirm="Continue" busyLabel="Sending code…" answer={confirm} />
        </>
      )}
    </Shell>
  );
}

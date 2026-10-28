"use client";

import { useEffect, useState, type CSSProperties, type ReactNode } from "react";
import type { RecoveryPreview } from "../browser/account-recovery";
import type { MessagePreview, TransactionPreview } from "../browser/keyway-signer";
import type { FiberChannelClosePreview, FiberChannelSettingsPreview, FiberPeerPreview } from "../browser/fiber-actions";
import {
  fundingDetails,
  modalActions,
  modalBackdrop,
  modalButton,
  modalCopy,
  modalEyebrow,
  modalInput,
  modalLabel,
  modalPalette,
  modalPanel,
  modalPrimaryButton,
  modalTitle,
  resendButton,
  type ModalPalette,
} from "./modal-styles";

type Theme = "light" | "dark";

function useEscape(onEscape: () => void) {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => { if (event.key === "Escape") onEscape(); };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onEscape]);
}

function Shell({ theme, labelId, children }: { theme: Theme; labelId: string; children: (palette: ModalPalette) => ReactNode }) {
  const palette = modalPalette(theme);
  return (
    <div role="presentation" style={{ ...modalBackdrop, background: palette.backdrop }}>
      <section role="dialog" aria-modal="true" aria-labelledby={labelId} style={{ ...modalPanel, width: "min(100%, 460px)", background: palette.panel, borderColor: palette.border, color: palette.text }}>
        {children(palette)}
      </section>
    </div>
  );
}

const rowValue: CSSProperties = { textAlign: "right", overflowWrap: "anywhere" };
const warning = (palette: ModalPalette): CSSProperties => ({ margin: "0 0 12px", padding: "10px 12px", borderRadius: 12, background: palette.errorSurface, color: palette.error, fontSize: 13, lineHeight: 1.5, textAlign: "left" });
const note = (palette: ModalPalette): CSSProperties => ({ ...modalCopy, margin: "0 auto 8px", color: palette.muted, fontSize: 13 });

function shortAddress(value: string): string {
  return value.length <= 24 ? value : `${value.slice(0, 12)}…${value.slice(-6)}`;
}

/** The built-in approval dialog for a transaction, drawn from the backend's decoding of its effects. */
export function KeyWayTransactionModal({ theme, appName, preview, answer }: { theme: Theme; appName: string; preview: TransactionPreview; answer: (approved: boolean) => void }) {
  useEscape(() => answer(false));
  const sending = preview.sendingCkb !== "0";
  // A token leaving is the point of the transaction; the CKB that travels inside its cell is secondary.
  const tokenOut = preview.tokens.find((token) => token.amount.startsWith("-") && token.amountText);
  const title = tokenOut ? `Send ${tokenOut.amountText!.slice(1)}?` : sending ? `Send ${preview.sendingCkb} CKB?` : "Approve this transaction?";
  return (
    <Shell theme={theme} labelId="keyway-transaction-title">
      {(palette) => (
        <>
          <p style={{ ...modalEyebrow, color: palette.muted }}>{appName} · APPROVE TRANSACTION</p>
          <h2 id="keyway-transaction-title" style={modalTitle}>{title}</h2>
          {preview.unrecognized.length > 0 && (
            <p role="alert" style={warning(palette)}>
              This transaction uses {preview.unrecognized.length === 1 ? "a script" : "scripts"} KeyWay doesn&apos;t recognize ({preview.unrecognized.map((item) => `${item.codeHash}, ${item.cells} cell${item.cells === 1 ? "" : "s"}`).join("; ")}). Only approve it if you trust {appName}.
            </p>
          )}
          <dl style={{ ...fundingDetails, margin: "16px 0" }}>
            {sending && <><dt>You send</dt><dd style={rowValue}>{preview.sendingCkb} CKB</dd></>}
            {preview.receivingCkb !== "0" && <><dt>You receive</dt><dd style={rowValue}>{preview.receivingCkb} CKB</dd></>}
            {preview.tokens.map((token) => <Row key={`t-${token.id}`} label={`Token ${token.id} (${token.standard})`} value={token.amountText ?? token.amount} />)}
            {preview.nfts.map((nft) => <Row key={`n-${nft.id}`} label={`${nft.kind} ${nft.id}`} value={nft.change} />)}
            {preview.dao.map((action, index) => <Row key={`d-${index}`} label={`Nervos DAO ${action.action}`} value={`${action.amountCkb} CKB`} />)}
            {preview.recipients.map((recipient) => (
              <Row
                key={recipient.address}
                label={`To ${shortAddress(recipient.address)} (${recipient.kind === "wallet" ? `${recipient.walletType ?? "standard"} wallet` : recipient.kind})`}
                value={[`${recipient.ckb} CKB`, ...recipient.tokens.map((token) => `${token.amount} ${token.id}`), ...recipient.nfts].join(", ")}
              />
            ))}
            <dt>Network fee</dt><dd style={rowValue}>{preview.feeCkb} CKB</dd>
            <dt>Network</dt><dd style={rowValue}>{preview.network}</dd>
          </dl>
          {preview.otherSigners > 0 && <p style={note(palette)}>{preview.otherSigners} input{preview.otherSigners === 1 ? "" : "s"} belong to someone else, who must sign too.</p>}
          {preview.requiresEmailCode && <p style={note(palette)}>This reaches your email confirmation amount, so we&apos;ll email you a code next.</p>}
          <details style={{ textAlign: "left", fontSize: 12, color: palette.muted, margin: "8px 0 0" }}>
            <summary style={{ cursor: "pointer" }}>Details</summary>
            <CellList title="Inputs" cells={preview.details.inputs} />
            <CellList title="Outputs" cells={preview.details.outputs} />
            <p style={{ margin: "8px 0 0", fontFamily: "ui-monospace, monospace", overflowWrap: "anywhere" }}>Transaction {preview.transactionHash}</p>
          </details>
          <div style={modalActions}>
            <button type="button" autoFocus style={{ ...modalButton, borderColor: palette.border, color: palette.text }} onClick={() => answer(false)}>Cancel</button>
            <button type="button" style={{ ...modalButton, ...modalPrimaryButton, background: palette.primary, color: palette.primaryText }} onClick={() => answer(true)}>Approve</button>
          </div>
        </>
      )}
    </Shell>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return <><dt style={{ overflowWrap: "anywhere" }}>{label}</dt><dd style={rowValue}>{value}</dd></>;
}

function CellList({ title, cells }: { title: string; cells: TransactionPreview["details"]["inputs"] }) {
  return (
    <div style={{ marginTop: 8 }}>
      <p style={{ margin: "0 0 4px", fontWeight: 700 }}>{title}</p>
      <ol style={{ margin: 0, paddingLeft: 18, fontFamily: "ui-monospace, monospace", lineHeight: 1.6 }}>
        {cells.map((cell, index) => <li key={index}>{cell.capacityCkb} CKB · lock {cell.lock}{cell.type ? ` · type ${cell.type}` : ""}{cell.dataBytes ? ` · ${cell.dataBytes} B data` : ""}</li>)}
      </ol>
    </div>
  );
}

/** The built-in approval dialog for signing a message, which shows the exact text. */
export function KeyWayMessageModal({ theme, appName, preview, answer }: { theme: Theme; appName: string; preview: MessagePreview; answer: (approved: boolean) => void }) {
  useEscape(() => answer(false));
  return (
    <Shell theme={theme} labelId="keyway-message-title">
      {(palette) => (
        <>
          <p style={{ ...modalEyebrow, color: palette.muted }}>{appName} · SIGN A MESSAGE</p>
          <h2 id="keyway-message-title" style={modalTitle}>Sign this message?</h2>
          <pre style={{ margin: "16px 0", padding: 14, maxHeight: 220, overflow: "auto", borderRadius: 12, background: palette.surface, border: `1px solid ${palette.border}`, textAlign: "left", whiteSpace: "pre-wrap", overflowWrap: "anywhere", fontFamily: "ui-monospace, monospace", fontSize: 13 }}>{preview.message}</pre>
          <p style={note(palette)}>Signing proves you control this account. It doesn&apos;t move any funds.</p>
          <div style={modalActions}>
            <button type="button" autoFocus style={{ ...modalButton, borderColor: palette.border, color: palette.text }} onClick={() => answer(false)}>Cancel</button>
            <button type="button" style={{ ...modalButton, ...modalPrimaryButton, background: palette.primary, color: palette.primaryText }} onClick={() => answer(true)}>Sign</button>
          </div>
        </>
      )}
    </Shell>
  );
}

/** Asks for the code KeyWay emailed the user. Always drawn by the SDK, even when an app brings its own approval UI. */
export function KeyWayEmailCodeModal({ theme, reason, error, resend, answer }: {
  theme: Theme;
  reason: "transaction" | "settings" | "payment" | "recovery";
  error?: string;
  resend: () => Promise<void>;
  answer: (code: string | undefined) => void;
}) {
  const [code, setCode] = useState("");
  const [resent, setResent] = useState<"idle" | "sending" | "sent">("idle");
  useEscape(() => answer(undefined));
  return (
    <Shell theme={theme} labelId="keyway-code-title">
      {(palette) => (
        <form onSubmit={(event) => { event.preventDefault(); if (code.length === 6) answer(code); }}>
          <p style={{ ...modalEyebrow, color: palette.muted }}>EMAIL CONFIRMATION</p>
          <h2 id="keyway-code-title" style={modalTitle}>Check your email</h2>
          <p style={{ ...modalCopy, color: palette.muted }}>
            {reason === "transaction" ? "We emailed you a code to confirm this transaction."
              : reason === "payment" ? "We emailed you a code to confirm this payment."
              : reason === "recovery" ? "We emailed you a code to confirm turning on recovery."
              : "We emailed you a code to confirm this security change."} It expires in 10 minutes.
          </p>
          <label style={modalLabel}>Confirmation code
            <input
              autoFocus
              required
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              maxLength={6}
              value={code}
              onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
              style={{ ...modalInput, borderColor: error ? palette.error : palette.border, background: palette.surface, color: palette.text, letterSpacing: "0.3em", fontFamily: "ui-monospace, monospace" }}
            />
          </label>
          {error && <p role="alert" style={{ margin: "10px 0 0", color: palette.error, fontSize: 13, textAlign: "left" }}>{error}</p>}
          <p style={{ margin: "14px 0 0", fontSize: 13, color: palette.muted, textAlign: "left" }}>
            {resent === "sent" ? "We sent a new code." : <button type="button" style={{ ...resendButton, color: palette.muted }} disabled={resent === "sending"} onClick={() => { setResent("sending"); void resend().then(() => setResent("sent"), () => setResent("idle")); }}>Send a new code</button>}
          </p>
          <div style={modalActions}>
            <button type="button" style={{ ...modalButton, borderColor: palette.border, color: palette.text }} onClick={() => answer(undefined)}>Cancel</button>
            <button type="submit" disabled={code.length !== 6} style={{ ...modalButton, ...modalPrimaryButton, background: palette.primary, color: palette.primaryText, opacity: code.length === 6 ? 1 : 0.6 }}>Confirm</button>
          </div>
        </form>
      )}
    </Shell>
  );
}

function Actions({ palette, confirm, answer }: { palette: ModalPalette; confirm: string; answer: (approved: boolean) => void }) {
  return (
    <div style={modalActions}>
      <button type="button" autoFocus style={{ ...modalButton, borderColor: palette.border, color: palette.text }} onClick={() => answer(false)}>Cancel</button>
      <button type="button" style={{ ...modalButton, ...modalPrimaryButton, background: palette.primary, color: palette.primaryText }} onClick={() => answer(true)}>{confirm}</button>
    </div>
  );
}

/** The built-in dialog for closing a channel. */
export function KeyWayChannelCloseModal({ theme, appName, preview, answer }: { theme: Theme; appName: string; preview: FiberChannelClosePreview; answer: (approved: boolean) => void }) {
  useEscape(() => answer(false));
  return (
    <Shell theme={theme} labelId="keyway-close-title">
      {(palette) => (
        <>
          <p style={{ ...modalEyebrow, color: palette.muted }}>{appName} · CLOSE CHANNEL</p>
          <h2 id="keyway-close-title" style={modalTitle}>{preview.force ? "Force-close this channel?" : "Close this channel?"}</h2>
          <dl style={{ ...fundingDetails, margin: "16px 0" }}>
            <Row label="Returns to you" value={preview.returningText} />
            <Row label="Peer" value={shortAddress(preview.peer)} />
            <Row label="Network" value={preview.network} />
          </dl>
          <p style={note(palette)}>
            {preview.force
              ? "A force close settles on-chain without the peer, after about 4 hours. With the current Fiber version, force-closed funds may not settle to your own address. Use a normal close whenever the peer is online."
              : "Your side of the channel, minus the closing fee, goes back to your own account."}
          </p>
          <Actions palette={palette} confirm={preview.force ? "Force close" : "Close channel"} answer={answer} />
        </>
      )}
    </Shell>
  );
}

/** The built-in dialog for connecting to or disconnecting from a Fiber peer. */
export function KeyWayPeerModal({ theme, appName, preview, answer }: { theme: Theme; appName: string; preview: FiberPeerPreview; answer: (approved: boolean) => void }) {
  useEscape(() => answer(false));
  const connect = preview.action === "connect";
  return (
    <Shell theme={theme} labelId="keyway-peer-title">
      {(palette) => (
        <>
          <p style={{ ...modalEyebrow, color: palette.muted }}>{appName} · FIBER PEER</p>
          <h2 id="keyway-peer-title" style={modalTitle}>{connect ? "Connect to this peer?" : "Disconnect this peer?"}</h2>
          <dl style={{ ...fundingDetails, margin: "16px 0" }}>
            {preview.pubkey && <Row label="Node ID" value={shortAddress(preview.pubkey)} />}
            {preview.address && <Row label="Address" value={preview.address} />}
          </dl>
          <p style={note(palette)}>
            {connect
              ? "Your Fiber node will talk to this node. No funds move."
              : preview.openChannels > 0
                ? `You have ${preview.openChannels} open channel${preview.openChannels === 1 ? "" : "s"} with this peer. ${preview.openChannels === 1 ? "It goes" : "They go"} offline until the peer reconnects.`
                : "No funds move."}
          </p>
          <Actions palette={palette} confirm={connect ? "Connect" : "Disconnect"} answer={answer} />
        </>
      )}
    </Shell>
  );
}

const SETTING_LABELS: Record<FiberChannelSettingsPreview["changes"][number]["setting"], string> = {
  enabled: "Forwarding payments",
  tlc_expiry_delta: "Payment expiry (ms)",
  tlc_minimum_value: "Smallest payment",
  tlc_fee_proportional_millionths: "Forwarding fee (per million)",
};

/** The built-in dialog for changing a channel's forwarding settings. */
export function KeyWayChannelSettingsModal({ theme, appName, preview, answer }: { theme: Theme; appName: string; preview: FiberChannelSettingsPreview; answer: (approved: boolean) => void }) {
  useEscape(() => answer(false));
  const show = (value?: string) => value === undefined ? "—" : value === "true" ? "on" : value === "false" ? "off" : /^0x/.test(value) ? BigInt(value).toString() : value;
  return (
    <Shell theme={theme} labelId="keyway-settings-title">
      {(palette) => (
        <>
          <p style={{ ...modalEyebrow, color: palette.muted }}>{appName} · CHANNEL SETTINGS</p>
          <h2 id="keyway-settings-title" style={modalTitle}>Change this channel&apos;s settings?</h2>
          <dl style={{ ...fundingDetails, margin: "16px 0" }}>
            {preview.changes.map((change) => <Row key={change.setting} label={SETTING_LABELS[change.setting]} value={`${show(change.from)} → ${show(change.to)}`} />)}
            <Row label="Peer" value={shortAddress(preview.peer)} />
          </dl>
          <p style={note(palette)}>These settings apply to payments other people route through this channel. No funds move.</p>
          <Actions palette={palette} confirm="Save settings" answer={answer} />
        </>
      )}
    </Shell>
  );
}

/** The built-in dialog for turning account recovery on, drawn from the backend's own plan. */
export function KeyWayRecoveryModal({ theme, appName, preview, answer }: { theme: Theme; appName: string; preview: RecoveryPreview; answer: (approved: boolean) => void }) {
  useEscape(() => answer(false));
  return (
    <Shell theme={theme} labelId="keyway-recovery-title">
      {(palette) => (
        <>
          <p style={{ ...modalEyebrow, color: palette.muted }}>{appName} · ACCOUNT RECOVERY</p>
          <h2 id="keyway-recovery-title" style={modalTitle}>Turn on recovery?</h2>
          <p style={{ ...modalCopy, color: palette.muted }}>
            {preview.backups.length === 1 ? "This backup" : "These backups"} can recover your account if you lose access to your email.
          </p>
          <dl style={{ ...fundingDetails, margin: "16px 0" }}>
            {preview.backups.map((backup) => <Row key={`${backup.kind}:${backup.address}`} label="Backup" value={backup.label} />)}
            <Row label="Locked for the recovery list" value={`${preview.adminListCkb} CKB`} />
            {preview.tokenCellsExtraCkb !== "0" && <Row label="Locked in token cells" value={`${preview.tokenCellsExtraCkb} CKB`} />}
            <Row label="Network fee" value={`${preview.feeCkb} CKB`} />
            <Row label="New address" value={shortAddress(preview.newAddress)} />
            <Row label="Network" value={preview.network} />
          </dl>
          <p role="note" style={warning(palette)}>Your address will change because you&apos;re turning on recovery.</p>
          <p style={note(palette)}>
            Your CKB{preview.tokens.length > 0 ? " and tokens" : ""} move to the new address in one transaction. The old address stays yours.
            {preview.cellsLeft > 0 ? ` ${preview.cellsLeft} cell${preview.cellsLeft === 1 ? "" : "s"} that can't be moved stay${preview.cellsLeft === 1 ? "s" : ""} there.` : ""} We&apos;ll email you a code next.
          </p>
          <details style={{ textAlign: "left", fontSize: 12, color: palette.muted, margin: "8px 0 0" }}>
            <summary style={{ cursor: "pointer" }}>Details</summary>
            <p style={{ margin: "8px 0 0", fontFamily: "ui-monospace, monospace", overflowWrap: "anywhere" }}>New address {preview.newAddress}</p>
            <p style={{ margin: "8px 0 0", fontFamily: "ui-monospace, monospace", overflowWrap: "anywhere" }}>Transaction {preview.transactionHash}</p>
          </details>
          <Actions palette={palette} confirm="Turn on recovery" answer={answer} />
        </>
      )}
    </Shell>
  );
}

"use client";

import { useEffect, useLayoutEffect, useRef, useState, type CSSProperties, type ReactNode, type RefObject } from "react";
import {
  detailLabel,
  detailRow,
  detailValue,
  modalActions,
  modalBackdrop,
  modalButton,
  modalPalette,
  modalPanel,
  modalPrimaryButton,
  modalStatus,
  otpCaret,
  otpInput,
  otpLabel,
  otpSlot,
  otpSlots,
  resendButton,
  visuallyHidden,
  type ModalPalette,
} from "./modal-styles";

export type Theme = "light" | "dark";

const FOCUSABLE = "button, [href], input, select, textarea, summary, [tabindex]:not([tabindex='-1'])";

// The element each open dialog returns focus to. A dialog opened from another one (the code prompt after an
// approval) inherits that one's opener, since the approval is gone by the time the prompt closes.
const openers = new WeakMap<Element, HTMLElement>();

/**
 * Keeps keyboard focus inside the dialog while it's open, closes it on Escape (unless `onEscape` is
 * undefined, while it's busy), and gives focus back to whatever opened it once it closes.
 */
export function useDialogFocus(panel: RefObject<HTMLElement | null>, onEscape?: () => void) {
  const [opener] = useState(() => {
    if (typeof document === "undefined") return undefined;
    const active = document.activeElement as HTMLElement | null;
    const parent = active?.closest("[data-keyway-dialog]");
    return parent ? openers.get(parent) : active ?? undefined;
  });
  const escape = useRef(onEscape);
  escape.current = onEscape;

  useLayoutEffect(() => {
    const node = panel.current;
    if (!node) return;
    if (opener) openers.set(node, opener);
    if (!node.contains(document.activeElement)) (node.querySelector<HTMLElement>("[autofocus]") ?? node).focus();
    const focusable = () => [...node.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((element) => !element.hasAttribute("disabled") && element.getClientRects().length > 0);
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        if (escape.current) { event.preventDefault(); escape.current(); }
        return;
      }
      if (event.key !== "Tab") return;
      const elements = focusable();
      if (elements.length === 0) { event.preventDefault(); node.focus(); return; }
      const first = elements[0];
      const last = elements[elements.length - 1];
      const inside = node.contains(document.activeElement);
      if (event.shiftKey && (!inside || document.activeElement === first || document.activeElement === node)) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && (!inside || document.activeElement === last)) { event.preventDefault(); first.focus(); }
    };
    // Focus that lands outside (a click on the page behind, say) is brought back in.
    const onFocusIn = (event: FocusEvent) => {
      const target = event.target as Element | null;
      if (target && !node.contains(target) && !target.closest("[data-keyway-dialog]")) (focusable()[0] ?? node).focus();
    };
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("focusin", onFocusIn);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("focusin", onFocusIn);
      // Only when focus would otherwise be lost: another dialog that opened in its place keeps it.
      queueMicrotask(() => {
        const active = document.activeElement;
        // Still in the page means React only re-ran the effect (StrictMode), not that the dialog closed.
        if (node.isConnected) return;
        if ((!active || active === document.body || node.contains(active)) && opener?.isConnected) opener.focus();
      });
    };
  }, [panel, opener]);
}

/** The backdrop and panel every SDK dialog shares. */
export function Shell({ theme, labelId, width = 460, onEscape, onBackdrop, children }: {
  theme: Theme;
  labelId: string;
  width?: number;
  onEscape?: () => void;
  onBackdrop?: () => void;
  children: (palette: ModalPalette) => ReactNode;
}) {
  const palette = modalPalette(theme);
  const panel = useRef<HTMLElement>(null);
  useDialogFocus(panel, onEscape);
  return (
    <div
      role="presentation"
      style={{ ...modalBackdrop, background: palette.backdrop }}
      onMouseDown={onBackdrop ? (event) => { if (event.target === event.currentTarget) onBackdrop(); } : undefined}
    >
      <style>{`[data-keyway-dialog] :focus-visible { outline: 2px solid ${palette.focus}; outline-offset: 2px; }
@keyframes ckb-keyway-caret { 0%, 45% { opacity: 1; } 46%, 100% { opacity: 0; } }`}</style>
      <section
        ref={panel}
        data-keyway-dialog=""
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelId}
        tabIndex={-1}
        style={{ ...modalPanel, width: `min(100%, ${width}px)`, background: palette.panel, borderColor: palette.border, color: palette.text, outline: "none" }}
      >
        {children(palette)}
      </section>
    </div>
  );
}

/** One line of a dialog's summary: a plain label on the left, the value on the right. */
export function Row({ palette, label, value, mono = true }: { palette: ModalPalette; label: ReactNode; value: ReactNode; mono?: boolean }) {
  // When both don't fit on one line (a narrow phone), the value moves below its label, still on the right.
  return (
    <div style={detailRow}>
      <dt style={{ ...detailLabel, color: palette.muted }}>{label}</dt>
      <dd style={{ ...detailValue, ...(mono ? {} : { fontFamily: "inherit" }) }}>{value}</dd>
    </div>
  );
}

/**
 * The six-box code entry of the login and email confirmation dialogs. One real input sits over the boxes,
 * so typing, pasting a whole code, backspace and the browser's one-time-code autofill all work as usual.
 */
export function CodeInput({ palette, value, onChange, state = "idle", readOnly, inputRef, label = "Confirmation code", describedBy }: {
  palette: ModalPalette;
  value: string;
  onChange: (code: string) => void;
  state?: "idle" | "success" | "error";
  readOnly?: boolean;
  inputRef: RefObject<HTMLInputElement | null>;
  label?: string;
  describedBy?: string;
}) {
  const [focused, setFocused] = useState(false);
  const border = state === "success" ? palette.success : state === "error" ? palette.error : palette.border;
  const background = state === "success" ? palette.successSurface : state === "error" ? palette.errorSurface : palette.surface;
  return (
    <label style={otpLabel}>
      <span style={visuallyHidden}>{label}</span>
      <span style={otpSlots} aria-hidden="true">
        {Array.from({ length: 6 }, (_, index) => {
          const active = focused && !readOnly && value.length < 6 && index === value.length;
          return (
            <span key={index} style={{
              ...otpSlot,
              borderColor: active ? palette.text : border,
              background,
              color: palette.text,
              boxShadow: active ? `0 0 0 1px ${palette.text}` : undefined,
              opacity: readOnly && state === "idle" ? 0.7 : 1,
            }}>
              {value[index] ?? (active ? <span style={{ ...otpCaret, background: palette.text }} /> : "")}
            </span>
          );
        })}
      </span>
      <input
        ref={inputRef}
        autoFocus
        required
        inputMode="numeric"
        autoComplete="one-time-code"
        pattern="[0-9]{6}"
        maxLength={6}
        value={value}
        readOnly={readOnly}
        aria-invalid={state === "error" || undefined}
        aria-describedby={describedBy}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        onChange={(event) => onChange(event.target.value.replace(/\D/g, "").slice(0, 6))}
        style={otpInput}
      />
    </label>
  );
}

/** "Send a new code", then "New code sent" with a short wait before the next one; a refusal is shown as it is. */
export function ResendLine({ palette, resend, disabled, prompt, style, waitSeconds = 30 }: {
  palette: ModalPalette;
  resend: () => Promise<void>;
  disabled?: boolean;
  /** How long "Send another" waits after a code goes out. The server's own limit still applies. */
  waitSeconds?: number;
  prompt?: string;
  style?: CSSProperties;
}) {
  const [state, setState] = useState<{ kind: "idle" | "sending" } | { kind: "sent"; until: number } | { kind: "error"; message: string }>({ kind: "idle" });
  const [now, setNow] = useState(() => Date.now());
  const mounted = useRef(true);
  // Set again on mount: React's StrictMode runs this effect's cleanup once before the real mount.
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => {
    if (state.kind !== "sent") return;
    const timer = window.setInterval(() => {
      setNow(Date.now());
      if (Date.now() >= state.until) setState({ kind: "idle" });
    }, 250);
    return () => clearInterval(timer);
  }, [state]);
  const send = () => {
    setState({ kind: "sending" });
    resend().then(
      () => { if (mounted.current) { setNow(Date.now()); setState({ kind: "sent", until: Date.now() + waitSeconds * 1000 }); } },
      (cause) => { if (mounted.current) setState({ kind: "error", message: cause instanceof Error && cause.message ? cause.message : "Couldn't send a new code. Try again." }); },
    );
  };
  const wait = state.kind === "sent" ? Math.max(1, Math.ceil((state.until - now) / 1000)) : 0;
  return (
    <div style={{ margin: "16px 0 0", fontSize: 14, color: palette.muted, ...style }}>
      {/* Only "New code sent." is announced; the countdown beside it would be read out every second. */}
      <p style={{ margin: 0 }}>
        <span role="status" aria-live="polite" style={{ color: palette.success, fontWeight: 600 }}>{state.kind === "sent" ? "New code sent." : ""}</span>
        {state.kind === "sent" ? <span aria-hidden="true"> Send another in {wait}s</span> : null}
      </p>
      {state.kind === "error" ? <p role="alert" style={{ margin: "0 0 6px", color: palette.error }}>{state.message}</p> : null}
      {state.kind !== "sent" ? (
        <p style={{ margin: 0 }}>
          {prompt ? <>{prompt}{" "}</> : null}
          <button type="button" disabled={disabled || state.kind === "sending"} style={{ ...resendButton, color: palette.text, opacity: disabled ? 0.5 : 1 }} onClick={send}>
            {state.kind === "sending" ? "Sending…" : "Send a new code"}
          </button>
        </p>
      ) : null}
    </div>
  );
}

/** What an approval dialog shows after the user approves: busy until the next step, or why it failed. */
export type ApprovalStep = { busy?: boolean; failure?: string };

/**
 * Cancel and the confirming button. Once approved, the dialog stays open with the button busy until the next
 * step is ready, and Cancel becomes Close: it only hides the dialog, since the approved step is already
 * running. If that step fails, the reason replaces the buttons, with Close.
 */
export function Actions({ palette, confirm, busyLabel, step, answer }: {
  palette: ModalPalette;
  confirm: string;
  busyLabel: string;
  step?: ApprovalStep;
  answer: (approved: boolean) => void;
}) {
  if (step?.failure) {
    return (
      <>
        <p role="alert" style={{ ...errorNote(palette), margin: "20px 0 0" }}>{step.failure}</p>
        <div style={modalActions}>
          <button type="button" autoFocus style={{ ...modalButton, ...modalPrimaryButton, background: palette.primary, color: palette.primaryText }} onClick={() => answer(false)}>Close</button>
        </div>
      </>
    );
  }
  const busy = Boolean(step?.busy);
  return (
    <>
      <p role="status" style={visuallyHidden}>{busy ? busyLabel : ""}</p>
      <div style={modalActions}>
        <button type="button" autoFocus style={{ ...modalButton, borderColor: palette.border, color: palette.text }} onClick={() => answer(false)}>{busy ? "Close" : "Cancel"}</button>
        <button
          type="button"
          aria-disabled={busy || undefined}
          style={{ ...modalButton, ...modalPrimaryButton, background: palette.primary, color: palette.primaryText, cursor: busy ? "progress" : "pointer" }}
          onClick={() => { if (!busy) answer(true); }}
        >
          {busy ? busyLabel : confirm}
        </button>
      </div>
    </>
  );
}

export const errorNote = (palette: ModalPalette): CSSProperties => ({ margin: "0 0 12px", padding: "10px 12px", borderRadius: 12, background: palette.errorSurface, color: palette.error, fontSize: 13, lineHeight: 1.5, textAlign: "left" });

export function StatusLine({ palette, tone, children }: { palette: ModalPalette; tone: "muted" | "success" | "error"; children: ReactNode }) {
  return <p role={tone === "error" ? "alert" : "status"} style={{ ...modalStatus, color: tone === "muted" ? palette.muted : palette[tone] }}>{children}</p>;
}

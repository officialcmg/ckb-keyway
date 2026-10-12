import type { CSSProperties } from "react";

// Shared look of the SDK's modals (login, funding and signing approvals).
export const modalBackdrop: CSSProperties = {
  position: "fixed",
  inset: 0,
  zIndex: 2147483647,
  display: "grid",
  placeItems: "center",
  overflowY: "auto",
  padding: "24px",
  backdropFilter: "blur(6px)",
};

export const modalPanel: CSSProperties = {
  position: "relative",
  width: "min(100%, 420px)",
  boxSizing: "border-box",
  padding: "38px 34px 28px",
  border: "1px solid",
  borderRadius: 24,
  boxShadow: "0 24px 70px rgba(15, 23, 42, 0.2)",
  fontFamily: "'Avenir Next', Avenir, ui-sans-serif, sans-serif",
  textAlign: "center",
};

export const modalClose: CSSProperties = {
  position: "absolute",
  top: 16,
  right: 18,
  border: 0,
  background: "transparent",
  fontSize: 26,
  lineHeight: 1,
  cursor: "pointer",
};

export const modalBack: CSSProperties = {
  position: "absolute",
  top: 16,
  left: 18,
  display: "grid",
  placeItems: "center",
  width: 36,
  height: 36,
  padding: 0,
  border: 0,
  borderRadius: "50%",
  cursor: "pointer",
};

export const modalIcon: CSSProperties = {
  display: "grid",
  placeItems: "center",
  width: 68,
  height: 68,
  margin: "2px auto 18px",
  borderRadius: "50%",
};

export const modalEyebrow: CSSProperties = {
  margin: "0 0 8px",
  fontSize: 12,
  fontWeight: 700,
  letterSpacing: "0.08em",
  textTransform: "uppercase",
};

export const modalTitle: CSSProperties = {
  margin: "0 0 10px",
  fontSize: "clamp(25px, 6vw, 32px)",
  fontWeight: 700,
  lineHeight: 1.15,
  letterSpacing: "-0.025em",
};

export const modalCopy: CSSProperties = {
  margin: "0 auto 26px",
  maxWidth: 340,
  fontSize: 15,
  lineHeight: 1.55,
};

export const modalFootnote: CSSProperties = {
  margin: "28px 0 0",
  fontSize: 12,
  lineHeight: 1.5,
};

export const modalLabel: CSSProperties = {
  display: "grid",
  gap: 8,
  textAlign: "left",
  fontSize: 13,
  fontWeight: 600,
};

export const modalInput: CSSProperties = {
  width: "100%",
  boxSizing: "border-box",
  minHeight: 52,
  border: "1px solid",
  borderRadius: 12,
  padding: "0 15px",
  font: "16px 'Avenir Next', Avenir, ui-sans-serif, sans-serif",
};

export const otpLabel: CSSProperties = {
  position: "relative",
  display: "block",
  cursor: "text",
};

export const otpSlots: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(6, minmax(0, 1fr))",
  gap: 8,
};

export const otpSlot: CSSProperties = {
  display: "grid",
  placeItems: "center",
  aspectRatio: "0.82",
  border: "1.5px solid",
  borderRadius: 12,
  fontSize: "clamp(22px, 6vw, 28px)",
  fontWeight: 700,
  transition: "border-color 160ms ease, background 160ms ease",
};

export const otpInput: CSSProperties = {
  position: "absolute",
  inset: 0,
  width: "100%",
  height: "100%",
  opacity: 0,
  cursor: "text",
};

export const otpCaret: CSSProperties = {
  width: 2,
  height: "38%",
  minHeight: 24,
  borderRadius: 2,
  animation: "ckb-keyway-caret 1s step-end infinite",
};

export const visuallyHidden: CSSProperties = {
  position: "absolute",
  width: 1,
  height: 1,
  padding: 0,
  margin: -1,
  overflow: "hidden",
  clip: "rect(0, 0, 0, 0)",
  whiteSpace: "nowrap",
  border: 0,
};

export const modalStatus: CSSProperties = {
  minHeight: 21,
  margin: "14px 0 0",
  fontSize: 14,
  fontWeight: 600,
};

export const resendCopy: CSSProperties = {
  margin: "26px 0 0",
  fontSize: 14,
};

export const resendButton: CSSProperties = {
  padding: 0,
  border: 0,
  borderBottom: "1px solid currentColor",
  background: "transparent",
  font: "inherit",
  cursor: "pointer",
};

export const fundingDetails: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "1fr auto",
  gap: "10px 24px",
  margin: "24px 0",
  fontFamily: "ui-monospace, monospace",
  fontSize: 13,
};

export const modalActions: CSSProperties = {
  display: "flex",
  justifyContent: "flex-end",
  gap: 10,
  marginTop: 24,
};

export const modalButton: CSSProperties = {
  width: "100%",
  minHeight: 44,
  marginTop: 18,
  padding: "0 18px",
  border: "1px solid transparent",
  borderRadius: 12,
  background: "transparent",
  fontFamily: "inherit",
  fontSize: 15,
  fontWeight: 700,
  cursor: "pointer",
};

export const modalPrimaryButton: CSSProperties = {
  minHeight: 50,
};

export type ModalPalette = {
  backdrop: string;
  panel: string;
  surface: string;
  text: string;
  muted: string;
  subtle: string;
  border: string;
  primary: string;
  primaryText: string;
  success: string;
  successSurface: string;
  error: string;
  errorSurface: string;
};

export function modalPalette(theme: "light" | "dark"): ModalPalette {
  return theme === "dark" ? {
    backdrop: "rgba(0, 0, 0, 0.72)",
    panel: "#18181b",
    surface: "#27272a",
    text: "#fafafa",
    muted: "#a1a1aa",
    subtle: "#71717a",
    border: "#3f3f46",
    primary: "#fafafa",
    primaryText: "#18181b",
    success: "#4ade80",
    successSurface: "rgba(34, 197, 94, 0.14)",
    error: "#fb7185",
    errorSurface: "rgba(244, 63, 94, 0.14)",
  } : {
    backdrop: "rgba(15, 23, 42, 0.38)",
    panel: "#ffffff",
    surface: "#f5f6fa",
    text: "#111827",
    muted: "#667085",
    subtle: "#98a2b3",
    border: "#d9deea",
    primary: "#111827",
    primaryText: "#ffffff",
    success: "#17824f",
    successSurface: "#e8f8ef",
    error: "#c62f3c",
    errorSurface: "#fff0f1",
  };
}

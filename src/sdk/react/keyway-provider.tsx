"use client";

import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type CSSProperties,
  type ReactNode,
} from "react";
import { KeyWayApiClient } from "../browser/api-client";
import { connectKeyWay, type ConnectedKeyWay } from "../browser/connect-keyway";
import type { ConfirmFunding, FundingPreview } from "../browser/remote-ckb-signer";

export type KeyWayStatus = "idle" | "authenticating" | "connecting" | "connected" | "disconnecting" | "error";

export type KeyWayProviderProps = {
  children: ReactNode;
  appName?: string;
  theme?: "light" | "dark";
  confirmFunding?: ConfirmFunding;
  autoConnect?: boolean;
  onError?: (error: Error) => void;
};

export type KeyWayUser = { id: string };

export type KeyWayContextValue = {
  ready: boolean;
  authenticated: boolean;
  user?: KeyWayUser;
  connection?: ConnectedKeyWay;
  status: KeyWayStatus;
  error?: Error;
  login: () => void;
  logout: () => Promise<void>;
  connect: () => Promise<ConnectedKeyWay>;
  disconnect: () => Promise<void>;
};

const KeyWayContext = createContext<KeyWayContextValue | undefined>(undefined);

export function KeyWayProvider({
  children,
  appName = "CKB KeyWay",
  theme = "light",
  confirmFunding,
  autoConnect = true,
  onError,
}: KeyWayProviderProps) {
  const resolvedAppName = appName.trim().slice(0, 64) || "CKB KeyWay";
  const connectionRef = useRef<ConnectedKeyWay | undefined>(undefined);
  const operationRef = useRef<Promise<void>>(Promise.resolve());
  const runRef = useRef(0);
  const callbacksRef = useRef({ confirmFunding, onError });
  callbacksRef.current = { confirmFunding, onError };
  const [connection, setConnection] = useState<ConnectedKeyWay>();
  const [status, setStatus] = useState<KeyWayStatus>("idle");
  const [error, setError] = useState<Error>();
  const [authToken, setAuthToken] = useState<string>();
  const [user, setUser] = useState<KeyWayUser>();
  const [ready, setReady] = useState(false);
  const [loginOpen, setLoginOpen] = useState(false);
  const [fundingRequest, setFundingRequest] = useState<{
    preview: FundingPreview;
    resolve: (approved: boolean) => void;
  }>();
  const authenticated = ready && Boolean(authToken && user);

  async function connect() {
    if (!authToken) throw new Error("Log in before connecting KeyWay");
    const run = ++runRef.current;
    setStatus("connecting");
    setError(undefined);
    const previousOperation = operationRef.current;
    const operation = (async () => {
      await previousOperation;
      if (run !== runRef.current) throw new Error("KeyWay connection was superseded");
      const previous = connectionRef.current;
      connectionRef.current = undefined;
      setConnection(undefined);
      if (previous) await previous.keyway.stop();

      try {
        const next = await connectKeyWay({
          authToken,
          confirmFunding: (preview) => callbacksRef.current.confirmFunding?.(preview) ??
            new Promise<boolean>((resolve) => setFundingRequest({ preview, resolve })),
          onLeaseLost: (leaseError) => {
            if (run !== runRef.current) return;
            connectionRef.current = undefined;
            setConnection(undefined);
            setError(leaseError);
            setStatus("error");
            callbacksRef.current.onError?.(leaseError);
          },
        });
        if (run !== runRef.current) {
          await next.keyway.stop();
          throw new Error("KeyWay connection was superseded");
        }
        connectionRef.current = next;
        setConnection(next);
        setStatus("connected");
        return next;
      } catch (cause) {
        const nextError = cause instanceof Error ? cause : new Error("Could not connect KeyWay");
        if (run === runRef.current) {
          setError(nextError);
          setStatus("error");
          callbacksRef.current.onError?.(nextError);
        }
        throw nextError;
      }
    })();
    operationRef.current = operation.then(() => undefined, () => undefined);
    return operation;
  }

  async function disconnect() {
    ++runRef.current;
    fundingRequest?.resolve(false);
    setFundingRequest(undefined);
    const current = connectionRef.current;
    connectionRef.current = undefined;
    setConnection(undefined);
    if (!current) {
      setStatus("idle");
      return;
    }
    setStatus("disconnecting");
    try {
      await current.keyway.stop();
    } finally {
      setStatus("idle");
    }
  }

  function login() {
    setStatus("authenticating");
    setLoginOpen(true);
  }

  async function logout() {
    await disconnect();
    const token = authToken;
    clearStoredSession();
    setAuthToken(undefined);
    setUser(undefined);
    if (token) await new KeyWayApiClient().logout(token).catch(() => undefined);
  }

  useEffect(() => {
    let active = true;
    setReady(false);
    const stored = readStoredSession();
    if (!stored) {
      setReady(true);
      return;
    }
    void new KeyWayApiClient().session(stored.authToken).then(({ user: currentUser }) => {
      if (!active) return;
      setAuthToken(stored.authToken);
      setUser(currentUser);
    }).catch(() => {
      clearStoredSession();
    }).finally(() => {
      if (active) setReady(true);
    });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (!authenticated) {
      setConnection(undefined);
      setError(undefined);
      if (ready) setStatus(loginOpen ? "authenticating" : "idle");
      return;
    }
    setLoginOpen(false);
    if (!autoConnect) return;
    void connect().catch(() => undefined);
    return () => {
      ++runRef.current;
      const current = connectionRef.current;
      connectionRef.current = undefined;
      if (current) void current.keyway.stop();
    };
  }, [authenticated, autoConnect]);

  return (
    <KeyWayContext.Provider value={{
      ready,
      authenticated,
      user,
      connection,
      status,
      error,
      login,
      logout,
      connect,
      disconnect,
    }}>
      {children}
      {loginOpen && !authenticated ? (
        <KeyWayLoginModal
          appName={resolvedAppName}
          theme={theme}
          close={() => {
            setLoginOpen(false);
            setStatus("idle");
          }}
          authenticated={(session) => {
            storeSession(session);
            setAuthToken(session.authToken);
            setUser(session.user);
            setLoginOpen(false);
          }}
        />
      ) : null}
      {fundingRequest ? (
        <KeyWayFundingModal
          theme={theme}
          preview={fundingRequest.preview}
          answer={(approved) => {
            fundingRequest.resolve(approved);
            setFundingRequest(undefined);
          }}
        />
      ) : null}
    </KeyWayContext.Provider>
  );
}

export function useKeyWay(): KeyWayContextValue {
  const value = useContext(KeyWayContext);
  if (!value) throw new Error("useKeyWay must be used inside KeyWayProvider");
  return value;
}

export type KeyWayLoginButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  loginLabel?: ReactNode;
  logoutLabel?: ReactNode;
  pendingLabel?: ReactNode;
};

export function KeyWayLoginButton({
  loginLabel = "Log in",
  logoutLabel = "Log out",
  pendingLabel = "Loading...",
  disabled,
  onClick,
  ...props
}: KeyWayLoginButtonProps) {
  const { ready, authenticated, status, login, logout } = useKeyWay();
  const pending = !ready || status === "authenticating" || status === "disconnecting";
  return (
    <button
      type="button"
      {...props}
      disabled={disabled || pending}
      onClick={(event) => {
        onClick?.(event);
        if (event.defaultPrevented) return;
        if (authenticated) void logout();
        else login();
      }}
    >
      {pending ? pendingLabel : authenticated ? logoutLabel : loginLabel}
    </button>
  );
}

export type KeyWayConnectButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  connectLabel?: ReactNode;
  connectedLabel?: ReactNode;
  connectingLabel?: ReactNode;
};

export function KeyWayConnectButton({
  connectLabel = "Start Fiber",
  connectedLabel = "Stop Fiber",
  connectingLabel = "Starting...",
  disabled,
  onClick,
  ...props
}: KeyWayConnectButtonProps) {
  const { authenticated, connection, status, login, connect, disconnect } = useKeyWay();
  const pending = status === "connecting" || status === "disconnecting";
  return (
    <button
      type="button"
      {...props}
      disabled={disabled || pending}
      onClick={(event) => {
        onClick?.(event);
        if (event.defaultPrevented) return;
        if (!authenticated) return login();
        void (connection ? disconnect() : connect()).catch(() => undefined);
      }}
    >
      {pending ? connectingLabel : connection ? connectedLabel : connectLabel}
    </button>
  );
}

function KeyWayLoginModal({
  appName,
  theme,
  close,
  authenticated,
}: {
  appName: string;
  theme: "light" | "dark";
  close: () => void;
  authenticated: (session: StoredSession) => void;
}) {
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [methodId, setMethodId] = useState<string>();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string>();
  const [verificationState, setVerificationState] = useState<"idle" | "success" | "error">("idle");
  const [codeFocused, setCodeFocused] = useState(false);
  const codeInputRef = useRef<HTMLInputElement>(null);
  const palette = modalPalette(theme);

  async function submit() {
    setPending(true);
    setError(undefined);
    setVerificationState("idle");
    const api = new KeyWayApiClient();
    try {
      if (!methodId) {
        setMethodId((await api.sendCode(email)).methodId);
        return;
      }
      const result = await api.verifyCode(methodId, code);
      setVerificationState("success");
      await new Promise((resolve) => setTimeout(resolve, 900));
      authenticated({ authToken: result.sessionToken, user: result.user });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not complete email login");
      if (methodId) setVerificationState("error");
    } finally {
      setPending(false);
    }
  }

  async function resend() {
    setPending(true);
    setError(undefined);
    setCode("");
    setVerificationState("idle");
    try {
      setMethodId((await new KeyWayApiClient().sendCode(email)).methodId);
      codeInputRef.current?.focus();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not resend the code");
    } finally {
      setPending(false);
    }
  }

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") close();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [close]);

  useEffect(() => {
    if (methodId && code.length === 6 && !pending && verificationState === "idle") void submit();
  }, [code, methodId, pending, verificationState]);

  useEffect(() => {
    if (!methodId) {
      setCodeFocused(false);
      return;
    }
    codeInputRef.current?.focus();
    setCodeFocused(document.activeElement === codeInputRef.current);
  }, [methodId]);

  const codeColor = verificationState === "success" ? palette.success
    : verificationState === "error" ? palette.error
    : palette.border;
  const codeBackground = verificationState === "success" ? palette.successSurface
    : verificationState === "error" ? palette.errorSurface
    : palette.surface;

  return (
    <div
      role="presentation"
      style={{ ...modalBackdrop, background: palette.backdrop }}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) close();
      }}
    >
      <section role="dialog" aria-modal="true" aria-labelledby="keyway-login-title" style={{ ...modalPanel, background: palette.panel, borderColor: palette.border, color: palette.text }}>
        <style>{`@keyframes ckb-keyway-caret { 0%, 45% { opacity: 1; } 46%, 100% { opacity: 0; } }`}</style>
        {!methodId ? (
          <button type="button" aria-label="Close login" onClick={close} style={{ ...modalClose, color: palette.muted }}>&times;</button>
        ) : (
          <button type="button" aria-label="Back" disabled={pending} style={{ ...modalBack, background: palette.surface, color: palette.muted }} onClick={() => {
            setMethodId(undefined);
            setCode("");
            setError(undefined);
            setVerificationState("idle");
          }}><ArrowLeftIcon /></button>
        )}
        <div style={{ ...modalIcon, background: palette.surface, color: palette.muted }}><MailIcon /></div>
        <p style={{ ...modalEyebrow, color: palette.muted }}>{appName}</p>
        <h2 id="keyway-login-title" style={modalTitle}>{methodId ? "Enter confirmation code" : "Log in or sign up"}</h2>
        <p style={{ ...modalCopy, color: palette.muted }}>{methodId
          ? <>Check <strong style={{ color: palette.text }}>{email}</strong> for a six-digit code.</>
          : `Use your email to continue to ${appName}.`}</p>
        <form onSubmit={(event) => {
          event.preventDefault();
          if (!methodId || code.length === 6) void submit();
        }}>
          {!methodId ? (
            <label style={{ ...modalLabel, color: palette.muted }}>
              Email address
              <input
                autoFocus
                required
                type="email"
                autoComplete="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="you@example.com"
                style={{ ...modalInput, background: palette.surface, borderColor: palette.border, color: palette.text }}
              />
            </label>
          ) : (
            <label style={otpLabel} onClick={() => codeInputRef.current?.focus()}>
              <span style={visuallyHidden}>One-time code</span>
              <span style={otpSlots}>
                {Array.from({ length: 6 }, (_, index) => {
                  const active = codeFocused && code.length < 6 && index === code.length;
                  return (
                    <span key={index} aria-hidden="true" style={{
                      ...otpSlot,
                      borderColor: active ? palette.text : codeColor,
                      background: codeBackground,
                      color: palette.text,
                      boxShadow: active ? `0 0 0 1px ${palette.text}` : undefined,
                    }}>
                      {code[index] ?? (active ? <span style={{ ...otpCaret, background: palette.text }} /> : "")}
                    </span>
                  );
                })}
              </span>
              <input
                ref={codeInputRef}
                autoFocus
                required
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6}"
                maxLength={6}
                value={code}
                onFocus={() => setCodeFocused(true)}
                onBlur={() => setCodeFocused(false)}
                onChange={(event) => {
                  setCode(event.target.value.replace(/\D/g, "").slice(0, 6));
                  setError(undefined);
                  setVerificationState("idle");
                }}
                style={otpInput}
              />
            </label>
          )}
          {verificationState === "success" ? <p role="status" style={{ ...modalStatus, color: palette.success }}>Code verified</p> : null}
          {methodId && pending && verificationState === "idle" ? <p role="status" style={{ ...modalStatus, color: palette.muted }}>Checking code...</p> : null}
          {error ? <p role="alert" style={{ ...modalStatus, color: palette.error }}>{friendlyOtpError(error)}</p> : null}
          {!methodId ? (
            <button type="submit" disabled={pending} style={{ ...modalButton, ...modalPrimaryButton, background: palette.primary, color: palette.primaryText }}>
              {pending ? "Sending code..." : "Continue"}
            </button>
          ) : (
            <p style={{ ...resendCopy, color: palette.muted }}>Didn't get an email?{" "}
              <button type="button" disabled={pending} style={{ ...resendButton, color: palette.text }} onClick={() => void resend()}>
                {pending ? "Sending..." : "Resend code"}
              </button>
            </p>
          )}
        </form>
        <p style={{ ...modalFootnote, color: palette.subtle }}>Secured by <strong>CKB KeyWay</strong></p>
      </section>
    </div>
  );
}

function friendlyOtpError(message: string): string {
  if (/code|otp|authenticate|invalid/i.test(message)) return "Incorrect or expired code";
  return message;
}

function ArrowLeftIcon() {
  return <svg aria-hidden="true" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m15 18-6-6 6-6" /></svg>;
}

function MailIcon() {
  return <svg aria-hidden="true" width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect width="18" height="14" x="3" y="5" rx="2" /><path d="m3 7 9 6 9-6" /></svg>;
}

function KeyWayFundingModal({
  theme,
  preview,
  answer,
}: {
  theme: "light" | "dark";
  preview: FundingPreview;
  answer: (approved: boolean) => void;
}) {
  const palette = modalPalette(theme);
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") answer(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [answer]);

  return (
    <div role="presentation" style={{ ...modalBackdrop, background: palette.backdrop }}>
      <section role="dialog" aria-modal="true" aria-labelledby="keyway-funding-title" style={{ ...modalPanel, background: palette.panel, borderColor: palette.border, color: palette.text }}>
        <p style={{ ...modalEyebrow, color: palette.muted }}>ON-CHAIN CONFIRMATION</p>
        <h2 id="keyway-funding-title" style={modalTitle}>Activate Fiber payments?</h2>
        <dl style={fundingDetails}>
          <dt>Channel funding</dt><dd>{preview.amountCkb} CKB</dd>
          <dt>Network fee</dt><dd>{preview.feeCkb} CKB</dd>
          <dt>Network</dt><dd>CKB testnet</dd>
        </dl>
        <p style={{ ...modalCopy, color: palette.muted }}>This locks testnet CKB into a payment channel. It does not send funds to another wallet.</p>
        <div style={modalActions}>
          <button type="button" autoFocus style={{ ...modalButton, borderColor: palette.border, color: palette.text }} onClick={() => answer(false)}>Cancel</button>
          <button type="button" style={{ ...modalButton, ...modalPrimaryButton, background: palette.primary, color: palette.primaryText }} onClick={() => answer(true)}>Confirm activation</button>
        </div>
      </section>
    </div>
  );
}

type StoredSession = { authToken: string; user: KeyWayUser };

const SESSION_STORAGE_KEY = "ckb-keyway.session";

function readStoredSession(): StoredSession | undefined {
  try {
    const value: unknown = JSON.parse(localStorage.getItem(SESSION_STORAGE_KEY) ?? "null");
    if (!value || typeof value !== "object") return;
    const { authToken, user } = value as Partial<StoredSession>;
    if (typeof authToken !== "string" || !user || typeof user.id !== "string") return;
    return { authToken, user };
  } catch {
    return;
  }
}

function storeSession(session: StoredSession): void {
  localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
}

function clearStoredSession(): void {
  localStorage.removeItem(SESSION_STORAGE_KEY);
}

const modalBackdrop: CSSProperties = {
  position: "fixed",
  inset: 0,
  zIndex: 2147483647,
  display: "grid",
  placeItems: "center",
  overflowY: "auto",
  padding: "24px",
  backdropFilter: "blur(6px)",
};

const modalPanel: CSSProperties = {
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

const modalClose: CSSProperties = {
  position: "absolute",
  top: 16,
  right: 18,
  border: 0,
  background: "transparent",
  fontSize: 26,
  lineHeight: 1,
  cursor: "pointer",
};

const modalBack: CSSProperties = {
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

const modalIcon: CSSProperties = {
  display: "grid",
  placeItems: "center",
  width: 68,
  height: 68,
  margin: "2px auto 18px",
  borderRadius: "50%",
};

const modalEyebrow: CSSProperties = {
  margin: "0 0 8px",
  fontSize: 12,
  fontWeight: 700,
  letterSpacing: "0.08em",
  textTransform: "uppercase",
};

const modalTitle: CSSProperties = {
  margin: "0 0 10px",
  fontSize: "clamp(25px, 6vw, 32px)",
  fontWeight: 700,
  lineHeight: 1.15,
  letterSpacing: "-0.025em",
};

const modalCopy: CSSProperties = {
  margin: "0 auto 26px",
  maxWidth: 340,
  fontSize: 15,
  lineHeight: 1.55,
};

const modalFootnote: CSSProperties = {
  margin: "28px 0 0",
  fontSize: 12,
  lineHeight: 1.5,
};

const modalLabel: CSSProperties = {
  display: "grid",
  gap: 8,
  textAlign: "left",
  fontSize: 13,
  fontWeight: 600,
};

const modalInput: CSSProperties = {
  width: "100%",
  boxSizing: "border-box",
  minHeight: 52,
  border: "1px solid",
  borderRadius: 12,
  padding: "0 15px",
  font: "16px 'Avenir Next', Avenir, ui-sans-serif, sans-serif",
};

const otpLabel: CSSProperties = {
  position: "relative",
  display: "block",
  cursor: "text",
};

const otpSlots: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(6, minmax(0, 1fr))",
  gap: 8,
};

const otpSlot: CSSProperties = {
  display: "grid",
  placeItems: "center",
  aspectRatio: "0.82",
  border: "1.5px solid",
  borderRadius: 12,
  fontSize: "clamp(22px, 6vw, 28px)",
  fontWeight: 700,
  transition: "border-color 160ms ease, background 160ms ease",
};

const otpInput: CSSProperties = {
  position: "absolute",
  inset: 0,
  width: "100%",
  height: "100%",
  opacity: 0,
  cursor: "text",
};

const otpCaret: CSSProperties = {
  width: 2,
  height: "38%",
  minHeight: 24,
  borderRadius: 2,
  animation: "ckb-keyway-caret 1s step-end infinite",
};

const visuallyHidden: CSSProperties = {
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

const modalStatus: CSSProperties = {
  minHeight: 21,
  margin: "14px 0 0",
  fontSize: 14,
  fontWeight: 600,
};

const resendCopy: CSSProperties = {
  margin: "26px 0 0",
  fontSize: 14,
};

const resendButton: CSSProperties = {
  padding: 0,
  border: 0,
  borderBottom: "1px solid currentColor",
  background: "transparent",
  font: "inherit",
  cursor: "pointer",
};

const fundingDetails: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "1fr auto",
  gap: "10px 24px",
  margin: "24px 0",
  fontFamily: "ui-monospace, monospace",
  fontSize: 13,
};

const modalActions: CSSProperties = {
  display: "flex",
  justifyContent: "flex-end",
  gap: 10,
  marginTop: 24,
};

const modalButton: CSSProperties = {
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

const modalPrimaryButton: CSSProperties = {
  minHeight: 50,
};

type ModalPalette = {
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

function modalPalette(theme: "light" | "dark"): ModalPalette {
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

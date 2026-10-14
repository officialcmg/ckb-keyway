"use client";

import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type CSSProperties,
  type ReactNode,
} from "react";
import { KeyWayApiClient, KeyWayApiError } from "../browser/api-client";
import { cleanupLegacyDatabases } from "../browser/legacy-cleanup";
import {
  connectKeyWay,
  type ConnectedKeyWay,
  type FiberStartupEvent,
  type FiberStartupStage,
} from "../browser/connect-keyway";
import {
  connectManagedKeyWay,
  type ConnectedManagedKeyWay,
} from "../browser/connect-managed-keyway";
import { bootstrapKeyWay, type PublicWallet } from "../browser/bootstrap";
import type { ApproveFiberChannelOpen, FiberChannelOpenPreview } from "../browser/remote-ckb-signer";
import type { ApproveFiberPayment } from "../browser/fiber-payment";
import type { RequestEmailCode } from "../browser/email-code";
import { KeyWaySigner, type ApproveCkbMessage, type ApproveCkbTransaction, type MessagePreview, type TransactionPreview } from "../browser/keyway-signer";
import { KeyWayChannelCloseModal, KeyWayChannelSettingsModal, KeyWayEmailCodeModal, KeyWayMessageModal, KeyWayPeerModal, KeyWayTransactionModal } from "./signing-modals";
import type { ApproveFiberChannelClose, ApproveFiberChannelSettings, ApproveFiberPeer, FiberChannelClosePreview, FiberChannelSettingsPreview, FiberPeerPreview } from "../browser/fiber-actions";
import {
  modalBackdrop,
  modalPanel,
  modalClose,
  modalBack,
  modalIcon,
  modalEyebrow,
  modalTitle,
  modalCopy,
  modalFootnote,
  modalLabel,
  modalInput,
  otpLabel,
  otpSlots,
  otpSlot,
  otpInput,
  otpCaret,
  visuallyHidden,
  modalStatus,
  resendCopy,
  resendButton,
  fundingDetails,
  modalActions,
  modalButton,
  modalPrimaryButton,
  ModalPalette,
  modalPalette,
} from "./modal-styles";


export type KeyWayStatus = "idle" | "authenticating" | "connecting" | "connected" | "disconnecting" | "error";

export type KeyWayProviderProps = {
  children: ReactNode;
  appId?: string;
  appName?: string;
  theme?: "light" | "dark";
  /** Replaces the built-in dialog for opening a Fiber channel. Return false to cancel. */
  approveFiberChannelOpen?: ApproveFiberChannelOpen;
  /**
   * Your own confirmation for Fiber payments. Off by default: Fiber is for fast payments, so KeyWay shows no
   * payment dialog. Payments still count toward the user's daily email-confirmation amount.
   */
  approveFiberPayment?: ApproveFiberPayment;
  /** Replaces the built-in dialog for closing a Fiber channel. Return false to cancel. */
  approveFiberChannelClose?: ApproveFiberChannelClose;
  /** Replaces the built-in dialog for connecting to or disconnecting from a Fiber peer. Return false to cancel. */
  approveFiberPeerConnect?: ApproveFiberPeer;
  /** Replaces the built-in dialog for changing a channel's forwarding settings. Return false to cancel. */
  approveFiberChannelSettings?: ApproveFiberChannelSettings;
  /** Replaces the built-in dialog for signing a CKB transaction. Return false to cancel. */
  approveCkbTransaction?: ApproveCkbTransaction;
  /** Replaces the built-in dialog for signing a message. Return false to cancel. */
  approveCkbMessage?: ApproveCkbMessage;
  /** Starts Fiber as soon as the user signs in. Off by default; call `useFiber().start()` instead. */
  autoStartFiber?: boolean;
  /** Where the user's Fiber node runs: on KeyWay's servers (default) or in this page. */
  fiberNode?: FiberNodeKind;
  onError?: (error: Error) => void;
  /** Reports each step of starting the Fiber node after `useFiber().start()`. */
  onFiberStartup?: (event: FiberStartupEvent) => void;
};

export type FiberNodeKind = "hosted" | "browser";
export type KeyWayConnection = ConnectedKeyWay | ConnectedManagedKeyWay;

export type KeyWayUser = { id: string };

export type KeyWayContextValue = {
  ready: boolean;
  authenticated: boolean;
  user?: KeyWayUser;
  fiberNode: FiberNodeKind;
  connection?: KeyWayConnection;
  wallet?: PublicWallet;
  /** A CCC signer for the signed-in account, once its wallet is ready. */
  signer?: KeyWaySigner;
  status: KeyWayStatus;
  error?: Error;
  walletReady: boolean;
  fiberStarting: boolean;
  fiberReady: boolean;
  fiberError?: Error;
  fiberStartupStage?: FiberStartupStage;
  fiberStartupTimings: Partial<Record<FiberStartupStage, number>>;
  login: () => void;
  logout: () => Promise<void>;
  startFiber: () => Promise<KeyWayConnection>;
  stopFiber: () => Promise<void>;
};

const KeyWayContext = createContext<KeyWayContextValue | undefined>(undefined);

export function KeyWayProvider({
  children,
  appId,
  appName = "CKB KeyWay",
  theme = "light",
  approveFiberChannelOpen,
  approveFiberPayment,
  approveFiberChannelClose,
  approveFiberPeerConnect,
  approveFiberChannelSettings,
  approveCkbTransaction,
  approveCkbMessage,
  autoStartFiber = false,
  fiberNode = "hosted",
  onError,
  onFiberStartup,
}: KeyWayProviderProps) {
  const resolvedAppName = appName.trim().slice(0, 64) || "CKB KeyWay";
  const api = new KeyWayApiClient({ appId });
  const connectionRef = useRef<KeyWayConnection | undefined>(undefined);
  const operationRef = useRef<Promise<void>>(Promise.resolve());
  const runRef = useRef(0);
  const callbacksRef = useRef({ approveFiberChannelOpen, approveFiberPayment, approveFiberChannelClose, approveFiberPeerConnect, approveFiberChannelSettings, approveCkbTransaction, approveCkbMessage, onError, onFiberStartup });
  callbacksRef.current = { approveFiberChannelOpen, approveFiberPayment, approveFiberChannelClose, approveFiberPeerConnect, approveFiberChannelSettings, approveCkbTransaction, approveCkbMessage, onError, onFiberStartup };
  const [connection, setConnection] = useState<KeyWayConnection>();
  const [wallet, setWallet] = useState<PublicWallet>();
  const [status, setStatus] = useState<KeyWayStatus>("idle");
  const [error, setError] = useState<Error>();
  const [fiberError, setFiberError] = useState<Error>();
  const [fiberStartupStage, setFiberStartupStage] = useState<FiberStartupStage>();
  const [fiberStartupTimings, setFiberStartupTimings] = useState<Partial<Record<FiberStartupStage, number>>>({});
  const [authToken, setAuthToken] = useState<string>();
  const [expiresAt, setExpiresAt] = useState<string>();
  const [user, setUser] = useState<KeyWayUser>();
  const [ready, setReady] = useState(false);
  const [loginOpen, setLoginOpen] = useState(false);
  const [transactionRequest, setTransactionRequest] = useState<{ preview: TransactionPreview; resolve: (approved: boolean) => void }>();
  const [messageRequest, setMessageRequest] = useState<{ preview: MessagePreview; resolve: (approved: boolean) => void }>();
  const [codeRequest, setCodeRequest] = useState<{
    reason: "transaction" | "settings" | "payment";
    error?: string;
    resend: () => Promise<void>;
    resolve: (code: string | undefined) => void;
  }>();
  const [actionRequest, setActionRequest] = useState<
    | { kind: "close"; preview: FiberChannelClosePreview; resolve: (approved: boolean) => void }
    | { kind: "peer"; preview: FiberPeerPreview; resolve: (approved: boolean) => void }
    | { kind: "settings"; preview: FiberChannelSettingsPreview; resolve: (approved: boolean) => void }
  >();
  const [fundingRequest, setFundingRequest] = useState<{
    preview: FiberChannelOpenPreview;
    resolve: (approved: boolean) => void;
  }>();
  const authenticated = ready && Boolean(authToken && user);

  // The code prompt is always the SDK's own, even when an app brings its own approval UI.
  const requestEmailCode: RequestEmailCode = (request) => new Promise<string | undefined>((resolve) => setCodeRequest({ ...request, resolve }));

  async function connect() {
    if (!authToken) throw new Error("Log in before connecting KeyWay");
    const run = ++runRef.current;
    setStatus("connecting");
    setError(undefined);
    setFiberError(undefined);
    setFiberStartupTimings({});
    const previousOperation = operationRef.current;
    const operation = (async () => {
      await previousOperation;
      if (run !== runRef.current) throw new Error("KeyWay connection was superseded");
      const previous = connectionRef.current;
      connectionRef.current = undefined;
      setConnection(undefined);
      if (previous) await previous.keyway.stop();

      try {
        const connectNode = fiberNode === "hosted" ? connectManagedKeyWay : connectKeyWay;
        const next = await connectNode({
          authToken,
          apiClient: api,
          approveFiberChannelOpen: (preview) => {
            if (run !== runRef.current) return false;
            return callbacksRef.current.approveFiberChannelOpen?.(preview) ??
              new Promise<boolean>((resolve) => setFundingRequest({ preview, resolve }));
          },
          // Read at payment time, so an app can add or drop its own confirmation without restarting Fiber.
          approveFiberPayment: (preview) => callbacksRef.current.approveFiberPayment?.(preview) ?? true,
          requestEmailCode,
          // Each reads the app's prop at the time of the action, falling back to the built-in dialog.
          approvals: () => ({
            approveFiberChannelClose: (preview) => callbacksRef.current.approveFiberChannelClose?.(preview) ??
              new Promise<boolean>((resolve) => setActionRequest({ kind: "close", preview, resolve })),
            approveFiberPeerConnect: (preview) => callbacksRef.current.approveFiberPeerConnect?.(preview) ??
              new Promise<boolean>((resolve) => setActionRequest({ kind: "peer", preview, resolve })),
            approveFiberChannelSettings: (preview) => callbacksRef.current.approveFiberChannelSettings?.(preview) ??
              new Promise<boolean>((resolve) => setActionRequest({ kind: "settings", preview, resolve })),
          }),
          ...(fiberNode === "browser" ? { onLeaseLost: (leaseError: Error) => {
            if (run !== runRef.current) return;
            connectionRef.current = undefined;
            setConnection(undefined);
            setError(leaseError);
            setFiberError(leaseError);
            setStatus("error");
            callbacksRef.current.onError?.(leaseError);
          } } : {}),
          onWalletReady: (nextWallet) => {
            if (run === runRef.current) setWallet(nextWallet);
          },
          onFiberStartup: (event) => {
            if (run !== runRef.current) return;
            setFiberStartupStage(event.stage);
            setFiberStartupTimings((current) => ({ ...current, [event.stage]: event.elapsedMs }));
            callbacksRef.current.onFiberStartup?.(event);
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
          setFiberError(nextError);
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
    actionRequest?.resolve(false);
    setActionRequest(undefined);
    const current = connectionRef.current;
    connectionRef.current = undefined;
    setConnection(undefined);
    if (!current) {
      setStatus("idle");
      setFiberStartupStage(undefined);
      return;
    }
    setStatus("disconnecting");
    try {
      await current.keyway.stop();
    } finally {
      setStatus("idle");
      setFiberStartupStage(undefined);
    }
  }

  function login() {
    setStatus("authenticating");
    setLoginOpen(true);
  }

  async function logout() {
    const token = authToken;
    ++runRef.current;
    fundingRequest?.resolve(false);
    setFundingRequest(undefined);
    setStatus("disconnecting");
    setError(undefined);
    await operationRef.current;
    const current = connectionRef.current;
    try {
      if (current) await current.keyway.stopForLogout();
      if (token) await api.logout(token);
      ++runRef.current;
      connectionRef.current = undefined;
      setConnection(undefined);
      setWallet(undefined);
      clearStoredSession(appId);
      setAuthToken(undefined);
      setExpiresAt(undefined);
      setUser(undefined);
      setStatus("idle");
      setFiberError(undefined);
      setFiberStartupStage(undefined);
    } catch (cause) {
      const logoutError = cause instanceof Error ? cause : new Error("Could not safely back up and log out");
      if (current) await connect().catch(() => undefined);
      setError(logoutError);
      setStatus("error");
      callbacksRef.current.onError?.(logoutError);
      throw logoutError;
    }
  }

  useEffect(() => {
    let active = true;
    void api.legacyCleanup().then((manifest) => {
      if (manifest.epoch && manifest.prefixes.length) return cleanupLegacyDatabases(manifest);
    }).catch(() => { /* Retry on the next visit; never delete unapproved state. */ });
    setReady(false);
    setAuthToken(undefined);
    setUser(undefined);
    const stored = readStoredSession(appId);
    if (!stored) {
      setReady(true);
      return;
    }
    void api.session(stored.authToken).then(({ user: currentUser, expiresAt, sessionToken }) => {
      if (!active) return;
      const token = sessionToken ?? stored.authToken;
      storeSession({ authToken: token, user: currentUser, appId, expiresAt });
      setAuthToken(token);
      setExpiresAt(expiresAt);
      setUser(currentUser);
    }).catch(() => {
      if (active) clearStoredSession(appId);
    }).finally(() => {
      if (active) setReady(true);
    });
    return () => { active = false; };
  }, [appId]);

  useEffect(() => {
    if (!authToken || !expiresAt) return;
    let active = true;
    const invalidate = () => {
      ++runRef.current;
      const current = connectionRef.current;
      connectionRef.current = undefined;
      if (current) void current.keyway.stop().catch(() => undefined);
      clearStoredSession(appId);
      setAuthToken(undefined);
      setUser(undefined);
      setExpiresAt(undefined);
    };
    const validate = async () => {
      try {
        const session = await api.session(authToken);
        if (!active) return;
        const token = session.sessionToken ?? authToken;
        storeSession({ authToken: token, user: session.user, appId, expiresAt: session.expiresAt });
        setAuthToken(token);
        setExpiresAt(session.expiresAt);
      } catch (cause) {
        // A network failure is not proof of revocation; expiry remains enforced.
        if (active && ((cause instanceof KeyWayApiError && cause.status === 401) || Date.now() >= Date.parse(expiresAt))) invalidate();
      }
    };
    const expiry = window.setTimeout(invalidate, Math.min(2_147_483_647, Math.max(0, Date.parse(expiresAt) - Date.now())));
    const renewal = window.setInterval(() => void validate(), 15 * 60_000);
    const focus = () => { if (document.visibilityState === "visible") void validate(); };
    window.addEventListener("focus", focus);
    document.addEventListener("visibilitychange", focus);
    return () => {
      active = false;
      clearTimeout(expiry);
      clearInterval(renewal);
      window.removeEventListener("focus", focus);
      document.removeEventListener("visibilitychange", focus);
    };
  }, [authToken, expiresAt, appId]);

  useEffect(() => {
    if (!authenticated) {
      setConnection(undefined);
      setError(undefined);
      setWallet(undefined);
      setFiberError(undefined);
      setFiberStartupStage(undefined);
      if (ready) setStatus(loginOpen ? "authenticating" : "idle");
      return;
    }
    setLoginOpen(false);
    let active = true;
    if (autoStartFiber) {
      void connect().catch(() => undefined);
    } else {
      setError(undefined);
      // Managed bootstrap recovers identity without claiming browser state or starting a node.
      void bootstrapKeyWay(authToken!, api, "managed").then(({ wallet: nextWallet }) => {
        if (!active) return;
        setWallet(nextWallet);
        setStatus((current) => current === "authenticating" ? "idle" : current);
      }).catch((cause) => {
        if (!active) return;
        const recoveryError = cause instanceof Error ? cause : new Error("Could not recover CKB account");
        setError(recoveryError);
        callbacksRef.current.onError?.(recoveryError);
      });
    }
    return () => {
      active = false;
      ++runRef.current;
      const current = connectionRef.current;
      connectionRef.current = undefined;
      if (current) void current.keyway.stop();
    };
  }, [authenticated, authToken, appId, autoStartFiber, fiberNode]);

  const signer = useMemo(() => {
    if (!wallet || !authToken) return undefined;
    return new KeyWaySigner(authToken, wallet.litPublicKey, {
      approveCkbTransaction: (preview) => callbacksRef.current.approveCkbTransaction?.(preview) ??
        new Promise<boolean>((resolve) => setTransactionRequest({ preview, resolve })),
      approveCkbMessage: (preview) => callbacksRef.current.approveCkbMessage?.(preview) ??
        new Promise<boolean>((resolve) => setMessageRequest({ preview, resolve })),
      requestEmailCode,
    }, undefined, new KeyWayApiClient({ appId }));
  }, [wallet?.litPublicKey, authToken, appId]);

  return (
    <KeyWayContext.Provider value={{
      ready,
      authenticated,
      user,
      fiberNode,
      connection,
      wallet,
      signer,
      status,
      error,
      walletReady: Boolean(wallet),
      fiberStarting: status === "connecting",
      fiberReady: Boolean(connection),
      fiberError,
      fiberStartupStage,
      fiberStartupTimings,
      login,
      logout,
      startFiber: connect,
      stopFiber: disconnect,
    }}>
      {children}
      {loginOpen && !authenticated ? (
        <KeyWayLoginModal
          api={api}
          appName={resolvedAppName}
          theme={theme}
          close={() => {
            setLoginOpen(false);
            setStatus("idle");
          }}
          authenticated={(session) => {
            storeSession({ ...session, appId });
            setAuthToken(session.authToken);
            setExpiresAt(session.expiresAt);
            setUser(session.user);
            setLoginOpen(false);
          }}
        />
      ) : null}
      {transactionRequest ? (
        <KeyWayTransactionModal
          theme={theme}
          appName={resolvedAppName}
          preview={transactionRequest.preview}
          answer={(approved) => { transactionRequest.resolve(approved); setTransactionRequest(undefined); }}
        />
      ) : null}
      {messageRequest ? (
        <KeyWayMessageModal
          theme={theme}
          appName={resolvedAppName}
          preview={messageRequest.preview}
          answer={(approved) => { messageRequest.resolve(approved); setMessageRequest(undefined); }}
        />
      ) : null}
      {codeRequest ? (
        <KeyWayEmailCodeModal
          key={codeRequest.error ?? "first"}
          theme={theme}
          reason={codeRequest.reason}
          error={codeRequest.error}
          resend={codeRequest.resend}
          answer={(code) => { codeRequest.resolve(code); setCodeRequest(undefined); }}
        />
      ) : null}
      {actionRequest ? (() => {
        const answer = (approved: boolean) => { actionRequest.resolve(approved); setActionRequest(undefined); };
        if (actionRequest.kind === "close") return <KeyWayChannelCloseModal theme={theme} appName={resolvedAppName} preview={actionRequest.preview} answer={answer} />;
        if (actionRequest.kind === "peer") return <KeyWayPeerModal theme={theme} appName={resolvedAppName} preview={actionRequest.preview} answer={answer} />;
        return <KeyWayChannelSettingsModal theme={theme} appName={resolvedAppName} preview={actionRequest.preview} answer={answer} />;
      })() : null}
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

export function useKeyWayContext(): KeyWayContextValue {
  const value = useContext(KeyWayContext);
  if (!value) throw new Error("useKeyWay must be used inside KeyWayProvider");
  return value;
}

export function useKeyWay() {
  const { ready, authenticated, user, login, logout } = useKeyWayContext();
  return { ready, authenticated, user, login, logout };
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
  const { ready, authenticated, status, login, logout } = useKeyWayContext();
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

export type KeyWayFiberButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  startLabel?: ReactNode;
  stopLabel?: ReactNode;
  startingLabel?: ReactNode;
};

/** Starts or stops the user's Fiber node, asking them to sign in first if needed. */
export function KeyWayFiberButton({
  startLabel = "Start Fiber",
  stopLabel = "Stop Fiber",
  startingLabel = "Starting...",
  disabled,
  onClick,
  ...props
}: KeyWayFiberButtonProps) {
  const { authenticated, connection, status, login, startFiber: connect, stopFiber: disconnect } = useKeyWayContext();
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
      {pending ? startingLabel : connection ? stopLabel : startLabel}
    </button>
  );
}

function KeyWayLoginModal({
  api,
  appName,
  theme,
  close,
  authenticated,
}: {
  api: KeyWayApiClient;
  appName: string;
  theme: "light" | "dark";
  close: () => void;
  authenticated: (session: StoredSession) => void;
}) {
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [challengeId, setChallengeId] = useState<string>();
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
    try {
      if (!challengeId) {
        setChallengeId((await api.sendCode(email)).challengeId);
        return;
      }
      const result = await api.verifyCode(challengeId, code);
      setVerificationState("success");
      await new Promise((resolve) => setTimeout(resolve, 900));
      authenticated({ authToken: result.sessionToken, user: result.user, expiresAt: result.expiresAt });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not complete email login");
      if (challengeId) setVerificationState("error");
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
      setChallengeId((await api.sendCode(email)).challengeId);
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
    if (challengeId && code.length === 6 && !pending && verificationState === "idle") void submit();
  }, [code, challengeId, pending, verificationState]);

  useEffect(() => {
    if (!challengeId) {
      setCodeFocused(false);
      return;
    }
    codeInputRef.current?.focus();
    setCodeFocused(document.activeElement === codeInputRef.current);
  }, [challengeId]);

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
        {!challengeId ? (
          <button type="button" aria-label="Close login" onClick={close} style={{ ...modalClose, color: palette.muted }}>&times;</button>
        ) : (
          <button type="button" aria-label="Back" disabled={pending} style={{ ...modalBack, background: palette.surface, color: palette.muted }} onClick={() => {
            setChallengeId(undefined);
            setCode("");
            setError(undefined);
            setVerificationState("idle");
          }}><ArrowLeftIcon /></button>
        )}
        <div style={{ ...modalIcon, background: palette.surface, color: palette.muted }}><MailIcon /></div>
        <p style={{ ...modalEyebrow, color: palette.muted }}>{appName}</p>
        <h2 id="keyway-login-title" style={modalTitle}>{challengeId ? "Enter confirmation code" : "Log in or sign up"}</h2>
        <p style={{ ...modalCopy, color: palette.muted }}>{challengeId
          ? <>Check <strong style={{ color: palette.text }}>{email}</strong> for a six-digit code.</>
          : `Use your email to continue to ${appName}.`}</p>
        <form onSubmit={(event) => {
          event.preventDefault();
          if (!challengeId || code.length === 6) void submit();
        }}>
          {!challengeId ? (
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
          {challengeId && pending && verificationState === "idle" ? <p role="status" style={{ ...modalStatus, color: palette.muted }}>Checking code...</p> : null}
          {error ? <p role="alert" style={{ ...modalStatus, color: palette.error }}>{friendlyOtpError(error)}</p> : null}
          {!challengeId ? (
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
  preview: FiberChannelOpenPreview;
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
          {preview.token && <><dt>Channel funding</dt><dd>{preview.token.amountText}</dd></>}
          <dt>{preview.token ? "CKB reserve" : "Channel funding"}</dt><dd>{preview.amountCkb} CKB</dd>
          {preview.peer && <><dt>Peer</dt><dd style={{ overflowWrap: "anywhere" }}>{preview.peer.slice(0, 12)}…{preview.peer.slice(-6)}</dd></>}
          {preview.feeReserveCkb && <><dt>Fee reserve</dt><dd>{preview.feeReserveCkb} CKB</dd></>}
          <dt>Network fee</dt><dd>{preview.feeCkb} CKB</dd>
          <dt>Network</dt><dd>CKB testnet</dd>
        </dl>
        <p style={{ ...modalCopy, color: palette.muted }}>{preview.token ? "This locks the token, and some CKB as a reserve," : "This locks testnet CKB"} into a payment channel. It does not send funds to another wallet, and a normal close returns your side to your own account.</p>
        {preview.feeReserveCkb && <p style={{ ...modalCopy, color: palette.muted }}>The fee reserve stays on your own Fiber node so it can claim your funds if a channel is ever force-closed. You get it back once all your channels are closed.</p>}
        <div style={modalActions}>
          <button type="button" autoFocus style={{ ...modalButton, borderColor: palette.border, color: palette.text }} onClick={() => answer(false)}>Cancel</button>
          <button type="button" style={{ ...modalButton, ...modalPrimaryButton, background: palette.primary, color: palette.primaryText }} onClick={() => answer(true)}>Confirm activation</button>
        </div>
      </section>
    </div>
  );
}

type StoredSession = { authToken: string; user: KeyWayUser; appId?: string; expiresAt: string };

const SESSION_STORAGE_KEY = "ckb-keyway.session.v2";

function sessionStorageKey(appId?: string): string { return `${SESSION_STORAGE_KEY}:${appId ?? "unregistered"}`; }

function readStoredSession(expectedAppId?: string): StoredSession | undefined {
  try {
    localStorage.removeItem("ckb-keyway.session");
    const value: unknown = JSON.parse(localStorage.getItem(sessionStorageKey(expectedAppId)) ?? "null");
    if (!value || typeof value !== "object") return;
    const { authToken, user, appId, expiresAt } = value as Partial<StoredSession>;
    if (typeof authToken !== "string" || !user || typeof user.id !== "string") return;
    if (appId !== expectedAppId) return;
    if (typeof expiresAt !== "string" || !Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= Date.now()) return;
    return { authToken, user, appId, expiresAt };
  } catch {
    return;
  }
}

function storeSession(session: StoredSession): void {
  localStorage.setItem(sessionStorageKey(session.appId), JSON.stringify(session));
}

function clearStoredSession(appId?: string): void {
  localStorage.removeItem(sessionStorageKey(appId));
}

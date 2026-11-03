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
import type { EmailCodeReason, RequestEmailCode } from "../browser/email-code";
import { friendlyKeyWayError } from "../browser/friendly-error";
import { changeRecoveryBackup, enableRecovery, requestBackupChallenge, type ApproveBackupChange, type ApproveRecovery, type BackupChanged, type BackupChangePreview, type RecoveryEnabled, type RecoveryPreview } from "../browser/account-recovery";
import type { RecoveryBackup, RecoveryBackupProof } from "../browser/recovery-backups";
import { KeyWaySigner, type ApproveCkbMessage, type ApproveCkbTransaction, type MessagePreview, type TransactionPreview } from "../browser/keyway-signer";
import { KeyWayChannelCloseModal, KeyWayChannelSettingsModal, KeyWayEmailCodeModal, KeyWayFundingModal, KeyWayMessageModal, KeyWayBackupChangeModal, KeyWayPeerModal, KeyWayRecoveryModal, KeyWayTransactionModal } from "./signing-modals";
import type { ApproveFiberChannelClose, ApproveFiberChannelSettings, ApproveFiberPeer, FiberApprovedAction, FiberChannelClosePreview, FiberChannelSettingsPreview, FiberPeerPreview } from "../browser/fiber-actions";
import { CodeInput, ResendLine, Shell, StatusLine, type ApprovalStep } from "./dialog";
import {
  modalClose,
  modalBack,
  modalIcon,
  modalEyebrow,
  modalTitle,
  modalCopy,
  modalFootnote,
  modalLabel,
  modalInput,
  modalButton,
  modalPrimaryButton,
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
  /** Replaces the built-in dialog for turning account recovery on. Return false to cancel. The emailed code follows. */
  approveRecovery?: ApproveRecovery;
  /** Replaces the built-in dialog for adding or removing a recovery backup. Return false to cancel. The emailed code follows. */
  approveBackupChange?: ApproveBackupChange;
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
  /** Turns account recovery on with these backups, after the user's approval and the emailed code. */
  enableRecovery: (backups: RecoveryBackupProof[]) => Promise<RecoveryEnabled>;
  /** Adds or removes a recovery backup, after the user's approval and the emailed code. */
  changeRecoveryBackup: (change: "add" | "remove", backup: RecoveryBackupProof | RecoveryBackup) => Promise<BackupChanged>;
  /** A fresh nonce from KeyWay that a new backup signs to prove the user controls it. */
  requestBackupChallenge: () => Promise<string>;
};

const KeyWayContext = createContext<KeyWayContextValue | undefined>(undefined);

type Approval<P> = ApprovalStep & { preview: P; resolve: (approved: boolean) => void };

/**
 * One built-in approval dialog. After the user approves, it stays open and busy until the next step shows
 * (`handOff`, when the code prompt opens) or the action ends (`settle`); a failure stays in it until closed.
 */
function useApproval<P>() {
  const [request, setRequest] = useState<Approval<P>>();
  const [actions] = useState(() => {
    let current: Approval<P> | undefined;
    const set = (next: Approval<P> | undefined) => { current = next; setRequest(next); };
    return {
      ask: (preview: P) => new Promise<boolean>((resolve) => {
        if (current && !current.busy && current.failure === undefined) current.resolve(false);
        set({ preview, resolve });
      }),
      answer: (approved: boolean) => {
        if (!current || current.busy) return;
        if (current.failure !== undefined) return set(undefined);
        current.resolve(approved);
        set(approved ? { ...current, busy: true } : undefined);
      },
      settle: (error?: unknown) => {
        if (!current?.busy) return;
        const text = error instanceof Error ? error.message : error === undefined ? "" : String(error);
        set(text && !/cancelled|not approved/i.test(text) ? { ...current, busy: false, failure: friendlyKeyWayError(text) } : undefined);
      },
      handOff: () => { if (current?.busy) set(undefined); },
      dismiss: () => {
        if (current && !current.busy && current.failure === undefined) current.resolve(false);
        set(undefined);
      },
    };
  });
  return { request, ...actions };
}

/** Reports how an action ended to `settle`, and passes its result or error on unchanged. */
async function settles<T>(work: Promise<T>, settle: (error?: unknown) => void): Promise<T> {
  try {
    const value = await work;
    settle();
    return value;
  } catch (error) {
    settle(error);
    throw error;
  }
}

/** The provider's signer: it tells the approval dialog left open after approval when signing has finished. */
class ProviderSigner extends KeyWaySigner {
  constructor(
    authToken: string,
    publicKey: ConstructorParameters<typeof KeyWaySigner>[1],
    handlers: ConstructorParameters<typeof KeyWaySigner>[2],
    client: ConstructorParameters<typeof KeyWaySigner>[3],
    api: ConstructorParameters<typeof KeyWaySigner>[4],
    recovery: ConstructorParameters<typeof KeyWaySigner>[5],
    private readonly settled: { transaction: (error?: unknown) => void; message: (error?: unknown) => void },
  ) {
    super(authToken, publicKey, handlers, client, api, recovery);
  }

  override signOnlyTransaction(transaction: Parameters<KeyWaySigner["signOnlyTransaction"]>[0]) {
    return settles(super.signOnlyTransaction(transaction), this.settled.transaction);
  }

  override signMessageRaw(text: Parameters<KeyWaySigner["signMessageRaw"]>[0]) {
    return settles(super.signMessageRaw(text), this.settled.message);
  }
}

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
  approveRecovery,
  approveBackupChange,
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
  const callbacksRef = useRef({ approveFiberChannelOpen, approveFiberPayment, approveFiberChannelClose, approveFiberPeerConnect, approveFiberChannelSettings, approveCkbTransaction, approveCkbMessage, approveRecovery, approveBackupChange, onError, onFiberStartup });
  callbacksRef.current = { approveFiberChannelOpen, approveFiberPayment, approveFiberChannelClose, approveFiberPeerConnect, approveFiberChannelSettings, approveCkbTransaction, approveCkbMessage, approveRecovery, approveBackupChange, onError, onFiberStartup };
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
  const transaction = useApproval<TransactionPreview>();
  const message = useApproval<MessagePreview>();
  const recovery = useApproval<RecoveryPreview>();
  const backupChange = useApproval<BackupChangePreview>();
  const channelClose = useApproval<FiberChannelClosePreview>();
  const peer = useApproval<FiberPeerPreview>();
  const channelSettings = useApproval<FiberChannelSettingsPreview>();
  const funding = useApproval<FiberChannelOpenPreview>();
  const approvalsRef = useRef({ transaction, message, recovery, backupChange, channelClose, peer, channelSettings, funding });
  approvalsRef.current = { transaction, message, recovery, backupChange, channelClose, peer, channelSettings, funding };
  const [codeRequest, setCodeRequest] = useState<{
    reason: EmailCodeReason;
    error?: string;
    sentTo?: string;
    resend: () => Promise<void>;
    verify?: (code: string) => Promise<void>;
    resolve: (code: string | undefined) => void;
  }>();
  const authenticated = ready && Boolean(authToken && user);

  // The code prompt is always the SDK's own, even when an app brings its own approval UI. It is the next step
  // of whatever the user just approved, so that dialog closes as the prompt opens.
  const requestEmailCode: RequestEmailCode = (request) => new Promise<string | undefined>((resolve) => {
    for (const approval of Object.values(approvalsRef.current)) approval.handOff();
    setCodeRequest({ ...request, resolve });
  });
  const fiberSettled = (action: FiberApprovedAction, error?: unknown) => {
    const approvals = approvalsRef.current;
    ({ close: approvals.channelClose, peer: approvals.peer, settings: approvals.channelSettings, funding: approvals.funding })[action].settle(error);
  };

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
            return callbacksRef.current.approveFiberChannelOpen?.(preview) ?? approvalsRef.current.funding.ask(preview);
          },
          // Read at payment time, so an app can add or drop its own confirmation without restarting Fiber.
          approveFiberPayment: (preview) => callbacksRef.current.approveFiberPayment?.(preview) ?? true,
          requestEmailCode,
          // Each reads the app's prop at the time of the action, falling back to the built-in dialog.
          approvals: () => ({
            approveFiberChannelClose: (preview) => callbacksRef.current.approveFiberChannelClose?.(preview) ?? approvalsRef.current.channelClose.ask(preview),
            approveFiberPeerConnect: (preview) => callbacksRef.current.approveFiberPeerConnect?.(preview) ?? approvalsRef.current.peer.ask(preview),
            approveFiberChannelSettings: (preview) => callbacksRef.current.approveFiberChannelSettings?.(preview) ?? approvalsRef.current.channelSettings.ask(preview),
            settled: fiberSettled,
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
    for (const approval of [funding, channelClose, peer, channelSettings]) approval.dismiss();
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
    funding.dismiss();
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
    return new ProviderSigner(authToken, wallet.litPublicKey, {
      approveCkbTransaction: (preview) => callbacksRef.current.approveCkbTransaction?.(preview) ?? approvalsRef.current.transaction.ask(preview),
      approveCkbMessage: (preview) => callbacksRef.current.approveCkbMessage?.(preview) ?? approvalsRef.current.message.ask(preview),
      requestEmailCode,
    }, undefined, new KeyWayApiClient({ appId }), wallet.recovery, {
      transaction: (error) => approvalsRef.current.transaction.settle(error),
      message: (error) => approvalsRef.current.message.settle(error),
    });
  }, [wallet?.litPublicKey, wallet?.recovery?.omnilockArgs, authToken, appId]);

  async function turnOnRecovery(backups: RecoveryBackupProof[]): Promise<RecoveryEnabled> {
    if (!authToken || !wallet) throw new Error("Sign in before turning on recovery");
    const result = await settles(enableRecovery({
      authToken,
      backups,
      api: new KeyWayApiClient({ appId }),
      approve: (preview) => callbacksRef.current.approveRecovery?.(preview) ?? recovery.ask(preview),
      requestEmailCode,
    }), recovery.settle);
    setWallet((current) => current && current.litPublicKey === wallet.litPublicKey ? { ...current, ckbAddress: result.ckbAddress, recovery: result.recovery } : current);
    return result;
  }

  async function backupChallenge(): Promise<string> {
    if (!authToken) throw new Error("Sign in before adding a backup");
    return requestBackupChallenge(authToken, new KeyWayApiClient({ appId }));
  }

  async function changeBackup(change: "add" | "remove", backup: RecoveryBackupProof | RecoveryBackup): Promise<BackupChanged> {
    if (!authToken || !wallet) throw new Error("Sign in before changing backups");
    const result = await settles(changeRecoveryBackup({
      authToken,
      change,
      backup,
      api: new KeyWayApiClient({ appId }),
      approve: (preview) => callbacksRef.current.approveBackupChange?.(preview) ?? backupChange.ask(preview),
      requestEmailCode,
    }), backupChange.settle);
    setWallet((current) => current && current.litPublicKey === wallet.litPublicKey ? { ...current, recovery: result.recovery } : current);
    return result;
  }

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
      enableRecovery: turnOnRecovery,
      changeRecoveryBackup: changeBackup,
      requestBackupChallenge: backupChallenge,
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
      {transaction.request ? <KeyWayTransactionModal theme={theme} appName={resolvedAppName} preview={transaction.request.preview} step={transaction.request} answer={transaction.answer} /> : null}
      {message.request ? <KeyWayMessageModal theme={theme} appName={resolvedAppName} preview={message.request.preview} step={message.request} answer={message.answer} /> : null}
      {recovery.request ? <KeyWayRecoveryModal theme={theme} appName={resolvedAppName} preview={recovery.request.preview} step={recovery.request} answer={recovery.answer} /> : null}
      {backupChange.request ? <KeyWayBackupChangeModal theme={theme} appName={resolvedAppName} preview={backupChange.request.preview} step={backupChange.request} answer={backupChange.answer} /> : null}
      {codeRequest ? (
        <KeyWayEmailCodeModal
          key={codeRequest.error ?? "first"}
          theme={theme}
          reason={codeRequest.reason}
          error={codeRequest.error}
          sentTo={codeRequest.sentTo}
          resend={codeRequest.resend}
          verify={codeRequest.verify}
          answer={(code) => { codeRequest.resolve(code); setCodeRequest(undefined); }}
        />
      ) : null}
      {channelClose.request ? <KeyWayChannelCloseModal theme={theme} appName={resolvedAppName} fiberNode={fiberNode} preview={channelClose.request.preview} step={channelClose.request} answer={channelClose.answer} /> : null}
      {peer.request ? <KeyWayPeerModal theme={theme} appName={resolvedAppName} preview={peer.request.preview} step={peer.request} answer={peer.answer} /> : null}
      {channelSettings.request ? <KeyWayChannelSettingsModal theme={theme} appName={resolvedAppName} preview={channelSettings.request.preview} step={channelSettings.request} answer={channelSettings.answer} /> : null}
      {funding.request ? <KeyWayFundingModal theme={theme} appName={resolvedAppName} preview={funding.request.preview} step={funding.request} answer={funding.answer} /> : null}
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

/** The SDK's email login: the address, then the six-digit code KeyWay emails to it. */
export function KeyWayLoginModal({
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
  const codeInputRef = useRef<HTMLInputElement>(null);

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
      if (challengeId) {
        // A wrong code is cleared so the next one can be typed straight away.
        setVerificationState("error");
        setCode("");
        requestAnimationFrame(() => codeInputRef.current?.focus());
      }
    } finally {
      setPending(false);
    }
  }

  async function resend() {
    setError(undefined);
    setVerificationState("idle");
    const next = await api.sendCode(email);
    setChallengeId(next.challengeId);
    setCode("");
    codeInputRef.current?.focus();
  }

  useEffect(() => {
    if (challengeId && code.length === 6 && !pending && verificationState !== "success") void submit();
  }, [code, challengeId]);

  // The email field is gone once the code is sent, so focus moves to the code.
  useEffect(() => { if (challengeId) codeInputRef.current?.focus(); }, [challengeId]);

  const checking = Boolean(challengeId) && pending;
  return (
    <Shell theme={theme} labelId="keyway-login-title" width={420} onEscape={checking ? undefined : close} onBackdrop={checking ? undefined : close}>
      {(palette) => (
        <>
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
            ? <>Check <strong style={{ color: palette.text, overflowWrap: "anywhere" }}>{email}</strong> for a six-digit code. It expires in 10 minutes.</>
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
              <CodeInput
                palette={palette}
                value={code}
                inputRef={codeInputRef}
                label="One-time code"
                readOnly={pending || verificationState === "success"}
                state={verificationState}
                describedBy={error ? "keyway-login-error" : undefined}
                onChange={(next) => {
                  setCode(next);
                  setError(undefined);
                  setVerificationState("idle");
                }}
              />
            )}
            {verificationState === "success" ? <StatusLine palette={palette} tone="success">Code verified</StatusLine> : null}
            {checking && verificationState === "idle" ? <StatusLine palette={palette} tone="muted">Checking code…</StatusLine> : null}
            {error ? <p id="keyway-login-error" role="alert" style={{ minHeight: 21, margin: "14px 0 0", fontSize: 14, fontWeight: 600, color: palette.error }}>{error}</p> : null}
            {!challengeId ? (
              <button type="submit" disabled={pending} style={{ ...modalButton, ...modalPrimaryButton, background: palette.primary, color: palette.primaryText }}>
                {pending ? "Sending code…" : "Continue"}
              </button>
            ) : (
              <ResendLine palette={palette} resend={resend} waitSeconds={60} disabled={pending || verificationState === "success"} prompt="Didn't get an email?" style={{ margin: "22px 0 0", textAlign: "center" }} />
            )}
          </form>
          <p style={{ ...modalFootnote, color: palette.subtle }}>Secured by <strong>CKB KeyWay</strong></p>
        </>
      )}
    </Shell>
  );
}

function ArrowLeftIcon() {
  return <svg aria-hidden="true" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m15 18-6-6 6-6" /></svg>;
}

function MailIcon() {
  return <svg aria-hidden="true" width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect width="18" height="14" x="3" y="5" rx="2" /><path d="m3 7 9 6 9-6" /></svg>;
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

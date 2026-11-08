"use client";

import {
  createContext,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
  type ButtonHTMLAttributes,
  type CSSProperties,
  type ReactNode,
} from "react";
import * as ccc from "@ckb-ccc/core";
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
import { createStoppedNodes } from "../browser/node-migration";
import type { ApproveFiberChannelOpen, FiberChannelOpenPreview } from "../browser/remote-ckb-signer";
import type { ApproveFiberPayment } from "../browser/fiber-payment";
import type { EmailCodeReason, RequestEmailCode } from "../browser/email-code";
import { friendlyKeyWayError } from "../browser/friendly-error";
import { changeRecoveryBackup, createJoyIdBackup as createJoyIdBackupWithSigner, enableRecovery, recoveryAccountAddress, requestBackupChallenge, type ApproveBackupChange, type ApproveRecovery, type BackupChanged, type BackupChangePreview, type RecoveryEnabled, type RecoveryPreview } from "../browser/account-recovery";
import type { RecoveryBackup, RecoveryBackupProof } from "../browser/recovery-backups";
import {
  chooseJoyIdTransport,
  isJoyIdHelperWindow,
  isReturnPath,
  joyIdBackupArguments,
  joyIdAppUrl,
  joyIdRecordClient,
  joyIdStateId,
  JoyIdCancelledError,
  resumeJoyIdRedirect,
  runJoyIdHelper,
  startJoyIdBackup,
  stopBrowserNodeForRedirect,
  stripJoyIdAnswerAgain,
  takeCapturedJoyIdReturn,
  takeJoyIdRecord,
  type JoyIdBackupOptions,
  type JoyIdHelperStatus,
  type JoyIdRequestRecord,
  type JoyIdResponse,
  type PendingJoyIdBackup,
  PendingJoyIdProof,
} from "../browser/joyid-redirect";
import { KeyWaySigner, type ApproveCkbMessage, type ApproveCkbTransaction, type ApproveDailyLimit, type MessagePreview, type TransactionPreview } from "../browser/keyway-signer";
import type { SendLimitOffer } from "../browser/send-limits";
import { KeyWayChannelCloseModal, KeyWayChannelSettingsModal, KeyWayDailyLimitModal, KeyWayEmailCodeModal, KeyWayFundingModal, KeyWayMessageModal, KeyWayBackupChangeModal, KeyWayPeerModal, KeyWayRecoveryModal, KeyWayTransactionModal } from "./signing-modals";
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
  /**
   * Replaces the built-in "Protect your account" dialog shown before an account's first send, which turns daily send
   * limits on. Return the daily CKB amount in shannons (`offer.ckb` is 100,000 CKB, or the user's own amount), or
   * null to cancel the send. The emailed code follows.
   */
  approveDailyLimit?: ApproveDailyLimit;
  /** Replaces the built-in dialog for turning account recovery on. Return false to cancel. The emailed code follows. */
  approveRecovery?: ApproveRecovery;
  /** Replaces the built-in dialog for adding or removing a recovery backup. Return false to cancel. The emailed code follows. */
  approveBackupChange?: ApproveBackupChange;
  /** Starts Fiber as soon as the user signs in. Off by default; call `useFiber().start()` instead. */
  autoStartFiber?: boolean;
  /** Where the user's Fiber node runs: on KeyWay's servers (default) or in this page. */
  fiberNode?: FiberNodeKind;
  /**
   * The page on this site JoyID returns to when a JoyID backup can't use JoyID's own window (pages with
   * `Cross-Origin-Opener-Policy: same-origin`). It must render KeyWayProvider. Defaults to the current page.
   */
  joyIdReturnPath?: string;
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
  /** Signs up a JoyID passkey as a backup over the transport the page allows. Call it straight from a click. */
  createJoyIdBackup: (signer?: ccc.Signer | JoyIdBackupOptions, options?: JoyIdBackupOptions) => Promise<RecoveryBackupProof>;
  /** A JoyID backup the page came back from JoyID with, while the provider finishes it. */
  pendingJoyIdBackup?: PendingJoyIdBackup;
  dismissPendingJoyIdBackup: () => void;
  /** Counts a Fiber payment or channel change, so the page doesn't leave for JoyID in the middle of one. */
  trackFiberOperation: <T>(work: () => Promise<T>) => Promise<T>;
};

const KeyWayContext = createContext<KeyWayContextValue | undefined>(undefined);

type Approval<P> = ApprovalStep & { preview: P; resolve: (approved: boolean) => void };

/**
 * One built-in approval dialog. After the user approves, it stays open and busy until the next step shows
 * (`handOff`, when the code prompt opens) or the action ends (`settle`); a failure stays in it until closed.
 */
function useApproval<P>(fiber = false) {
  const [request, setRequest] = useState<Approval<P>>();
  const [actions] = useState(() => {
    let current: Approval<P> | undefined;
    const set = (next: Approval<P> | undefined) => { current = next; setRequest(next); };
    return {
      // A new request replaces the dialog; if the previous one was still busy, its outcome is no longer shown.
      ask: (preview: P) => new Promise<boolean>((resolve) => {
        if (current && !current.busy && current.failure === undefined) current.resolve(false);
        set({ preview, resolve });
      }),
      answer: (approved: boolean) => {
        if (!current) return;
        // Close while busy (or after a failure) only hides the dialog: the approved step keeps running.
        if (current.busy || current.failure !== undefined) {
          if (!approved || current.failure !== undefined) set(undefined);
          return;
        }
        current.resolve(approved);
        set(approved ? { ...current, busy: true } : undefined);
      },
      settle: (error?: unknown) => {
        if (!current?.busy) return;
        const text = error instanceof Error ? error.message : error === undefined ? "" : String(error);
        // Fiber's own wording only fits Fiber actions; signing and recovery show KeyWay's message as it is.
        set(text && !/cancelled|not approved/i.test(text) ? { ...current, busy: false, failure: fiber ? friendlyKeyWayError(text) : text } : undefined);
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
  approveDailyLimit,
  approveRecovery,
  approveBackupChange,
  autoStartFiber = false,
  fiberNode = "hosted",
  joyIdReturnPath,
  onError,
  onFiberStartup,
}: KeyWayProviderProps) {
  const resolvedAppName = appName.trim().slice(0, 64) || "CKB KeyWay";
  const api = new KeyWayApiClient({ appId });
  const connectionRef = useRef<KeyWayConnection | undefined>(undefined);
  // Stopped nodes may still be sending channel updates to KeyWay's watchtower: a logout delivers them first.
  const [stoppedNodes] = useState(() => createStoppedNodes<KeyWayConnection["keyway"]>());
  const operationRef = useRef<Promise<void>>(Promise.resolve());
  const runRef = useRef(0);
  const callbacksRef = useRef({ approveFiberChannelOpen, approveFiberPayment, approveFiberChannelClose, approveFiberPeerConnect, approveFiberChannelSettings, approveCkbTransaction, approveCkbMessage, approveDailyLimit, approveRecovery, approveBackupChange, onError, onFiberStartup });
  callbacksRef.current = { approveFiberChannelOpen, approveFiberPayment, approveFiberChannelClose, approveFiberPeerConnect, approveFiberChannelSettings, approveCkbTransaction, approveCkbMessage, approveDailyLimit, approveRecovery, approveBackupChange, onError, onFiberStartup };
  // The "Protect your account" dialog: answered with the chosen daily amount, or null to cancel the send.
  const [limitRequest, setLimitRequest] = useState<{ offer: SendLimitOffer; resolve: (amount: bigint | null) => void }>();
  const askDailyLimit = (offer: SendLimitOffer) => new Promise<bigint | null>((resolve) => setLimitRequest({ offer, resolve }));
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
  // A JoyID window this provider runs in (`?keyway-joyid=`) never restores the session or starts Fiber.
  const joyIdHelper = useSyncExternalStore(noSubscription, isJoyIdHelperWindow, () => false);
  const [joyIdHelperStatus, setJoyIdHelperStatus] = useState<JoyIdHelperStatus>("waiting");
  const [pendingJoyIdBackup, setPendingJoyIdBackup] = useState<PendingJoyIdBackup>();
  // Holds Fiber autostart while a JoyID answer from a full-page redirect is checked or continued.
  const [joyIdHold, setJoyIdHold] = useState(false);
  const joyIdReturnRef = useRef<{ response: JoyIdResponse; record?: JoyIdRequestRecord }>(undefined);
  // A checked JoyID proof from a full-page redirect, held until the wallet is ready.
  const [joyIdProof] = useState(() => new PendingJoyIdProof(setPendingJoyIdBackup));
  const fiberOperationsRef = useRef(0);
  // The SDK took any JoyID answer out of the address bar when it loaded. A router hydrating can put it back, so
  // it goes again before this provider's (or its children's) first fetch, and once more after the router mounts.
  useBrowserLayoutEffect(() => {
    stripJoyIdAnswerAgain();
    // Twice, in case the router's own effect that hooks history hasn't run by the first.
    const timers = [setTimeout(() => stripJoyIdAnswerAgain(true), 0), setTimeout(() => stripJoyIdAnswerAgain(true), 300)];
    return () => timers.forEach(clearTimeout);
  }, []);
  const transaction = useApproval<TransactionPreview>();
  const message = useApproval<MessagePreview>();
  const recovery = useApproval<RecoveryPreview>();
  const backupChange = useApproval<BackupChangePreview>();
  const channelClose = useApproval<FiberChannelClosePreview>(true);
  const peer = useApproval<FiberPeerPreview>(true);
  const channelSettings = useApproval<FiberChannelSettingsPreview>(true);
  const funding = useApproval<FiberChannelOpenPreview>(true);
  const approvalsRef = useRef({ transaction, message, recovery, backupChange, channelClose, peer, channelSettings, funding });
  approvalsRef.current = { transaction, message, recovery, backupChange, channelClose, peer, channelSettings, funding };
  const [codeRequest, setCodeRequest] = useState<{
    reason: EmailCodeReason;
    error?: string;
    sentTo?: string;
    codeLength?: 6 | 8;
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
    if (isJoyIdHelperWindow()) throw new Error("The JoyID window doesn't run Fiber");
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
      if (previous) {
        stoppedNodes.add(previous.keyway);
        await previous.keyway.stop();
      }

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
            if (connectionRef.current) stoppedNodes.add(connectionRef.current.keyway);
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
    stoppedNodes.add(current.keyway);
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
      await stoppedNodes.logout();
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
    if (isJoyIdHelperWindow()) {
      setReady(true);
      return;
    }
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
      // A JoyID proof held for this session's wallet must not apply to the next sign-in's.
      if (joyIdProof.holding) joyIdProof.dismiss();
      setConnection(undefined);
      setError(undefined);
      setWallet(undefined);
      setFiberError(undefined);
      setFiberStartupStage(undefined);
      if (ready) setStatus(loginOpen ? "authenticating" : "idle");
      return;
    }
    setLoginOpen(false);
    // Checking or continuing a JoyID redirect comes first: the page may leave again straight away.
    if (joyIdHold || isJoyIdHelperWindow()) return;
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
  }, [authenticated, authToken, appId, autoStartFiber, fiberNode, joyIdHold]);

  // The JoyID window: hands requests to JoyID and answers back to the tab that opened it.
  useEffect(() => {
    if (!isJoyIdHelperWindow()) return;
    return runJoyIdHelper(setJoyIdHelperStatus);
  }, []);

  // Back from JoyID after a full-page redirect. The SDK already took the answer out of the address bar when it
  // loaded; its record is taken (and so deleted) now, before anything uses it.
  useEffect(() => {
    if (isJoyIdHelperWindow()) return;
    const response = takeCapturedJoyIdReturn();
    if (!response) return;
    let record: JoyIdRequestRecord | undefined;
    try { record = takeJoyIdRecord(sessionStorage, joyIdStateId(response.state)); } catch { record = undefined; }
    joyIdReturnRef.current = { response, record };
    setJoyIdHold(true);
    setPendingJoyIdBackup({ operation: joyIdOperation(record), status: "checking" });
  }, []);

  useEffect(() => {
    const resumed = joyIdReturnRef.current;
    if (!resumed || !ready) return;
    joyIdReturnRef.current = undefined;
    const { response, record } = resumed;
    const operation = joyIdOperation(record);
    const token = authToken;
    void resumeJoyIdRedirect(response, record, {
      userId: user?.id,
      client: record ? joyIdRecordClient(record) : new ccc.ClientPublicTestnet(),
      requestChallenge: () => {
        if (!token) throw new Error("Sign in again, then add the JoyID backup");
        return requestBackupChallenge(token, new KeyWayApiClient({ appId }));
      },
    }).then((result) => {
      if (result.status === "continuing") {
        setPendingJoyIdBackup({ operation, status: "continuing" });
        return;
      }
      joyIdProof.hold({ op: result.record.op, proof: result.proof, otherProofs: result.record.otherProofs ?? [] });
      setJoyIdHold(false);
    }).catch((cause) => {
      const failure = cause instanceof Error ? cause : new Error("The JoyID backup couldn't be finished");
      setPendingJoyIdBackup({ operation, status: failure instanceof JoyIdCancelledError ? "cancelled" : "failed", error: failure });
      setJoyIdHold(false);
      // A crafted link with no request behind it isn't the app's error to report.
      if (!(failure instanceof JoyIdCancelledError) && record) callbacksRef.current.onError?.(failure);
    });
  }, [ready]);

  const signer = useMemo(() => {
    if (!wallet || !authToken) return undefined;
    return new ProviderSigner(authToken, wallet.litPublicKey, {
      approveCkbTransaction: (preview) => callbacksRef.current.approveCkbTransaction?.(preview) ?? approvalsRef.current.transaction.ask(preview),
      approveCkbMessage: (preview) => callbacksRef.current.approveCkbMessage?.(preview) ?? approvalsRef.current.message.ask(preview),
      approveDailyLimit: (offer) => callbacksRef.current.approveDailyLimit?.(offer) ?? askDailyLimit(offer),
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

  // A JoyID backup proof from a full-page redirect goes into the usual flow: the preview, then the emailed code.
  useEffect(() => {
    if (!joyIdProof.holding) return;
    if (wallet && authToken) {
      joyIdProof.apply((job) => job.op === "backup-add" ? changeBackup("add", job.proof) : turnOnRecovery([...job.otherProofs, job.proof]));
      return;
    }
    // The wallet failed to start: say so rather than stay at "applying". The proof stays held for the next start.
    if (error && status !== "connecting") joyIdProof.walletFailed(error);
  }, [wallet, authToken, error, status, pendingJoyIdBackup]);

  /** Before the whole page goes to JoyID: a browser Fiber node stops cleanly, and never in the middle of a payment. */
  function leaveForJoyId() {
    const approvals = approvalsRef.current;
    return stopBrowserNodeForRedirect({
      kind: fiberNode,
      busy: fiberOperationsRef.current > 0 || [approvals.funding, approvals.channelClose, approvals.peer, approvals.channelSettings].some((approval) => approval.request),
      starting: operationRef.current,
      running: () => Boolean(connectionRef.current),
      stop: disconnect,
    });
  }

  function joyIdBackup(signerOrOptions?: ccc.Signer | JoyIdBackupOptions, maybeOptions?: JoyIdBackupOptions): Promise<RecoveryBackupProof> {
    const [joyIdSigner, options] = joyIdBackupArguments(signerOrOptions, maybeOptions);
    if (!wallet || !authToken || !user) return Promise.reject(new Error("Recover the CKB account before adding a backup"));
    if (joyIdSigner && joyIdSigner.signType !== ccc.SignerSignType.JoyId) return Promise.reject(new Error("A JoyID backup needs CCC's JoyID signer"));
    const publicKey = wallet.litPublicKey;
    const client = joyIdSigner?.client ?? new ccc.ClientPublicTestnet();
    const account = () => recoveryAccountAddress(publicKey, client);
    try {
      const transport = chooseJoyIdTransport(options.transport);
      if (transport === "popup" && joyIdSigner) {
        // As before 0.2.7: the app's own CCC JoyID signer, in JoyID's own window.
        return (async () => createJoyIdBackupWithSigner(await account(), await backupChallenge(), joyIdSigner))();
      }
      const named = joyIdSigner as { name?: unknown; icon?: unknown } | undefined;
      return startJoyIdBackup({
        client,
        app: {
          joyIdAppURL: joyIdAppUrl(client),
          name: typeof named?.name === "string" && named.name ? named.name : resolvedAppName,
          logo: typeof named?.icon === "string" && named.icon ? named.icon : appLogo(),
        },
        userId: user.id,
        appId,
        op: (options.afterRedirect ?? (wallet.recovery ? "add" : "enable")) === "add" ? "backup-add" : "backup-enable",
        returnPath: joyIdReturnPath ?? `${location.pathname}${location.search}${location.hash}`,
        account,
        requestChallenge: backupChallenge,
        beforeLeaving: leaveForJoyId,
        options,
      }, transport);
    } catch (cause) {
      return Promise.reject(cause);
    }
  }

  async function trackFiberOperation<T>(work: () => Promise<T>): Promise<T> {
    fiberOperationsRef.current += 1;
    try {
      return await work();
    } finally {
      fiberOperationsRef.current -= 1;
    }
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

  if (joyIdHelper) return <JoyIdHelperScreen theme={theme} appName={resolvedAppName} status={joyIdHelperStatus} />;

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
      createJoyIdBackup: joyIdBackup,
      pendingJoyIdBackup,
      dismissPendingJoyIdBackup: () => joyIdProof.dismiss(),
      trackFiberOperation,
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
      {limitRequest ? (
        <KeyWayDailyLimitModal
          theme={theme}
          appName={resolvedAppName}
          offer={limitRequest.offer}
          answer={(amount) => { limitRequest.resolve(amount); setLimitRequest(undefined); }}
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
          codeLength={codeRequest.codeLength}
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

const noSubscription = () => () => undefined;
// useLayoutEffect warns during server rendering in React 18.
const useBrowserLayoutEffect = typeof window === "undefined" ? useEffect : useLayoutEffect;


function joyIdOperation(record: JoyIdRequestRecord | undefined): PendingJoyIdBackup["operation"] {
  return record?.op === "backup-add" ? "add" : "enable";
}

/** The site's icon for JoyID's screen: the page's own icon link, or /favicon.ico. */
function appLogo(): string {
  const link = document.querySelector<HTMLLinkElement>('link[rel~="icon"]');
  return link?.href || new URL("/favicon.ico", location.origin).href;
}

const JOYID_HELPER_TEXT: Record<JoyIdHelperStatus, { title: string; copy: (appName: string) => string }> = {
  waiting: { title: "Opening JoyID", copy: (appName) => `${appName} is preparing the request.` },
  opening: { title: "Opening JoyID", copy: () => "JoyID opens in this window." },
  returning: { title: "Back from JoyID", copy: (appName) => `Returning the result to ${appName}. This window closes by itself.` },
  done: { title: "Done", copy: () => "You can close this window." },
  unknown: { title: "Nothing to do here", copy: (appName) => `This window isn't waiting for JoyID any more. Close it and try again in ${appName}.` },
};

/** What the JoyID window shows between JoyID's pages. The app's own page isn't rendered in it. */
function JoyIdHelperScreen({ theme, appName, status }: { theme: "light" | "dark"; appName: string; status: JoyIdHelperStatus }) {
  const text = JOYID_HELPER_TEXT[status];
  return (
    <Shell theme={theme} labelId="keyway-joyid-title" width={420}>
      {(palette) => (
        <>
          <p style={{ ...modalEyebrow, color: palette.muted }}>{appName}</p>
          <h2 id="keyway-joyid-title" style={modalTitle}>{text.title}</h2>
          <p role="status" style={{ ...modalCopy, color: palette.muted }}>{text.copy(appName)}</p>
          {status === "done" || status === "unknown" ? (
            <button type="button" style={{ ...modalButton, borderColor: palette.border, color: palette.text }} onClick={() => window.close()}>Close window</button>
          ) : null}
          <p style={{ ...modalFootnote, color: palette.subtle }}>Secured by <strong>CKB KeyWay</strong></p>
        </>
      )}
    </Shell>
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

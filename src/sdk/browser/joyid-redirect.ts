import * as ccc from "@ckb-ccc/core";
import { authWithPopup, buildJoyIDURL, decodeSearch, isStandaloneBrowser, signMessageWithPopup } from "@joyid/common";
import { joyIdLock, joyIdMainKey, joyIdPubkeyHash, recoveryBackupChallenge, verifyBackupOwnership, type RecoveryBackupProof } from "./recovery-backups";

/**
 * JoyID backups on any page, including cross-origin isolated ones.
 *
 * JoyID answers its own window through `window.opener.postMessage`. A page that sends
 * `Cross-Origin-Opener-Policy: same-origin` (needed for the browser Fiber node's SharedArrayBuffer) loses that link,
 * so JoyID's signature never comes back. JoyID's redirect mode returns the same assertion in the return URL's query
 * instead (`_data_`, research/joyid-redirect). Three transports:
 * - "popup": JoyID's own window, as CCC's JoyID signer opens it. Only works without COOP same-origin.
 * - "window": a window on the app's own origin (`?keyway-joyid=<id>`) runs JoyID's redirect mode and hands the result
 *   back over a BroadcastChannel, so this tab, and a Fiber node in it, keeps running. Opened synchronously on the
 *   user's click.
 * - "redirect": the whole page goes to JoyID and back. The provider resumes on return.
 *
 * A first-time JoyID backup needs the JoyID address before it can sign (the signed text names it), so it connects
 * first (JoyID's Auth, without a challenge) and then signs. A JoyID connection CCC already stored skips the connect.
 *
 * Every redirect and window request carries `state = { v: 1, id }` with a fresh 128-bit id, recorded once in
 * sessionStorage. A result is accepted only for the request this tab started, unexpired, for the same user, with
 * the step's type, the exact challenge text, a JoyID main key (ES256) and a signature `verifyBackupOwnership` accepts.
 */
export type JoyIdTransport = "auto" | "popup" | "window" | "redirect";

/** Where a JoyID backup is: connecting JoyID, waiting for its signature, or leaving the page for JoyID. */
export type JoyIdBackupStage = "connecting" | "signing" | "leaving";

export type JoyIdBackupOptions = {
  /**
   * "auto" (default): JoyID's own window on a page that isn't cross-origin isolated; otherwise a window on this
   * site, or a full-page redirect when that window can't open (blocked, or an installed app).
   */
  transport?: JoyIdTransport;
  onStage?: (stage: JoyIdBackupStage) => void;
  /** Stops waiting for JoyID. The backup's promise rejects as cancelled. */
  signal?: AbortSignal;
  /**
   * After a full-page redirect the page reloads, so the provider finishes the job itself: turning recovery on
   * (with `otherBackups`) or adding the backup. Defaults to "enable" when recovery is off and "add" when it is on.
   */
  afterRedirect?: "enable" | "add";
  /** Other backups' proofs to turn recovery on with, alongside the JoyID one, after a full-page redirect. */
  otherBackups?: RecoveryBackupProof[];
};

/** What happens with a JoyID backup the page came back from JoyID with. */
export type PendingJoyIdBackup = {
  operation: "enable" | "add";
  status: "checking" | "continuing" | "applying" | "done" | "cancelled" | "failed";
  error?: Error;
  /**
   * With "failed": the wallet didn't start, so the checked JoyID proof is still held. Starting the wallet again
   * (`startFiber`) applies it; `dismissPendingJoyIdBackup` drops it.
   */
  waitingForWallet?: boolean;
};

/** A checked JoyID proof from a full-page redirect, to apply once the wallet is ready. */
export type JoyIdProofJob = { op: JoyIdOperation; proof: RecoveryBackupProof; otherProofs: RecoveryBackupProof[] };

/**
 * Holds a checked JoyID proof from a full-page redirect until the wallet is ready, and reports where it is. If the
 * wallet fails to start, the proof stays held (`waitingForWallet`) so a later start applies it; dismissing drops it,
 * and an apply already running then reports nothing.
 */
export class PendingJoyIdProof {
  private job: JoyIdProofJob | undefined;
  private failedWith: Error | undefined;
  private generation = 0;

  constructor(private readonly report: (pending: PendingJoyIdBackup | undefined) => void) {}

  /** A proof is waiting for the wallet. */
  get holding(): boolean {
    return this.job !== undefined;
  }

  /** The redirect's answer checked out: hold its proof until the wallet is ready. */
  hold(job: JoyIdProofJob): void {
    this.generation++;
    this.job = job;
    this.failedWith = undefined;
    this.report({ operation: proofOperation(job.op), status: "applying" });
  }

  /** The wallet failed to start. Says so once per failure, and keeps the proof for the next start. */
  walletFailed(cause: Error): void {
    const job = this.job;
    if (!job || this.failedWith === cause) return;
    this.failedWith = cause;
    const error = new Error(`The wallet didn't start, so the JoyID backup isn't applied yet. Start it again to finish, or dismiss it. ${cause.message}`.trim(), { cause });
    this.report({ operation: proofOperation(job.op), status: "failed", error, waitingForWallet: true });
  }

  /** The wallet is ready: applies a held proof, once. */
  apply(work: (job: JoyIdProofJob) => Promise<unknown>): void {
    const job = this.job;
    if (!job) return;
    this.job = undefined;
    this.failedWith = undefined;
    const generation = this.generation;
    const operation = proofOperation(job.op);
    this.report({ operation, status: "applying" });
    let running: Promise<unknown>;
    try { running = Promise.resolve(work(job)); } catch (cause) { running = Promise.reject(cause); }
    void running.then(
      () => { if (generation === this.generation) this.report({ operation, status: "done" }); },
      (cause) => {
        if (generation !== this.generation) return;
        const failure = cause instanceof Error ? cause : new Error("The JoyID backup couldn't be finished");
        this.report({ operation, status: /cancelled/i.test(failure.message) ? "cancelled" : "failed", error: failure });
      },
    );
  }

  /** Drops a held proof, so it can't apply later, and clears the report. */
  dismiss(): void {
    this.generation++;
    this.job = undefined;
    this.failedWith = undefined;
    this.report(undefined);
  }
}

function proofOperation(op: JoyIdOperation): PendingJoyIdBackup["operation"] {
  return op === "backup-add" ? "add" : "enable";
}

export type JoyIdOperation = "backup-enable" | "backup-add";
type Step = "auth" | "sign";

/** One JoyID request, as this tab recorded it. Holds nothing secret: the proofs are the user's own signatures. */
export type JoyIdRequestRecord = {
  v: 1;
  id: string;
  transport: "window" | "redirect";
  op: JoyIdOperation;
  step: Step;
  appId: string | null;
  userId: string;
  account: string;
  /** The JoyID address the challenge names; known for the sign step. */
  joyIdAddress?: string;
  challengeNonce?: string;
  joyIdAppURL: string;
  name: string;
  logo: string;
  expiresAt: number;
  /** Path and query JoyID returns to, without the JoyID parameters. */
  returnPath: string;
  otherProofs?: RecoveryBackupProof[];
};

/** A JoyID answer read from a return URL: the top-level `_data_` object, which also carries `state` for Auth. */
export type JoyIdResponse = { type?: unknown; data?: unknown; error?: unknown; state?: unknown };

export type JoyIdApp = { joyIdAppURL: string; name: string; logo: string };

export const JOYID_HELPER_PARAM = "keyway-joyid";
const JOYID_REDIRECT_PARAM = "joyid-redirect";
const JOYID_DATA_PARAM = "_data_";
const RECORD_PREFIX = "keyway:joyid:";
const CHANNEL_NAME = "keyway:joyid";
/** CCC's JoyID signer keeps its connections here (ConnectionsRepoLocalStorage). */
const CCC_CONNECTIONS_KEY = "ccc-joy-id-signer";
/** How long the connect step may take. The sign step runs until the backup challenge expires. */
const AUTH_TTL_MS = 10 * 60_000;
/** How long the window may take to load before KeyWay gives up on it. */
const HELPER_LOAD_MS = 30_000;
const ID_PATTERN = /^[0-9a-f]{32}$/;
/** The JoyID apps a request may go to: mainnet and testnet, as CCC's JoyID signer picks them. */
const JOYID_APPS = ["https://app.joy.id", "https://testnet.joyid.dev"];

export class JoyIdCancelledError extends Error {
  constructor(message = "JoyID was cancelled. Nothing changed") {
    super(message);
    this.name = "JoyIdCancelledError";
  }
}

const invalidAnswer = () => new Error("JoyID's answer doesn't match this request. Nothing changed; try again");

/** JoyID's web app for the client's network, as CCC's JoyID signer picks it. */
export function joyIdAppUrl(client: ccc.Client): string {
  return client.addressPrefix === "ckb" ? "https://app.joy.id" : "https://testnet.joyid.dev";
}

export function newJoyIdId(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** KeyWay's state shape, `{ v: 1, id }`, as it comes back from JoyID. */
export function joyIdStateId(state: unknown): string | undefined {
  if (!state || typeof state !== "object") return undefined;
  const { v, id } = state as { v?: unknown; id?: unknown };
  return v === 1 && typeof id === "string" && ID_PATTERN.test(id) ? id : undefined;
}

/**
 * The request JoyID's page gets, with exactly the fields CCC's JoyID signer sends (name, logo, joyidAppURL, and for
 * signing challenge, isData false and address) plus `state`. `redirectURL` is where the answer goes.
 */
export function joyIdRequest(record: Pick<JoyIdRequestRecord, "id" | "step" | "account" | "joyIdAddress" | "challengeNonce" | "joyIdAppURL" | "name" | "logo">, redirectURL: string) {
  const base = { redirectURL, joyidAppURL: record.joyIdAppURL, name: record.name, logo: record.logo };
  const state = { v: 1, id: record.id };
  if (record.step === "auth") return { ...base, state };
  if (!record.joyIdAddress || !record.challengeNonce) throw new Error("A JoyID signature request needs its address and challenge");
  return { ...base, challenge: joyIdChallenge(record), isData: false, address: record.joyIdAddress, state };
}

/** JoyID's page URL for a recorded request in redirect mode. */
export function joyIdRedirectUrl(record: JoyIdRequestRecord, redirectURL: string): string {
  return buildJoyIDURL(joyIdRequest(record, redirectURL) as never, "redirect", record.step === "auth" ? "/auth" : "/sign-message");
}

function joyIdChallenge(record: Pick<JoyIdRequestRecord, "account" | "joyIdAddress" | "challengeNonce">): string {
  return recoveryBackupChallenge(record.account, { kind: "joyid", address: record.joyIdAddress! }, record.challengeNonce!);
}

export function saveJoyIdRecord(storage: Storage, record: JoyIdRequestRecord): void {
  storage.setItem(RECORD_PREFIX + record.id, JSON.stringify(record));
}

/** Reads a recorded request once: it is deleted before it is used, so an answer can't be replayed in this tab. */
export function takeJoyIdRecord(storage: Storage, id: string | undefined): JoyIdRequestRecord | undefined {
  if (!id || !ID_PATTERN.test(id)) return undefined;
  const key = RECORD_PREFIX + id;
  const raw = storage.getItem(key);
  storage.removeItem(key);
  if (!raw) return undefined;
  try {
    const record = JSON.parse(raw) as JoyIdRequestRecord;
    return isJoyIdRecord(record) && record.id === id ? record : undefined;
  } catch {
    return undefined;
  }
}

export function isJoyIdRecord(value: unknown): value is JoyIdRequestRecord {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return record.v === 1 && typeof record.id === "string" && ID_PATTERN.test(record.id)
    && (record.transport === "window" || record.transport === "redirect")
    && (record.op === "backup-enable" || record.op === "backup-add")
    && (record.step === "auth" || record.step === "sign")
    && typeof record.userId === "string" && typeof record.account === "string"
    && typeof record.joyIdAppURL === "string" && JOYID_APPS.includes(record.joyIdAppURL)
    && (record.appId === null || typeof record.appId === "string")
    && (record.otherProofs === undefined || Array.isArray(record.otherProofs))
    && typeof record.name === "string" && typeof record.logo === "string"
    && typeof record.expiresAt === "number" && isReturnPath(record.returnPath)
    && record.account.length > 0
    && (record.step === "auth" || (typeof record.joyIdAddress === "string" && typeof record.challengeNonce === "string"));
}

/** Reads JoyID's answer from a return URL, or undefined when the URL isn't one. */
export function readJoyIdReturn(href: string): JoyIdResponse | undefined {
  let url: URL;
  try { url = new URL(href); } catch { return undefined; }
  if (!url.searchParams.has(JOYID_REDIRECT_PARAM)) return undefined;
  const data = url.searchParams.get(JOYID_DATA_PARAM);
  if (data === null) return {};
  try {
    const decoded = decodeSearch(data) as unknown;
    return decoded && typeof decoded === "object" ? decoded as JoyIdResponse : {};
  } catch {
    return {};
  }
}

/** The URL without JoyID's answer (`_data_`, `joyid-redirect`). The helper window's own marker stays. */
export function withoutJoyIdAnswer(href: string): string {
  const url = new URL(href);
  url.searchParams.delete(JOYID_DATA_PARAM);
  url.searchParams.delete(JOYID_REDIRECT_PARAM);
  return url.pathname + url.search + url.hash;
}

let captured: JoyIdResponse | undefined;
let answeredOnLoad = false;

/**
 * Reads a JoyID answer meant for KeyWay from this page's URL and strips it from the address bar at once, before
 * anything else on the page can fetch, log or render it. Runs when the SDK loads; the provider takes the result.
 * Answers to other JoyID requests (another library's state) are left alone.
 */
export function captureJoyIdReturn(): void {
  if (typeof window === "undefined" || typeof location === "undefined") return;
  const response = readJoyIdReturn(location.href);
  if (!response) return;
  const helper = new URL(location.href).searchParams.get(JOYID_HELPER_PARAM);
  if (!joyIdStateId(response.state) && !helper) return;
  try { history.replaceState(history.state, "", withoutJoyIdAnswer(location.href)); } catch { /* keep the answer anyway */ }
  captured = response;
  answeredOnLoad = true;
}

/**
 * A router may put the URL it was served with back while it hydrates (Next.js's app router does, from its
 * server-rendered state), so the provider strips the answer again before its first fetch. With `router`, the call
 * goes through the router's own history hook (Next.js patches `history.replaceState` once it has mounted, and skips
 * calls carrying its `__NA` marker), so the router forgets the old URL too and can't restore it later.
 */
export function stripJoyIdAnswerAgain(router = false): void {
  if (!answeredOnLoad || typeof location === "undefined") return;
  const clean = withoutJoyIdAnswer(location.href);
  if (!router && clean === location.pathname + location.search + location.hash) return;
  try {
    if (!router) return history.replaceState(history.state, "", clean);
    const { __NA: _marker, ...state } = (history.state ?? {}) as Record<string, unknown>;
    history.replaceState(state, "", clean);
  } catch { /* keep going: the answer was already taken */ }
}

/** The JoyID answer this page loaded with, once. */
export function takeCapturedJoyIdReturn(): JoyIdResponse | undefined {
  const response = captured;
  captured = undefined;
  return response;
}

captureJoyIdReturn();

/** Whether this page is the window KeyWay opened for JoyID. It must not start Fiber or restore the session. */
export function isJoyIdHelperWindow(): boolean {
  if (typeof location === "undefined") return false;
  return ID_PATTERN.test(new URL(location.href).searchParams.get(JOYID_HELPER_PARAM) ?? "");
}

/** The connection CCC's JoyID signer stored for this JoyID app, if it is a main key. */
export function knownJoyIdAddress(joyIdAppURL: string): string | undefined {
  try {
    const connections = JSON.parse(localStorage.getItem(CCC_CONNECTIONS_KEY) ?? "[]") as Array<[{ uri?: unknown; addressType?: unknown }, { address?: unknown; keyType?: unknown }]>;
    const found = connections.find(([key]) => key?.uri === joyIdAppURL && typeof key.addressType === "string" && key.addressType.startsWith("ckb"))?.[1];
    return found && found.keyType === "main_key" && typeof found.address === "string" ? found.address : undefined;
  } catch {
    return undefined;
  }
}

/** Stores a JoyID connection where CCC's JoyID signer keeps it, so the next backup or a CCC signer skips connecting. */
export function rememberJoyIdConnection(joyIdAppURL: string, connection: { address: string; publicKey: string; keyType: string }): void {
  try {
    const connections = JSON.parse(localStorage.getItem(CCC_CONNECTIONS_KEY) ?? "[]") as Array<[{ uri: string; addressType: string }, unknown]>;
    const value = { address: connection.address, publicKey: ccc.hexFrom(connection.publicKey.startsWith("0x") ? connection.publicKey : `0x${connection.publicKey}`), keyType: connection.keyType };
    const existing = connections.find(([key]) => key?.uri === joyIdAppURL && key.addressType === "ckb");
    if (existing) existing[1] = value;
    else connections.push([{ uri: joyIdAppURL, addressType: "ckb" }, value]);
    localStorage.setItem(CCC_CONNECTIONS_KEY, JSON.stringify(connections));
  } catch { /* the next backup connects again */ }
}

/**
 * `createJoyIdBackup`'s arguments: `(signer, options)`, `(undefined, options)` or `(options)`. A signer is anything
 * with `signMessage`, as CCC's signers have.
 */
export function joyIdBackupArguments(first?: ccc.Signer | JoyIdBackupOptions, second?: JoyIdBackupOptions): [ccc.Signer | undefined, JoyIdBackupOptions] {
  if (first && typeof (first as ccc.Signer).signMessage === "function") return [first as ccc.Signer, second ?? {}];
  return [undefined, (first as JoyIdBackupOptions | undefined) ?? second ?? {}];
}

/** "popup" unless the page is cross-origin isolated; then a window on this site, or a redirect in an installed app. */
export function chooseJoyIdTransport(transport: JoyIdTransport = "auto", page = joyIdPage()): "popup" | "window" | "redirect" {
  if (transport === "popup" || transport === "redirect") return transport;
  if (transport === "auto" && !page.isolated) return "popup";
  return page.standalone ? "redirect" : "window";
}

function joyIdPage() {
  let standalone = false;
  try { standalone = Boolean(isStandaloneBrowser()); } catch { standalone = false; }
  return { isolated: typeof crossOriginIsolated !== "undefined" && crossOriginIsolated, standalone };
}

type AuthData = { address?: unknown; pubkey?: unknown; keyType?: unknown; alg?: unknown };
type SignData = { signature?: unknown; message?: unknown; challenge?: unknown; alg?: unknown; pubkey?: unknown; keyType?: unknown };

function requireMainKey(keyType: unknown, alg: unknown, pubkey: unknown): string {
  // joyIdMainKey throws the plain messages for session keys and sub keys.
  const publicKey = joyIdMainKey(JSON.stringify({ keyType, publicKey: pubkey }), JSON.stringify({ alg }));
  if (!publicKey) throw invalidAnswer();
  return publicKey;
}

/** Checks JoyID's connect answer: a JoyID main-key (ES256) address on this network. */
export async function checkJoyIdAuth(data: unknown, client: ccc.Client): Promise<{ address: string; publicKey: string; keyType: string }> {
  if (!data || typeof data !== "object") throw invalidAnswer();
  const { address, pubkey, keyType, alg } = data as AuthData;
  const publicKey = requireMainKey(keyType, alg, pubkey);
  if (typeof address !== "string") throw invalidAnswer();
  const lock = await joyIdLock(client, address);
  if (ccc.hexFrom(ccc.hashCkbShort(publicKey)) !== ccc.hexFrom(joyIdPubkeyHash(lock))) throw invalidAnswer();
  return { address, publicKey, keyType: "main_key" };
}

/**
 * Checks JoyID's signature answer for the challenge this request named and turns it into a backup proof, with the
 * signature and identity in the JSON CCC's JoyID signer returns. `verifyBackupOwnership` must accept it.
 */
export async function checkJoyIdSignature(
  data: unknown,
  expected: { account: string; joyIdAddress: string; challengeNonce: string },
  client: ccc.Client,
  now = new Date(),
): Promise<RecoveryBackupProof> {
  if (!data || typeof data !== "object") throw invalidAnswer();
  const signed = data as SignData;
  if (signed.challenge !== joyIdChallenge(expected)) throw invalidAnswer();
  const publicKey = requireMainKey(signed.keyType, signed.alg, signed.pubkey);
  if (typeof signed.signature !== "string" || typeof signed.message !== "string") throw invalidAnswer();
  const proof: RecoveryBackupProof = {
    kind: "joyid",
    address: expected.joyIdAddress,
    signature: JSON.stringify({ signature: signed.signature, alg: signed.alg, message: signed.message }),
    identity: JSON.stringify({ keyType: "main_key", publicKey: publicKey.slice(2) }),
    challengeNonce: expected.challengeNonce,
  };
  await verifyBackupOwnership(client, expected.account, proof, now);
  return proof;
}

/**
 * Checks a JoyID answer against the request this tab recorded for it. A rejection in JoyID is a cancel. Anything
 * else must be the recorded step's type, unexpired, for the signed-in user, and pass the step's own checks.
 */
export async function checkJoyIdResponse(
  record: JoyIdRequestRecord,
  response: JoyIdResponse,
  context: { userId: string | undefined; client: ccc.Client; now?: Date },
): Promise<{ step: "auth"; address: string; publicKey: string; keyType: string } | { step: "sign"; proof: RecoveryBackupProof }> {
  const now = context.now ?? new Date();
  if (joyIdStateId(response.state) !== record.id) throw invalidAnswer();
  if (response.error !== undefined && response.error !== null && /reject|cancel/i.test(String(response.error))) throw new JoyIdCancelledError();
  if (context.userId === undefined) throw new Error("Sign in again, then add the JoyID backup again. Nothing changed");
  if (context.userId !== record.userId) throw new Error("This JoyID answer was for a different sign-in. Nothing changed; try again");
  if (response.error !== undefined && response.error !== null) throw new Error(`JoyID couldn't finish: ${String(response.error).slice(0, 120)}`);
  if (now.getTime() >= record.expiresAt) throw new Error("The JoyID request expired. Nothing changed; try again");
  if (response.type !== (record.step === "auth" ? "Auth" : "SignMessage")) throw invalidAnswer();
  if (record.step === "auth") return { step: "auth", ...await checkJoyIdAuth(response.data, context.client) };
  return {
    step: "sign",
    proof: await checkJoyIdSignature(response.data, { account: record.account, joyIdAddress: record.joyIdAddress!, challengeNonce: record.challengeNonce! }, context.client, now),
  };
}

/** A path on this site: starts with one slash, so it can't name another origin ("//host", "/\\host"). */
export function isReturnPath(value: unknown): value is string {
  return typeof value === "string" && value.startsWith("/") && !/^\/[/\\]/.test(value);
}

/** Where JoyID returns to: this site's return path, plus the window's marker when a window runs the request. */
export function joyIdReturnUrl(returnPath: string, helperId?: string): string {
  if (!isReturnPath(returnPath)) throw new Error("joyIdReturnPath must be a path on this site, such as /wallet");
  const url = new URL(returnPath, location.origin);
  if (url.origin !== location.origin) throw new Error("joyIdReturnPath must be a path on this site, such as /wallet");
  url.searchParams.delete(JOYID_DATA_PARAM);
  url.searchParams.delete(JOYID_REDIRECT_PARAM);
  url.searchParams.delete(JOYID_HELPER_PARAM);
  if (helperId) url.searchParams.set(JOYID_HELPER_PARAM, helperId);
  return url.href;
}

/** Everything a JoyID backup run needs from the provider. */
export type JoyIdBackupRun = {
  client: ccc.Client;
  app: JoyIdApp;
  userId: string;
  appId?: string;
  op: JoyIdOperation;
  returnPath: string;
  account: () => Promise<string>;
  /** A fresh challenge nonce from KeyWay. Asked for right before the sign step. */
  requestChallenge: () => Promise<string>;
  /** Runs before the page leaves for JoyID: stops a browser Fiber node, or throws to refuse. */
  beforeLeaving: () => Promise<void>;
  options: JoyIdBackupOptions;
};

type HelperMessage =
  | { kind: "ready"; helper: string }
  | { kind: "gone"; helper: string }
  | { kind: "response"; helper: string; response: JoyIdResponse }
  | { kind: "go"; helper: string; record: JoyIdRequestRecord }
  | { kind: "close"; helper: string };

/**
 * Starts a JoyID backup over the "window" or "redirect" transport, or "popup" without a CCC signer. Call it straight
 * from the user's click: the window opens before anything is awaited. Resolves with the proof, except after a
 * full-page redirect, where the page leaves and the provider finishes on return.
 */
export function startJoyIdBackup(run: JoyIdBackupRun, transport: "popup" | "window" | "redirect"): Promise<RecoveryBackupProof> {
  const stage = (next: JoyIdBackupStage) => { try { run.options.onStage?.(next); } catch { /* the app's callback */ } };
  if (run.options.signal?.aborted) return Promise.reject(new JoyIdCancelledError());
  // A window or a redirect returns to joyIdReturnPath. Refuse a bad one now, before a window opens, a request is
  // saved or a browser node stops for the redirect.
  if (transport !== "popup") {
    try { joyIdReturnUrl(run.returnPath); } catch (error) { return Promise.reject(error); }
  }
  const known = knownJoyIdAddress(run.app.joyIdAppURL);
  if (transport === "popup") {
    if (joyIdPage().isolated) return Promise.reject(new Error("JoyID's own window can't answer this page, because it is cross-origin isolated. Use the \"window\" or \"redirect\" transport"));
    return joyIdBackupByPopup(run, known, stage);
  }
  if (transport === "window") {
    const helper = openJoyIdHelper(run.returnPath);
    if (helper) return joyIdBackupByWindow(run, known, helper, stage);
  }
  return joyIdBackupByRedirect(run, known, stage);
}

function newRecord(run: JoyIdBackupRun, transport: "window" | "redirect", step: Step, account: string, extra: Partial<JoyIdRequestRecord> = {}): JoyIdRequestRecord {
  return {
    v: 1,
    id: newJoyIdId(),
    transport,
    op: run.op,
    step,
    appId: run.appId ?? null,
    userId: run.userId,
    account,
    joyIdAppURL: run.app.joyIdAppURL,
    name: run.app.name,
    logo: run.app.logo,
    expiresAt: Date.now() + AUTH_TTL_MS,
    returnPath: run.returnPath,
    // Turning recovery on with other backups: they ride every step, so a connect step that leaves the page still
    // hands them to the sign step it continues to.
    ...(run.options.otherBackups?.length ? { otherProofs: run.options.otherBackups } : {}),
    ...extra,
  };
}

async function signRecord(run: JoyIdBackupRun, transport: "window" | "redirect", joyIdAddress: string): Promise<JoyIdRequestRecord> {
  const account = await run.account();
  const challengeNonce = await run.requestChallenge();
  const expiresAt = Number(challengeNonce.split(".")[0]);
  return newRecord(run, transport, "sign", account, {
    joyIdAddress,
    challengeNonce,
    expiresAt: Number.isFinite(expiresAt) ? expiresAt : Date.now() + AUTH_TTL_MS,
  });
}

function cancellable<T>(signal: AbortSignal | undefined, work: Promise<T>, onCancel?: () => void): Promise<T> {
  if (!signal) return work;
  return new Promise<T>((resolve, reject) => {
    const abort = () => { onCancel?.(); reject(new JoyIdCancelledError()); };
    if (signal.aborted) return abort();
    signal.addEventListener("abort", abort, { once: true });
    work.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}

function popupCancel(error: unknown): unknown {
  const text = error instanceof Error ? error.message : String(error);
  return /user rejected|popup closed|cancel/i.test(text) ? new JoyIdCancelledError() : error;
}

/** JoyID's own window, with the same requests CCC's JoyID signer sends. The connect window opens on the click. */
function joyIdBackupByPopup(run: JoyIdBackupRun, known: string | undefined, stage: (next: JoyIdBackupStage) => void): Promise<RecoveryBackupProof> {
  const base = { redirectURL: location.href, joyidAppURL: run.app.joyIdAppURL, name: run.app.name, logo: run.app.logo };
  if (!known) stage("connecting");
  const connecting = known ? undefined : authWithPopup(base as never);
  return cancellable(run.options.signal, (async () => {
    let address = known;
    try {
      if (connecting) {
        const connection = await checkJoyIdAuth(await connecting, run.client);
        rememberJoyIdConnection(run.app.joyIdAppURL, connection);
        address = connection.address;
      }
      const account = await run.account();
      const challengeNonce = await run.requestChallenge();
      stage("signing");
      const data = await signMessageWithPopup({ ...base, challenge: joyIdChallenge({ account, joyIdAddress: address, challengeNonce }), isData: false, address: address! } as never);
      return await checkJoyIdSignature(data, { account, joyIdAddress: address!, challengeNonce }, run.client);
    } catch (error) {
      throw popupCancel(error);
    }
  })());
}

/** Opens the window on this site, synchronously. Undefined when the browser blocked it. */
function openJoyIdHelper(returnPath: string): { id: string; window: Window; channel: BroadcastChannel; messages: HelperMessage[]; listeners: Set<() => void> } | undefined {
  if (typeof BroadcastChannel === "undefined") return undefined;
  const id = newJoyIdId();
  const channel = new BroadcastChannel(CHANNEL_NAME);
  const messages: HelperMessage[] = [];
  const listeners = new Set<() => void>();
  channel.onmessage = (event: MessageEvent) => {
    const message = event.data as HelperMessage | undefined;
    if (!message || typeof message !== "object" || message.helper !== id || (message.kind !== "ready" && message.kind !== "response" && message.kind !== "gone")) return;
    messages.push(message);
    for (const listener of listeners) listener();
  };
  const width = 420;
  const height = 640;
  const left = window.screenX + (window.innerWidth - width) / 2;
  const top = window.screenY + (window.innerHeight - height) / 2;
  let opened: Window | null = null;
  try { opened = window.open(joyIdReturnUrl(returnPath, id), "keyway-joyid", `left=${left},top=${top},width=${width},height=${height},resizable,scrollbars=yes`); } catch { opened = null; }
  if (!opened || opened.closed) {
    channel.close();
    return undefined;
  }
  return { id, window: opened, channel, messages, listeners };
}

function joyIdBackupByWindow(
  run: JoyIdBackupRun,
  known: string | undefined,
  helper: NonNullable<ReturnType<typeof openJoyIdHelper>>,
  stage: (next: JoyIdBackupStage) => void,
): Promise<RecoveryBackupProof> {
  let finished = false;
  const close = () => {
    if (finished) return;
    finished = true;
    try { helper.channel.postMessage({ kind: "close", helper: helper.id } satisfies HelperMessage); } catch { /* already closed */ }
    helper.channel.close();
    try { helper.window.close(); } catch { /* the window is JoyID's now */ }
  };

  /** Waits for the next message of a kind. Until the window is sent to JoyID its handle tells when it is closed. */
  const next = <K extends "ready" | "response">(kind: K, deadline: number, watchClosed: boolean) => new Promise<Extract<HelperMessage, { kind: K }>>((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let poll: ReturnType<typeof setInterval> | undefined;
    const done = () => { helper.listeners.delete(check); clearTimeout(timer); clearInterval(poll); };
    const check = () => {
      // The window was closed on this site, or reloaded (Back from JoyID's page) while an answer was due.
      const lost = helper.messages.findIndex((message) => message.kind === "gone" || (kind === "response" && message.kind === "ready"));
      if (lost >= 0) {
        helper.messages.splice(lost, 1);
        done();
        reject(new JoyIdCancelledError("The JoyID window was closed. Nothing changed"));
        return;
      }
      const index = helper.messages.findIndex((message) => message.kind === kind);
      if (index < 0) return;
      const [message] = helper.messages.splice(index, 1);
      done();
      resolve(message as Extract<HelperMessage, { kind: K }>);
    };
    helper.listeners.add(check);
    timer = setTimeout(() => {
      done();
      reject(new Error(kind === "ready" ? "The JoyID window didn't load. Close it and try again" : "JoyID didn't answer in time. Nothing changed; try again"));
    }, Math.max(0, deadline - Date.now()));
    if (watchClosed) poll = setInterval(() => {
      if (!helper.window.closed) return;
      done();
      reject(new JoyIdCancelledError("The JoyID window was closed. Nothing changed"));
    }, 500);
    check();
  });

  const step = async (record: JoyIdRequestRecord, first: boolean) => {
    if (first) await next("ready", Date.now() + HELPER_LOAD_MS, true);
    // Only a "ready" after this request means the window reloaded; drop any said before it.
    for (let index = helper.messages.length - 1; index >= 0; index--) if (helper.messages[index].kind === "ready") helper.messages.splice(index, 1);
    helper.channel.postMessage({ kind: "go", helper: helper.id, record } satisfies HelperMessage);
    const { response } = await next("response", record.expiresAt, false);
    return checkJoyIdResponse(record, response, { userId: run.userId, client: run.client });
  };

  return cancellable(run.options.signal, (async () => {
    try {
      let address = known;
      let first = true;
      if (!address) {
        stage("connecting");
        const result = await step(newRecord(run, "window", "auth", await run.account()), true);
        first = false;
        if (result.step !== "auth") throw invalidAnswer();
        rememberJoyIdConnection(run.app.joyIdAppURL, result);
        address = result.address;
      }
      const record = await signRecord(run, "window", address);
      stage("signing");
      const result = await step(record, first);
      if (result.step !== "sign") throw invalidAnswer();
      return result.proof;
    } finally {
      close();
    }
  })(), close);
}

async function joyIdBackupByRedirect(run: JoyIdBackupRun, known: string | undefined, stage: (next: JoyIdBackupStage) => void): Promise<RecoveryBackupProof> {
  const record = known ? await signRecord(run, "redirect", known) : newRecord(run, "redirect", "auth", await run.account());
  if (run.options.signal?.aborted) throw new JoyIdCancelledError();
  await run.beforeLeaving();
  leaveForJoyId(record);
  stage("leaving");
  // The page is leaving; the provider finishes the backup when JoyID sends the user back. If the browser brings
  // this page back from its cache instead (Back on JoyID's page), the request is over.
  return new Promise<never>((_, reject) => {
    const back = (event: PageTransitionEvent) => {
      if (!event.persisted) return;
      window.removeEventListener("pageshow", back);
      // The request is over: an answer that still arrives later (Forward) must not be applied.
      takeJoyIdRecord(sessionStorage, record.id);
      reject(new JoyIdCancelledError());
    };
    window.addEventListener("pageshow", back);
  });
}

/**
 * Before the whole page goes to JoyID with a browser Fiber node running: refuses while a payment or channel change
 * is in flight, waits for a start in progress, then stops the node cleanly (its lock and lease go with it), so it
 * isn't killed mid-write when the page unloads. A hosted node keeps running on KeyWay's servers.
 */
export async function stopBrowserNodeForRedirect(node: {
  kind: "hosted" | "browser";
  busy: boolean;
  starting: Promise<unknown>;
  running: () => boolean;
  stop: () => Promise<void>;
}): Promise<void> {
  if (node.kind !== "browser") return;
  if (node.busy) throw new Error("A Fiber payment or channel change is still running. Wait for it to finish, then add the JoyID backup");
  await node.starting.catch(() => undefined);
  if (node.running()) await node.stop();
}

/** Records the request in this tab and sends the whole page to JoyID. */
export function leaveForJoyId(record: JoyIdRequestRecord): void {
  saveJoyIdRecord(sessionStorage, record);
  location.assign(joyIdRedirectUrl(record, joyIdReturnUrl(record.returnPath)));
}

/**
 * After a full-page redirect: checks JoyID's answer against the request this tab recorded (taken, and so deleted,
 * with `takeJoyIdRecord` before this runs). A connect answer continues straight to the sign step; a signature answer
 * becomes the backup proof.
 */
export async function resumeJoyIdRedirect(
  response: JoyIdResponse,
  record: JoyIdRequestRecord | undefined,
  context: { userId: string | undefined; client: ccc.Client; requestChallenge: () => Promise<string>; now?: Date },
): Promise<{ status: "continuing"; record: JoyIdRequestRecord } | { status: "signed"; record: JoyIdRequestRecord; proof: RecoveryBackupProof }> {
  if (!record || record.transport !== "redirect") throw invalidAnswer();
  const result = await checkJoyIdResponse(record, response, context);
  if (result.step === "sign") return { status: "signed", record, proof: result.proof };
  rememberJoyIdConnection(record.joyIdAppURL, result);
  const challengeNonce = await context.requestChallenge();
  const expiresAt = Number(challengeNonce.split(".")[0]);
  const next: JoyIdRequestRecord = { ...record, id: newJoyIdId(), step: "sign", joyIdAddress: result.address, challengeNonce, expiresAt: Number.isFinite(expiresAt) ? expiresAt : Date.now() + AUTH_TTL_MS };
  leaveForJoyId(next);
  return { status: "continuing", record: next };
}

/** The network a recorded request is for, from the account address it names. */
export function joyIdRecordClient(record: Pick<JoyIdRequestRecord, "account">): ccc.Client {
  return record.account.startsWith("ckb1") ? new ccc.ClientPublicMainnet() : new ccc.ClientPublicTestnet();
}

export type JoyIdHelperStatus = "waiting" | "opening" | "returning" | "done" | "unknown";

/**
 * The JoyID window's side, once per page load: one channel and one set of listeners that outlive the provider's
 * effect, so a re-run (React StrictMode mounts effects twice) neither repeats a message nor leaves a gap in which
 * the opening tab's message is lost.
 */
type HelperLoad = { status: JoyIdHelperStatus; report?: (status: JoyIdHelperStatus) => void };
let helperLoad: HelperLoad | undefined;

/** Forgets this page load's JoyID window. For tests, which simulate several loads in one process. */
export function resetJoyIdHelperLoad(): void { helperLoad = undefined; }

/**
 * The window KeyWay opened for JoyID: tells the opening tab it is ready, takes each request it sends, goes to
 * JoyID with it, and hands JoyID's answer back. It answers only for a request it recorded itself, once. Closing it,
 * or coming back to it from the browser's cache, tells the opening tab to stop waiting.
 */
export function runJoyIdHelper(onStatus: (status: JoyIdHelperStatus) => void): () => void {
  if (helperLoad) {
    const load = helperLoad;
    load.report = onStatus;
    onStatus(load.status);
    return () => { if (load.report === onStatus) load.report = undefined; };
  }
  const load: HelperLoad = { status: "waiting", report: onStatus };
  helperLoad = load;
  const status = (next: JoyIdHelperStatus) => { load.status = next; load.report?.(next); };
  const helperId = new URL(location.href).searchParams.get(JOYID_HELPER_PARAM) ?? "";
  if (!ID_PATTERN.test(helperId) || typeof BroadcastChannel === "undefined") {
    status("unknown");
    return () => { load.report = undefined; };
  }
  const channel = new BroadcastChannel(CHANNEL_NAME);
  let idle: ReturnType<typeof setTimeout> | undefined;
  let toJoyId = false;
  const post = (message: HelperMessage) => channel.postMessage(message);
  const waitForOpener = () => {
    clearTimeout(idle);
    idle = setTimeout(() => status("unknown"), 2 * 60_000);
  };
  // Closing this window (or leaving it for anything but JoyID) tells the tab that opened it to stop waiting.
  window.addEventListener("pagehide", () => { if (!toJoyId) post({ kind: "gone", helper: helperId }); });
  // Back from JoyID's page into this page from the browser's cache: the request in flight is over.
  window.addEventListener("pageshow", (event: PageTransitionEvent) => {
    if (!event.persisted) return;
    toJoyId = false;
    post({ kind: "gone", helper: helperId });
    status("unknown");
  });
  channel.onmessage = (event: MessageEvent) => {
    const message = event.data as HelperMessage | undefined;
    if (!message || message.helper !== helperId) return;
    if (message.kind === "close") {
      toJoyId = true;
      status("done");
      window.close();
      return;
    }
    if (message.kind !== "go" || !isJoyIdRecord(message.record) || message.record.transport !== "window") return;
    clearTimeout(idle);
    saveJoyIdRecord(sessionStorage, message.record);
    toJoyId = true;
    status("opening");
    location.assign(joyIdRedirectUrl(message.record, joyIdReturnUrl(message.record.returnPath, helperId)));
  };
  const response = takeCapturedJoyIdReturn();
  if (response) {
    const record = takeJoyIdRecord(sessionStorage, joyIdStateId(response.state));
    if (!record || record.transport !== "window") {
      status("unknown");
    } else {
      status("returning");
      post({ kind: "response", helper: helperId, response });
      waitForOpener();
    }
  } else {
    status("waiting");
    post({ kind: "ready", helper: helperId });
    waitForOpener();
  }
  return () => { if (load.report === onStatus) load.report = undefined; };
}

import { litActionCid } from "./lit-cid.ts";

const CHIPOTLE_ACTION_URL = "https://api.chipotle.litprotocol.com/core/v1/lit_action";
const HEX_32 = /^0x[0-9a-fA-F]{64}$/;
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

export type LitSignature = {
  r: `0x${string}`;
  s: `0x${string}`;
  recoveryParam: 0 | 1;
};

export type LitRuntimeConfig = {
  apiKey: string;
  actionCid: string;
  actionCode?: string;
};

type LitActionResponse = {
  has_error: boolean;
  logs: string;
  response: unknown;
};

export async function signCkbDigest(
  digest: string,
  pkpId: string,
  config: LitRuntimeConfig,
): Promise<LitSignature> {
  if (!HEX_32.test(digest)) throw new Error("CKB digest must be a 0x-prefixed 32-byte hex string");
  if (!EVM_ADDRESS.test(pkpId)) throw new Error("Lit PKP ID must be a 20-byte EVM address");
  const signature = await executeAction(config, { pkpId, digest });
  if (!isSignature(signature)) throw new Error("Lit Action returned an invalid signature");

  return signature;
}

export async function encryptFiberKey(
  fiberKey: Uint8Array,
  pkpId: string,
  config: LitRuntimeConfig,
): Promise<string> {
  if (fiberKey.length !== 32) throw new Error("Fiber key must be exactly 32 bytes");
  const response = await executeAction(config, { pkpId, fiberKey: Buffer.from(fiberKey).toString("base64") });
  if (!response || typeof response !== "object" || typeof (response as { ciphertext?: unknown }).ciphertext !== "string") {
    throw new Error("Lit encrypt Action returned invalid ciphertext");
  }
  return (response as { ciphertext: string }).ciphertext;
}

export async function decryptFiberKey(
  ciphertext: string,
  pkpId: string,
  config: LitRuntimeConfig,
): Promise<Uint8Array> {
  if (!ciphertext) throw new Error("Encrypted Fiber key is required");
  const response = await executeAction(config, { pkpId, ciphertext });
  const encoded = response && typeof response === "object" ? (response as { fiberKey?: unknown }).fiberKey : undefined;
  if (typeof encoded !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(encoded)) {
    throw new Error("Lit decrypt Action returned an invalid Fiber key");
  }
  const fiberKey = new Uint8Array(Buffer.from(encoded, "base64"));
  if (fiberKey.length !== 32) throw new Error("Lit decrypt Action returned an invalid Fiber key");
  return fiberKey;
}

/** A Lit failure that is worth retrying: rate limiting, a dependency outage, a network error, or a grant that hasn't propagated yet. */
export class LitTransientError extends Error {
  constructor(message: string, readonly reason: "unavailable" | "not-granted") { super(message); }
}

const NOT_GRANTED = /cannot use selected wallet/i;

async function executeAction(config: LitRuntimeConfig, js_params: Record<string, unknown>): Promise<unknown> {
  if (!config.apiKey || !config.actionCid) throw new Error("Lit runtime configuration is incomplete");
  // Lit allows only Action code whose CID is in the KeyWay group; refuse to send code that isn't the pinned CID.
  if (config.actionCode && litActionCid(config.actionCode) !== config.actionCid) {
    throw new Error("Lit Action code does not match its pinned CID");
  }
  const action = config.actionCode ? { code: config.actionCode } : { ipfs_id: config.actionCid };
  return withLitRetry(async () => {
    let response: Response;
    try {
      response = await fetch(CHIPOTLE_ACTION_URL, {
        method: "POST",
        signal: AbortSignal.timeout(30_000),
        // Privacy mode keeps js_params (such as a Fiber key) and Action output out of Chipotle's logs.
        headers: { "Content-Type": "application/json", "X-Api-Key": config.apiKey, "X-Privacy-Mode": "true" },
        body: JSON.stringify({ ...action, js_params }),
      });
    } catch {
      throw new LitTransientError("Lit could not be reached", "unavailable");
    }
    const body: unknown = await response.json().catch(() => null);
    if (!response.ok) {
      const message = readApiError(body, `Lit returned HTTP ${response.status}`);
      if (NOT_GRANTED.test(message)) throw new LitTransientError("Lit has not granted this wallet to the Action yet", "not-granted");
      if ([429, 502, 503, 504].includes(response.status)) throw new LitTransientError(`Lit returned HTTP ${response.status}`, "unavailable");
      throw new Error(message);
    }
    if (!isActionResponse(body)) throw new Error("Lit returned an invalid Action response");
    if (body.has_error) {
      if (NOT_GRANTED.test(body.logs)) throw new LitTransientError("Lit has not granted this wallet to the Action yet", "not-granted");
      throw new Error(`Lit Action failed${body.logs ? `: ${body.logs}` : ""}`);
    }
    return body.response;
  });
}

type RetryOptions = { budgetMs?: number; sleep?: (ms: number) => Promise<void>; now?: () => number };

/**
 * Retries transient Lit failures with backoff (0.5, 1, 2, 4, 8 s...). The default budget outlasts
 * Chipotle's 30-second cached denial after a wallet is first added to the group.
 */
export async function withLitRetry<T>(operation: () => Promise<T>, options: RetryOptions = {}): Promise<T> {
  const { budgetMs = 40_000, sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)), now = Date.now } = options;
  const deadline = now() + budgetMs;
  for (let delay = 500; ; delay = Math.min(delay * 2, 8_000)) {
    try {
      return await operation();
    } catch (error) {
      if (!(error instanceof LitTransientError) || now() + delay > deadline) throw error;
      await sleep(delay);
    }
  }
}

function isActionResponse(value: unknown): value is LitActionResponse {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<LitActionResponse>;
  return typeof candidate.has_error === "boolean" && typeof candidate.logs === "string" && "response" in candidate;
}

function isSignature(value: unknown): value is LitSignature {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<LitSignature>;
  return /^0x[0-9a-fA-F]{64}$/.test(candidate.r ?? "") &&
    /^0x[0-9a-fA-F]{64}$/.test(candidate.s ?? "") &&
    (candidate.recoveryParam === 0 || candidate.recoveryParam === 1);
}

function readApiError(value: unknown, fallback: string): string {
  if (typeof value === "string" && value) return value;
  if (!value || typeof value !== "object") return fallback;
  const candidate = value as { message?: unknown; error?: unknown; fix?: unknown };
  return [candidate.message, candidate.error, candidate.fix].filter((item): item is string => typeof item === "string").join(". ") || fallback;
}

const CHIPOTLE_ACTION_URL = "https://api.chipotle.litprotocol.com/core/v1/lit_action";
const HEX_32 = /^0x[0-9a-fA-F]{64}$/;
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

export type LitSignature = {
  r: `0x${string}`;
  s: `0x${string}`;
  recoveryParam: 0 | 1;
};

type LitActionResponse = {
  has_error: boolean;
  logs: string;
  response: unknown;
};

export async function signCkbDigest(
  digest: string,
  pkpId: string,
  config: { apiKey: string; actionCid: string },
): Promise<LitSignature> {
  if (!HEX_32.test(digest)) throw new Error("CKB digest must be a 0x-prefixed 32-byte hex string");
  if (!EVM_ADDRESS.test(pkpId)) throw new Error("Lit PKP ID must be a 20-byte EVM address");
  if (!config.apiKey || !config.actionCid) throw new Error("Lit runtime configuration is incomplete");

  const response = await fetch(CHIPOTLE_ACTION_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Api-Key": config.apiKey },
    body: JSON.stringify({ ipfs_id: config.actionCid, js_params: { pkpId, digest } }),
  });
  const body: unknown = await response.json().catch(() => null);

  if (!response.ok) throw new Error(readApiError(body, `Lit returned HTTP ${response.status}`));
  if (!isActionResponse(body)) throw new Error("Lit returned an invalid Action response");
  if (body.has_error) throw new Error(`Lit Action failed${body.logs ? `: ${body.logs}` : ""}`);
  if (!isSignature(body.response)) throw new Error("Lit Action returned an invalid signature");

  return body.response;
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
  if (!value || typeof value !== "object") return fallback;
  const candidate = value as { message?: unknown; error?: unknown; fix?: unknown };
  return [candidate.message, candidate.error, candidate.fix].filter((item): item is string => typeof item === "string").join(". ") || fallback;
}

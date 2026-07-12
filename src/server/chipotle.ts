const BASE_URL = "https://api.chipotle.litprotocol.com/core/v1";
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

export async function createPkp(apiKey: string): Promise<string> {
  const response = await request("create PKP", "/create_wallet", apiKey, { method: "POST" });
  const address = response && typeof response === "object" ? (response as { wallet_address?: unknown }).wallet_address : undefined;
  if (typeof address !== "string" || !EVM_ADDRESS.test(address)) throw new Error("Chipotle returned an invalid PKP");
  return address;
}

export async function findGroupId(apiKey: string, name: string): Promise<number> {
  const response = await request("list groups", "/list_groups?page_number=0&page_size=100", apiKey);
  if (!Array.isArray(response)) throw new Error("Chipotle returned an invalid group list");
  const group = response.find((item) => item && typeof item === "object" && (item as { name?: unknown }).name === name);
  const id = group && typeof group === "object" ? (group as { id?: unknown }).id : undefined;
  if (typeof id !== "string") throw new Error(`Lit group not found: ${name}`);
  const parsed = Number(BigInt(id));
  if (!Number.isSafeInteger(parsed)) throw new Error("Lit group ID is outside the supported range");
  return parsed;
}

export async function addPkpToGroup(apiKey: string, groupId: number, pkpId: string): Promise<void> {
  await request("add PKP to group", "/add_pkp_to_group", apiKey, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ group_id: groupId, pkp_id: pkpId }),
  });
}

async function request(operation: string, path: string, apiKey: string, init: RequestInit = {}): Promise<unknown> {
  if (!apiKey) throw new Error("Lit usage API key is missing");
  const response = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: { ...init.headers, "X-Api-Key": apiKey },
  });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok || isApiError(body)) {
    throw new Error(`Chipotle could not ${operation}: ${readApiError(body, `HTTP ${response.status}`)}`);
  }
  return body;
}

function isApiError(value: unknown): boolean {
  return Boolean(value && typeof value === "object" && "error" in value);
}

function readApiError(value: unknown, fallback: string): string {
  if (typeof value === "string" && value) return value;
  if (!value || typeof value !== "object") return fallback;
  const candidate = value as { message?: unknown; error?: unknown; fix?: unknown };
  return [candidate.message, candidate.error, candidate.fix].filter((item): item is string => typeof item === "string").join(". ") || fallback;
}

// Client for the managed KeyWay API's dashboard endpoints. Rules live in src/server/applications.ts.
const API_URL = "https://keyway-api-production.up.railway.app";

export type ApplicationOrigin = { origin: string; environment: "development" | "production" };
export type DeveloperApplication = {
  appId: string;
  name: string;
  disabled: boolean;
  otpLimitPerMinute: number;
  origins: ApplicationOrigin[];
  usage: { sent24h: number; failed24h: number; rateLimited24h: number };
  createdAt: string;
  updatedAt: string;
};

export class DashboardApiError extends Error {
  constructor(message: string, readonly status: number) { super(message); }
}

export async function apiRequest<T>(path: string, body: unknown, token?: string): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-KeyWay-Auth-Scope": "dashboard", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body),
    });
  } catch {
    throw new DashboardApiError("The KeyWay API didn't respond", 0);
  }
  const result = response.status === 204 ? undefined : await response.json().catch(() => ({}));
  if (!response.ok) throw new DashboardApiError(result?.error ?? "KeyWay request failed", response.status);
  return result as T;
}

export function developerRequest<T>(token: string, body: Record<string, unknown>): Promise<T> {
  return apiRequest("/api/keyway/developer/apps", body, token);
}

/** Mirrors the server's origin rules so mistakes are explained before the request is sent. */
export function checkOrigin(value: string): { origin?: string; error?: string } {
  let parsed: URL;
  try {
    parsed = new URL(value.trim());
  } catch {
    return { error: "Enter a full origin, including the scheme, such as https://acmepay.xyz." };
  }
  if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || parsed.username || parsed.password) {
    return { error: "Origins must start with https:// or http:// and can't include a username or password." };
  }
  if (parsed.pathname !== "/" || parsed.search || parsed.hash) {
    return { error: `Origins can't include a path, query or fragment. Use ${parsed.origin} instead.` };
  }
  return { origin: parsed.origin };
}

export const APP_NAME_MAX = 80;

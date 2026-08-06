export type KeyWayApiClientOptions = {
  fetch?: typeof globalThis.fetch;
};

export type NodeBackupPayload = {
  formatVersion: 1;
  databasePrefix: string;
  salt: string;
  iv: string;
  ciphertext: string;
  digest: string;
};

export type ClaimedNodeBackup = NodeBackupPayload & { generation: number };

const KEYWAY_API_BASE_URL = "https://keyway-api-production.up.railway.app";

export class KeyWayApiClient {
  private readonly fetcher: typeof globalThis.fetch;

  constructor(options: KeyWayApiClientOptions = {}) {
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  async sendCode(email: string): Promise<{ methodId: string }> {
    return this.publicJson("/api/keyway/auth/send-code", { email });
  }

  async verifyCode(methodId: string, code: string): Promise<{ sessionToken: string; user: { id: string } }> {
    return this.publicJson("/api/keyway/auth/verify-code", { methodId, code });
  }

  async session(authToken: string): Promise<{ user: { id: string } }> {
    return this.json("/api/keyway/auth/session", authToken, {});
  }

  async logout(authToken: string): Promise<void> {
    const response = await this.request("/api/keyway/auth/logout", authToken, {});
    if (!response.ok) throw new Error(await responseError(response, "Could not log out"));
  }

  bootstrap(authToken: string, body: { deviceIdHash: string; fiberKey?: string }) {
    return this.json("/api/keyway/bootstrap", authToken, body);
  }

  async loadFiberKey(authToken: string, body: { deviceIdHash: string; leaseId: string }): Promise<Uint8Array> {
    const response = await this.request("/api/keyway/fiber-key", authToken, body);
    if (!response.ok) throw new Error(await responseError(response, "Could not unlock Fiber credentials"));
    return new Uint8Array(await response.arrayBuffer());
  }

  async markChannelOpened(authToken: string, body: { deviceIdHash: string }): Promise<void> {
    const response = await this.request("/api/keyway/channel-state", authToken, body);
    if (!response.ok) throw new Error(await responseError(response, "Could not protect Fiber channel recovery state"));
  }

  async requestLease(
    authToken: string,
    body: { operation: string; deviceIdHash: string; leaseId?: string },
  ): Promise<{ leaseId: string; expiresAt: string }> {
    const response = await this.request("/api/keyway/device-lease", authToken, body);
    if (response.status === 204) return { leaseId: body.leaseId ?? "", expiresAt: "" };
    const result = await response.json();
    if (!response.ok) throw new Error(result.error ?? "Device lease failed");
    return result;
  }

  signTransaction(authToken: string, body: Record<string, unknown>) {
    return this.json("/api/keyway/sign-transaction", authToken, body);
  }

  saveNodeBackup(
    authToken: string,
    body: { deviceIdHash: string; leaseId: string; backup: NodeBackupPayload },
  ): Promise<{ generation: number; digest: string }> {
    return this.json("/api/keyway/node-backup/save", authToken, body);
  }

  loadNodeBackup(
    authToken: string,
    body: { deviceIdHash: string; leaseId: string },
  ): Promise<ClaimedNodeBackup> {
    return this.json("/api/keyway/node-backup/load", authToken, body);
  }

  async confirmNodeBackup(
    authToken: string,
    body: { deviceIdHash: string; leaseId: string; generation: number },
  ): Promise<void> {
    const response = await this.request("/api/keyway/node-backup/confirm", authToken, body);
    if (!response.ok) throw new Error(await responseError(response, "Could not confirm Fiber state restoration"));
  }

  private async publicJson<T>(path: string, body: unknown): Promise<T> {
    const response = await this.fetcher(`${KEYWAY_API_BASE_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error ?? "KeyWay request failed");
    return result;
  }

  private async json<T>(path: string, authToken: string, body: unknown): Promise<T> {
    const response = await this.request(path, authToken, body);
    const result = await response.json();
    if (!response.ok) throw new Error(result.error ?? "KeyWay request failed");
    return result;
  }

  private request(path: string, authToken: string, body: unknown): Promise<Response> {
    return this.fetcher(`${KEYWAY_API_BASE_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${authToken}` },
      body: JSON.stringify(body),
    });
  }
}

async function responseError(response: Response, fallback: string): Promise<string> {
  const result = await response.json().catch(() => ({}));
  return result.error ?? fallback;
}

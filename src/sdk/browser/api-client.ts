export type KeyWayApiClientOptions = {
  fetch?: typeof globalThis.fetch;
  appId?: string;
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

const KEYWAY_API_BASE_URL = process.env.KEYWAY_API_TARGET === "staging"
  ? "https://keyway-api-staging-staging.up.railway.app"
  : "https://keyway-api-production.up.railway.app";
const KEYWAY_API_PATH = "/api/v1/keyway";

export class KeyWayApiClient {
  private readonly fetcher: typeof globalThis.fetch;
  private readonly appId?: string;

  constructor(options: KeyWayApiClientOptions = {}) {
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.appId = options.appId;
  }

  async sendCode(email: string): Promise<{ methodId: string }> {
    return this.publicJson(`${KEYWAY_API_PATH}/auth/send-code`, { email });
  }

  async verifyCode(methodId: string, code: string): Promise<{ sessionToken: string; user: { id: string } }> {
    return this.publicJson(`${KEYWAY_API_PATH}/auth/verify-code`, { methodId, code });
  }

  async session(authToken: string): Promise<{ user: { id: string } }> {
    return this.json(`${KEYWAY_API_PATH}/auth/session`, authToken, {});
  }

  async logout(authToken: string): Promise<void> {
    const response = await this.request(`${KEYWAY_API_PATH}/auth/logout`, authToken, {});
    if (!response.ok) throw new Error(await responseError(response, "Could not log out"));
  }

  bootstrap(authToken: string, body: {
    deviceIdHash: string;
    fiberKey?: string;
    nodeMode?: "browser" | "managed";
  }) {
    return this.idempotentJson(`${KEYWAY_API_PATH}/bootstrap`, authToken, body);
  }

  async loadFiberKey(authToken: string, body: { deviceIdHash: string; leaseId: string }): Promise<Uint8Array> {
    const response = await this.request(`${KEYWAY_API_PATH}/fiber-key`, authToken, body);
    if (!response.ok) throw new Error(await responseError(response, "Could not unlock Fiber credentials"));
    return new Uint8Array(await response.arrayBuffer());
  }

  async markChannelOpened(authToken: string, body: { deviceIdHash: string }): Promise<void> {
    const response = await this.request(`${KEYWAY_API_PATH}/channel-state`, authToken, body);
    if (!response.ok) throw new Error(await responseError(response, "Could not protect Fiber channel recovery state"));
  }

  async requestLease(
    authToken: string,
    body: { operation: string; deviceIdHash: string; leaseId?: string },
  ): Promise<{ leaseId: string; expiresAt: string }> {
    const response = await this.request(`${KEYWAY_API_PATH}/device-lease`, authToken, body);
    if (response.status === 204) return { leaseId: body.leaseId ?? "", expiresAt: "" };
    const result = await response.json();
    if (!response.ok) throw new Error(result.error ?? "Device lease failed");
    return result;
  }

  signTransaction(authToken: string, body: Record<string, unknown>) {
    return body.operation === "sign"
      ? this.idempotentJson(`${KEYWAY_API_PATH}/sign-transaction`, authToken, body)
      : this.json(`${KEYWAY_API_PATH}/sign-transaction`, authToken, body);
  }

  managedNode<T>(
    authToken: string,
    body: Record<string, unknown>,
    idempotencyKey?: string,
  ): Promise<T> {
    return this.json(`${KEYWAY_API_PATH}/managed-node`, authToken, body, idempotencyKey
      ? { "Idempotency-Key": idempotencyKey }
      : undefined);
  }

  saveNodeBackup(
    authToken: string,
    body: { deviceIdHash: string; leaseId: string; backup: NodeBackupPayload },
  ): Promise<{ generation: number; digest: string }> {
    return this.idempotentJson(`${KEYWAY_API_PATH}/node-backup/save`, authToken, body);
  }

  loadNodeBackup(
    authToken: string,
    body: { deviceIdHash: string; leaseId: string },
  ): Promise<ClaimedNodeBackup> {
    return this.idempotentJson(`${KEYWAY_API_PATH}/node-backup/load`, authToken, body);
  }

  async confirmNodeBackup(
    authToken: string,
    body: { deviceIdHash: string; leaseId: string; generation: number },
  ): Promise<void> {
    const response = await this.request(
      `${KEYWAY_API_PATH}/node-backup/confirm`,
      authToken,
      body,
      { "Idempotency-Key": crypto.randomUUID() },
    );
    if (!response.ok) throw new Error(await responseError(response, "Could not confirm Fiber state restoration"));
  }

  private async publicJson<T>(path: string, body: unknown): Promise<T> {
    const response = await this.fetcher(`${KEYWAY_API_BASE_URL}${path}`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(body),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error ?? "KeyWay request failed");
    return result;
  }

  private async json<T>(
    path: string,
    authToken: string,
    body: unknown,
    extraHeaders?: Record<string, string>,
  ): Promise<T> {
    const response = await this.request(path, authToken, body, extraHeaders);
    const result = await response.json();
    if (!response.ok) throw new Error(result.error ?? "KeyWay request failed");
    return result;
  }

  private idempotentJson<T>(path: string, authToken: string, body: unknown): Promise<T> {
    return this.json(path, authToken, body, { "Idempotency-Key": crypto.randomUUID() });
  }

  private request(
    path: string,
    authToken: string,
    body: unknown,
    extraHeaders?: Record<string, string>,
  ): Promise<Response> {
    const request = () => this.fetcher(`${KEYWAY_API_BASE_URL}${path}`, {
      method: "POST",
      headers: { ...this.headers(authToken), ...extraHeaders },
      body: JSON.stringify(body),
    });
    if (!extraHeaders?.["Idempotency-Key"]) return request();
    return request().then(
      (response) => [502, 503, 504].includes(response.status) ? request() : response,
      () => request(),
    );
  }

  private headers(authToken?: string): Record<string, string> {
    return {
      "Content-Type": "application/json",
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
      ...(this.appId ? { "X-KeyWay-App-Id": this.appId } : {}),
    };
  }
}

async function responseError(response: Response, fallback: string): Promise<string> {
  const result = await response.json().catch(() => ({}));
  return result.error ?? fallback;
}

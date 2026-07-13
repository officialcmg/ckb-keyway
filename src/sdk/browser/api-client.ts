export type KeyWayApiClientOptions = {
  apiBaseUrl?: string;
  fetch?: typeof globalThis.fetch;
};

export class KeyWayApiClient {
  private readonly apiBaseUrl: string;
  private readonly fetcher: typeof globalThis.fetch;

  constructor(options: KeyWayApiClientOptions = {}) {
    this.apiBaseUrl = options.apiBaseUrl?.replace(/\/$/, "") ?? "";
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  bootstrap(sessionJwt: string, body: { deviceIdHash: string; fiberKey?: string }) {
    return this.json("/api/keyway/bootstrap", sessionJwt, body);
  }

  async loadFiberKey(sessionJwt: string, body: { deviceIdHash: string; leaseId: string }): Promise<Uint8Array> {
    const response = await this.request("/api/keyway/fiber-key", sessionJwt, body);
    if (!response.ok) throw new Error(await responseError(response, "Could not unlock Fiber credentials"));
    return new Uint8Array(await response.arrayBuffer());
  }

  async markChannelOpened(sessionJwt: string, body: { deviceIdHash: string }): Promise<void> {
    const response = await this.request("/api/keyway/channel-state", sessionJwt, body);
    if (!response.ok) throw new Error(await responseError(response, "Could not protect Fiber channel recovery state"));
  }

  async requestLease(
    sessionJwt: string,
    body: { operation: string; deviceIdHash: string; leaseId?: string },
  ): Promise<{ leaseId: string; expiresAt: string }> {
    const response = await this.request("/api/keyway/device-lease", sessionJwt, body);
    if (response.status === 204) return { leaseId: body.leaseId ?? "", expiresAt: "" };
    const result = await response.json();
    if (!response.ok) throw new Error(result.error ?? "Device lease failed");
    return result;
  }

  signTransaction(sessionJwt: string, body: Record<string, unknown>) {
    return this.json("/api/keyway/sign-transaction", sessionJwt, body);
  }

  private async json(path: string, sessionJwt: string, body: unknown): Promise<unknown> {
    const response = await this.request(path, sessionJwt, body);
    const result = await response.json();
    if (!response.ok) throw new Error(result.error ?? "KeyWay request failed");
    return result;
  }

  private request(path: string, sessionJwt: string, body: unknown): Promise<Response> {
    return this.fetcher(`${this.apiBaseUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${sessionJwt}` },
      body: JSON.stringify(body),
    });
  }
}

async function responseError(response: Response, fallback: string): Promise<string> {
  const result = await response.json().catch(() => ({}));
  return result.error ?? fallback;
}

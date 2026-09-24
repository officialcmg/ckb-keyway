import assert from "node:assert/strict";
import test from "node:test";
import { KeyWayApiClient } from "../src/sdk/browser/api-client.ts";

test("sends SDK requests to the managed KeyWay backend", async () => {
  let requestedUrl = "";
  const api = new KeyWayApiClient({
    fetch: async (input) => {
      requestedUrl = String(input);
      return Response.json({ needsFiberKey: true });
    },
  });

  await api.bootstrap("session", { deviceIdHash: "00".repeat(32) });
  assert.equal(requestedUrl, "https://keyway-api-production.up.railway.app/api/v1/keyway/bootstrap");
});

test("keeps OTP public and protects session requests with the KeyWay token", async () => {
  const requests: RequestInit[] = [];
  const api = new KeyWayApiClient({
    fetch: async (_input, init) => {
      requests.push(init ?? {});
      return Response.json(requests.length === 1
        ? { methodId: "email-test" }
        : { user: { id: "user-test" } });
    },
  });

  await api.sendCode("user@example.com");
  await api.session("keyway-session");

  assert.equal(new Headers(requests[0].headers).has("authorization"), false);
  assert.equal(new Headers(requests[1].headers).get("authorization"), "Bearer keyway-session");
});

test("identifies registered applications on every request", async () => {
  const headers: Headers[] = [];
  const api = new KeyWayApiClient({
    appId: "keyway_test",
    fetch: async (_input, init) => {
      headers.push(new Headers(init?.headers));
      return Response.json(headers.length === 1
        ? { methodId: "email-test" }
        : { user: { id: "user-test" } });
    },
  });

  await api.sendCode("user@example.com");
  await api.session("keyway-session");

  assert.equal(headers[0].get("x-keyway-app-id"), "keyway_test");
  assert.equal(headers[1].get("x-keyway-app-id"), "keyway_test");
});

test("uploads and confirms encrypted node backups through authenticated endpoints", async () => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const api = new KeyWayApiClient({
    fetch: async (input, init) => {
      requests.push({ url: String(input), init });
      if (String(input).endsWith("/save")) return Response.json({ generation: 2, digest: "ab".repeat(32) });
      return new Response(null, { status: 204 });
    },
  });
  const backup = {
    formatVersion: 1 as const,
    databasePrefix: "/wasm-wallet",
    salt: "salt",
    iv: "iv",
    ciphertext: "ciphertext",
    digest: "ab".repeat(32),
  };
  await api.saveNodeBackup("session", { deviceIdHash: "00".repeat(32), leaseId: "lease", backup });
  await api.confirmNodeBackup("session", {
    deviceIdHash: "00".repeat(32),
    leaseId: "lease",
    generation: 2,
  });
  assert.match(requests[0].url, /node-backup\/save$/);
  assert.match(requests[1].url, /node-backup\/confirm$/);
  assert.equal(new Headers(requests[0].init?.headers).get("authorization"), "Bearer session");
});

test("sends idempotency keys for managed mutations", async () => {
  let headers = new Headers();
  const api = new KeyWayApiClient({
    fetch: async (_input, init) => {
      headers = new Headers(init?.headers);
      return Response.json({ status: "Success" });
    },
  });
  await api.managedNode("session", { operation: "send-payment" }, "payment-request-1234");
  assert.equal(headers.get("idempotency-key"), "payment-request-1234");
});

test("retries versioned mutations with the same idempotency key", async () => {
  const keys: string[] = [];
  let attempts = 0;
  const api = new KeyWayApiClient({
    fetch: async (_input, init) => {
      keys.push(new Headers(init?.headers).get("idempotency-key") ?? "");
      attempts += 1;
      if (attempts === 1) throw new TypeError("network interrupted");
      return Response.json({ needsFiberKey: true });
    },
  });

  await api.bootstrap("session", { deviceIdHash: "00".repeat(32) });
  assert.equal(attempts, 2);
  assert.match(keys[0], /^[0-9a-f-]{36}$/);
  assert.equal(keys[1], keys[0]);
});

test("retries transient server failures only for idempotent requests", async () => {
  let attempts = 0;
  const api = new KeyWayApiClient({
    fetch: async () => {
      attempts += 1;
      return attempts === 1
        ? Response.json({ error: "temporarily unavailable" }, { status: 503 })
        : Response.json({ needsFiberKey: true });
    },
  });

  await api.bootstrap("session", { deviceIdHash: "00".repeat(32) });
  assert.equal(attempts, 2);
});

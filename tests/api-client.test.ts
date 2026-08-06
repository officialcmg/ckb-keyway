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
  assert.equal(requestedUrl, "https://keyway-api-production.up.railway.app/api/keyway/bootstrap");
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

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

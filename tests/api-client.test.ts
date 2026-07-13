import assert from "node:assert/strict";
import test from "node:test";
import { KeyWayApiClient } from "../src/sdk/browser/api-client.ts";

test("sends SDK requests to a configured backend", async () => {
  let requestedUrl = "";
  const api = new KeyWayApiClient({
    apiBaseUrl: "https://api.keyway.test/",
    fetch: async (input) => {
      requestedUrl = String(input);
      return Response.json({ needsFiberKey: true });
    },
  });

  await api.bootstrap("session", { deviceIdHash: "00".repeat(32) });
  assert.equal(requestedUrl, "https://api.keyway.test/api/keyway/bootstrap");
});

test("keeps same-origin requests relative when no backend is configured", async () => {
  let requestedUrl = "";
  const api = new KeyWayApiClient({
    fetch: async (input) => {
      requestedUrl = String(input);
      return Response.json({ needsFiberKey: true });
    },
  });

  await api.bootstrap("session", { deviceIdHash: "00".repeat(32) });
  assert.equal(requestedUrl, "/api/keyway/bootstrap");
});

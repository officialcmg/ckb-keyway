import assert from "node:assert/strict";
import test from "node:test";
import { handleKeyWayRequest } from "../src/server/http.ts";

test("serves health checks and configured CORS without authentication", async () => {
  process.env.KEYWAY_ALLOWED_ORIGINS = "https://wallet.example";
  const response = await handleKeyWayRequest(new Request("https://api.example/healthz", {
    headers: { Origin: "https://wallet.example" },
  }));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("access-control-allow-origin"), "https://wallet.example");
  assert.deepEqual(await response.json(), { status: "ok" });
});

test("rejects unconfigured browser origins", async () => {
  process.env.KEYWAY_ALLOWED_ORIGINS = "https://wallet.example";
  const response = await handleKeyWayRequest(new Request("https://api.example/healthz", {
    headers: { Origin: "https://malicious.example" },
  }));
  assert.equal(response.status, 403);
});

test("rejects malformed OTP requests before calling the provider", async () => {
  process.env.KEYWAY_ALLOWED_ORIGINS = "https://wallet.example";
  const response = await handleKeyWayRequest(new Request("https://api.example/api/keyway/auth/send-code", {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: "https://wallet.example" },
    body: JSON.stringify({ email: "not-an-email" }),
  }));
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: "A valid email address is required" });
});

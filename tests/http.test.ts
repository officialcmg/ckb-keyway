import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { handleKeyWayRequest } from "../src/server/http.ts";
import { nodeRequestHandler } from "../src/server/node-server.ts";

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

test("allows CORS preflight before validating the app ID on the real request", async () => {
  process.env.KEYWAY_ALLOWED_ORIGINS = "https://wallet.example";
  const response = await handleKeyWayRequest(new Request("https://api.example/api/keyway/auth/send-code", {
    method: "OPTIONS",
    headers: {
      Origin: "https://new-app.example",
      "Access-Control-Request-Headers": "content-type,x-keyway-app-id",
      "Access-Control-Request-Method": "POST",
    },
  }));
  assert.equal(response.status, 204);
  assert.equal(response.headers.get("access-control-allow-origin"), "https://new-app.example");
  assert.match(response.headers.get("access-control-allow-headers") ?? "", /X-KeyWay-App-Id/);
});

test("rejects malformed OTP requests before calling the provider", async () => {
  process.env.KEYWAY_ALLOWED_ORIGINS = "https://wallet.example";
  process.env.KEYWAY_DASHBOARD_ORIGINS = "https://wallet.example";
  const response = await handleKeyWayRequest(new Request("https://api.example/api/keyway/auth/send-code", {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: "https://wallet.example", "X-KeyWay-Auth-Scope": "dashboard" },
    body: JSON.stringify({ email: "not-an-email" }),
  }));
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: "A valid email address is required" });
});

test("serves versioned API routes while retaining legacy compatibility", async () => {
  process.env.KEYWAY_ALLOWED_ORIGINS = "https://wallet.example";
  process.env.KEYWAY_DASHBOARD_ORIGINS = "https://wallet.example";
  const response = await handleKeyWayRequest(new Request("https://api.example/api/v1/keyway/auth/send-code", {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: "https://wallet.example", "X-KeyWay-Auth-Scope": "dashboard" },
    body: JSON.stringify({ email: "not-an-email" }),
  }));
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: "A valid email address is required" });
});

test("readiness checks tell anonymous callers only ready or unavailable", async (t) => {
  process.env.KEYWAY_ALLOWED_ORIGINS = "https://wallet.example";
  const saved = { ...process.env };
  t.after(() => {
    for (const name of ["DATABASE_URL", "KEYWAY_MANAGED_FIBER_HOST_URL", "KEYWAY_MANAGED_FIBER_HOST_TOKEN"]) {
      if (saved[name] === undefined) delete process.env[name]; else process.env[name] = saved[name];
    }
  });
  const errors: unknown[][] = [];
  const error = console.error;
  console.error = (...args: unknown[]) => { errors.push(args); };
  t.after(() => { console.error = error; });
  const check = async (path: string) => {
    const response = await handleKeyWayRequest(new Request(`https://api.example${path}`));
    assert.equal(response.status, 503);
    const body = await response.text();
    assert.deepEqual(JSON.parse(body), { status: "unavailable" });
    assert.doesNotMatch(body, /internal|DATABASE_URL|ENOTFOUND|5432/);
  };

  delete process.env.DATABASE_URL;
  await check("/readyz");
  process.env.DATABASE_URL = "postgres://keyway:not-a-secret@db.internal.invalid:5432/keyway";
  await check("/readyz");
  delete process.env.KEYWAY_MANAGED_FIBER_HOST_URL;
  await check("/managed-readyz");
  process.env.KEYWAY_MANAGED_FIBER_HOST_URL = "https://fiber-host.internal.invalid";
  process.env.KEYWAY_MANAGED_FIBER_HOST_TOKEN = "not-a-secret";
  await check("/managed-readyz");
  // The operator's log gets an error code, never the address or credentials.
  assert.ok(errors.length >= 4);
  assert.doesNotMatch(JSON.stringify(errors), /internal\.invalid|not-a-secret/);
});

test("errors outside the API handler get a fixed message", async (t) => {
  const error = console.error;
  console.error = () => undefined;
  const server = createServer(nodeRequestHandler(async () => { throw new Error("connect ECONNREFUSED 10.1.2.3:5432 (db.internal)"); }));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => { console.error = error; server.close(); });
  const { port } = server.address() as { port: number };
  const failed = await fetch(`http://127.0.0.1:${port}/readyz`);
  assert.equal(failed.status, 500);
  assert.deepEqual(await failed.json(), { error: "KeyWay request failed" });
  const tooLarge = await fetch(`http://127.0.0.1:${port}/api/v1/keyway/auth/send-code`, { method: "POST", body: "x".repeat(10_000) });
  assert.equal(tooLarge.status, 413);
  assert.deepEqual(await tooLarge.json(), { error: "Request body is too large" });
});

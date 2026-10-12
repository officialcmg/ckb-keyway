import assert from "node:assert/strict";
import test from "node:test";
import { publicErrorMessage } from "../src/server/http.ts";
import { litActionCid } from "../src/server/lit-cid.ts";
import { LitTransientError, signCkbDigest, withLitRetry } from "../src/server/lit.ts";

const pkpId = `0x${"11".repeat(20)}`;
const digest = `0x${"ab".repeat(32)}`;
const code = "(async () => { Lit.Actions.setResponse({ response: '{}' }); })();";
const config = { apiKey: "test", actionCid: litActionCid(code), actionCode: code };
const signature = { r: `0x${"11".repeat(32)}`, s: `0x${"22".repeat(32)}`, recoveryParam: 1 };
const notGranted = "Internal server error.: Actions failed with : lit_node::Error { kind: Unexpected, source: Uncaught (in promise) Error: API key cannot use selected wallet in selected action }";

async function withFetch<T>(handler: typeof fetch, run: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = handler;
  try { return await run(); } finally { globalThis.fetch = original; }
}

test("computes the IPFS CIDv0 Lit uses for Action source", () => {
  assert.equal(litActionCid("hello world\n"), "QmT78zSuBmuS4z925WZfrqQ1qHaJ56DQaTfyMUF7F8ff5o");
});

test("refuses to send Action code that does not match its pinned CID", async () => {
  let called = false;
  await withFetch(async () => { called = true; return Response.json({}); }, async () => {
    await assert.rejects(() => signCkbDigest(digest, pkpId, { ...config, actionCid: "QmNotThisCode" }), /pinned CID/);
  });
  assert.equal(called, false);
});

test("sends Lit's privacy-mode header with every Action call", async () => {
  await withFetch(async (_input, init) => {
    assert.equal(new Headers(init?.headers).get("X-Privacy-Mode"), "true");
    return Response.json({ has_error: false, logs: "", response: signature });
  }, () => signCkbDigest(digest, pkpId, config));
});

test("waits for a new wallet's group grant to propagate, then signs", async () => {
  let calls = 0;
  const result = await withFetch(async () => {
    calls += 1;
    if (calls < 3) return new Response(JSON.stringify({ message: notGranted }), { status: 500 });
    return Response.json({ has_error: false, logs: "", response: signature });
  }, () => signCkbDigest(digest, pkpId, config));
  assert.equal(calls, 3);
  assert.equal(result.recoveryParam, 1);
});

test("does not retry a request Lit rejects outright", async () => {
  let calls = 0;
  await withFetch(async () => { calls += 1; return new Response(JSON.stringify({ message: "Invalid js_params" }), { status: 400 }); }, async () => {
    await assert.rejects(() => signCkbDigest(digest, pkpId, config), /Invalid js_params/);
  });
  assert.equal(calls, 1);
});

test("gives up once the retry budget is spent", async () => {
  let clock = 0;
  const waits: number[] = [];
  await assert.rejects(() => withLitRetry(async () => { throw new LitTransientError("down", "unavailable"); }, {
    budgetMs: 10_000,
    now: () => clock,
    sleep: async (ms) => { waits.push(ms); clock += ms; },
  }), /down/);
  assert.deepEqual(waits, [500, 1000, 2000, 4000]);
});

test("shows browsers a plain sentence instead of provider internals", () => {
  assert.equal(publicErrorMessage(notGranted), "The Lit signature service is temporarily unavailable. Try again in a moment.");
  assert.equal(publicErrorMessage("Bad\u001b[38;5;245m input\nhere"), "Bad input here");
  assert.equal(publicErrorMessage("x".repeat(500)).length, 240);
  assert.equal(publicErrorMessage("Too many login codes requested. Try again later"), "Too many login codes requested. Try again later");
});

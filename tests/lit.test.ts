import assert from "node:assert/strict";
import test from "node:test";
import { signCkbDigest } from "../src/server/lit.ts";

const config = { apiKey: "test", actionCid: "QmTest" };
const pkpId = `0x${"11".repeat(20)}`;

test("rejects a digest that is not exactly 32 bytes", async () => {
  await assert.rejects(() => signCkbDigest("0x12", pkpId, config), /32-byte/);
});

test("rejects a malformed PKP ID before calling Lit", async () => {
  await assert.rejects(() => signCkbDigest(`0x${"00".repeat(32)}`, "0x12", config), /PKP ID/);
});

test("executes only the configured CID with the supplied PKP and digest", async () => {
  const originalFetch = globalThis.fetch;
  const digest = `0x${"ab".repeat(32)}`;

  globalThis.fetch = async (input, init) => {
    assert.equal(input, "https://api.chipotle.litprotocol.com/core/v1/lit_action");
    assert.equal(new Headers(init?.headers).get("X-Api-Key"), config.apiKey);
    assert.deepEqual(JSON.parse(String(init?.body)), {
      ipfs_id: config.actionCid,
      js_params: { pkpId, digest },
    });
    return Response.json({
      has_error: false,
      logs: "",
      response: { r: `0x${"11".repeat(32)}`, s: `0x${"22".repeat(32)}`, recoveryParam: 1 },
    });
  };

  try {
    assert.equal((await signCkbDigest(digest, pkpId, config)).recoveryParam, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

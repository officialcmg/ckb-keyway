import assert from "node:assert/strict";
import test from "node:test";
import { decryptFiberKey, encryptFiberKey, signCkbDigest } from "../src/server/lit.ts";

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

test("round-trips Fiber key transport through pinned Lit Actions", async () => {
  const originalFetch = globalThis.fetch;
  const fiberKey = new Uint8Array(32).fill(7);
  const encryptedConfig = { apiKey: "test", actionCid: "QmEncrypt" };
  const decryptedConfig = { apiKey: "test", actionCid: "QmDecrypt" };

  globalThis.fetch = async (_input, init) => {
    const request = JSON.parse(String(init?.body));
    if (request.ipfs_id === encryptedConfig.actionCid) {
      assert.equal(request.js_params.fiberKey, Buffer.from(fiberKey).toString("base64"));
      return Response.json({ has_error: false, logs: "", response: { ciphertext: "encrypted" } });
    }
    assert.equal(request.ipfs_id, decryptedConfig.actionCid);
    assert.equal(request.js_params.ciphertext, "encrypted");
    return Response.json({
      has_error: false,
      logs: "",
      response: { fiberKey: Buffer.from(fiberKey).toString("base64") },
    });
  };

  try {
    const ciphertext = await encryptFiberKey(fiberKey, pkpId, encryptedConfig);
    assert.equal(ciphertext, "encrypted");
    assert.deepEqual(await decryptFiberKey(ciphertext, pkpId, decryptedConfig), fiberKey);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("preserves Chipotle string errors", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json("cache miss", { status: 400 });

  try {
    await assert.rejects(
      () => encryptFiberKey(new Uint8Array(32), pkpId, { apiKey: "test", actionCid: "QmEncrypt" }),
      /cache miss/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("submits inline Action source when provided", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_input, init) => {
    const request = JSON.parse(String(init?.body));
    assert.equal(request.code, "async function main() {}");
    assert.equal(request.ipfs_id, undefined);
    return Response.json({ has_error: false, logs: "", response: { ciphertext: "encrypted" } });
  };

  try {
    await encryptFiberKey(new Uint8Array(32), pkpId, {
      apiKey: "test",
      actionCid: "QmRegistered",
      actionCode: "async function main() {}",
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

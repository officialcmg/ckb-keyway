import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { loadLitAction } from "../src/server/lit-actions.ts";
import { litActionCid } from "../src/server/lit-cid.ts";
import { LIT_ACTION_CIDS } from "../src/server/lit-config.ts";
import { POLICY_ACTION_CID } from "../src/server/lit-policy.ts";

test("the API runtime includes all wallet recovery and signing actions", async () => {
  const dockerfile = await readFile(new URL("../Dockerfile", import.meta.url), "utf8");
  const runtime = dockerfile.slice(dockerfile.lastIndexOf("FROM "));
  assert.match(runtime, /COPY --from=build \/app\/lit-actions \.\/lit-actions/);
  for (const name of ["sign-ckb-transaction", "generate-fiber-key", "wrap-fiber-key"] as const) {
    assert.ok((await loadLitAction(name)).length > 0);
  }
});

test("each Action's CID in lit-config.ts matches its source", async () => {
  for (const [action, cid] of Object.entries(LIT_ACTION_CIDS) as [keyof typeof LIT_ACTION_CIDS, string][]) {
    assert.equal(litActionCid(await loadLitAction(action)), cid, action);
  }
});

test("the policy Action's CID is pinned in code, and the server only ever sends that exact source", async () => {
  assert.equal(litActionCid(await loadLitAction("sign-ckb-transaction")), POLICY_ACTION_CID);
});

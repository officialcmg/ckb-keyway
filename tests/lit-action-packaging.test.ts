import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { loadLitAction } from "../src/server/lit-actions.ts";
import { litActionCid } from "../src/server/lit-cid.ts";

test("the API runtime includes all wallet recovery and signing actions", async () => {
  const dockerfile = await readFile(new URL("../Dockerfile", import.meta.url), "utf8");
  const runtime = dockerfile.slice(dockerfile.lastIndexOf("FROM "));
  assert.match(runtime, /COPY --from=build \/app\/lit-actions \.\/lit-actions/);
  for (const name of ["sign-ckb-digest", "generate-fiber-key", "wrap-fiber-key"] as const) {
    assert.ok((await loadLitAction(name)).length > 0);
  }
});

test("each Action's pinned CID in .env.example matches its source", async () => {
  const env = await readFile(new URL("../.env.example", import.meta.url), "utf8");
  const pinned = (name: string) => new RegExp(`^${name}=(\\S+)$`, "m").exec(env)?.[1];
  for (const [variable, action] of [
    ["LIT_SIGN_ACTION_CID", "sign-ckb-digest"],
    ["LIT_GENERATE_ACTION_CID", "generate-fiber-key"],
    ["LIT_WRAP_ACTION_CID", "wrap-fiber-key"],
  ] as const) {
    assert.equal(litActionCid(await loadLitAction(action)), pinned(variable), variable);
  }
});

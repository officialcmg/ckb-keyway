import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { loadLitAction } from "../src/server/lit-actions.ts";

test("the API runtime includes all wallet recovery and signing actions", async () => {
  const dockerfile = await readFile(new URL("../Dockerfile", import.meta.url), "utf8");
  const runtime = dockerfile.slice(dockerfile.lastIndexOf("FROM "));
  assert.match(runtime, /COPY --from=build \/app\/lit-actions \.\/lit-actions/);
  for (const name of ["sign-ckb-digest", "encrypt-fiber-key", "decrypt-fiber-key"] as const) {
    assert.ok((await loadLitAction(name)).length > 0);
  }
});

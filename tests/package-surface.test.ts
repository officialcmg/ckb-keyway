import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("publishes only the React SDK entrypoint", async () => {
  const repositoryPackage = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  const packageJson = JSON.parse(await readFile(new URL("../package.sdk.json", import.meta.url), "utf8"));

  assert.equal(repositoryPackage.private, true);
  assert.equal(packageJson.name, "@ckb-keyway/react");
  assert.deepEqual(Object.keys(packageJson.exports), [".", "./package.json"]);
  assert.deepEqual(packageJson.files, ["dist"]);
  assert.equal(packageJson.dependencies.postgres, undefined);
  assert.equal(packageJson.dependencies.stytch, undefined);
  assert.equal(packageJson.dependencies["@stytch/react"], undefined);
  assert.equal(JSON.stringify(packageJson).includes("dist/server"), false);
});

test("exports React and headless KeyWay APIs from one public entrypoint", async () => {
  const sdk = await import("../src/sdk/react/index.ts");

  assert.equal(typeof sdk.KeyWayProvider, "function");
  assert.equal(typeof sdk.KeyWayLoginButton, "function");
  assert.equal(typeof sdk.KeyWayConnectButton, "function");
  assert.equal(typeof sdk.useKeyWay, "function");
  assert.equal(typeof sdk.connectKeyWay, "function");
});

test("the reference app consumes the published SDK package", async () => {
  const repositoryPackage = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  const referenceApp = await readFile(new URL("../app/auth-panel.tsx", import.meta.url), "utf8");

  assert.equal(repositoryPackage.name, "ckb-keyway");
  assert.equal(repositoryPackage.dependencies["@ckb-keyway/react"], repositoryPackage.version);
  assert.match(referenceApp, /from "@ckb-keyway\/react"/);
  assert.doesNotMatch(referenceApp, /src\/sdk\/react/);
});

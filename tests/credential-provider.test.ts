import assert from "node:assert/strict";
import test from "node:test";
import { KeyWayCredentialProvider } from "../src/sdk/browser/credential-provider.ts";

test("provides only the Fiber key and clears it when locked", async () => {
  const source = new Uint8Array(32).fill(7);
  const credential = new KeyWayCredentialProvider("user-test", async () => source);

  assert.equal(credential.isUnlocked(), false);
  await credential.unlock();
  assert.equal(credential.isUnlocked(), true);
  assert.deepEqual(await credential.getFiberKeyPair(), source);
  assert.equal(await credential.getCkbSecretKey(), undefined);

  const exposedCopy = await credential.getFiberKeyPair();
  exposedCopy.fill(9);
  assert.deepEqual(await credential.getFiberKeyPair(), source);

  await credential.lock();
  assert.equal(credential.isUnlocked(), false);
  await assert.rejects(() => credential.getFiberKeyPair(), /locked/);
});

test("rejects a malformed Fiber key", async () => {
  const credential = new KeyWayCredentialProvider("user-test", async () => new Uint8Array(31));
  await assert.rejects(() => credential.unlock(), /32 bytes/);
});

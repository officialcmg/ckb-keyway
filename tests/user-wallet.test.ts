import assert from "node:assert/strict";
import test from "node:test";
import type { User } from "stytch";
import { readWallet } from "../src/server/user-wallet.ts";

const user = (keyway: unknown) => ({
  user_id: "user-test",
  trusted_metadata: { existing: true, keyway },
}) as unknown as User;

test("reads valid ready wallet metadata without exposing unrelated metadata", () => {
  const wallet = {
    version: 1,
    status: "ready",
    litPkpId: "0x1111111111111111111111111111111111111111",
    litPublicKey: `0x${"22".repeat(33)}`,
    ckbAddress: "ckt1test",
    encryptedFiberKey: "ciphertext",
    primaryDeviceIdHash: "a".repeat(64),
    hasOpenedChannel: false,
    createdAt: "2026-07-12T00:00:00.000Z",
    updatedAt: "2026-07-12T00:00:00.000Z",
  } as const;
  assert.deepEqual(readWallet(user(wallet)), wallet);
});

test("rejects incomplete ready wallet metadata", () => {
  assert.equal(readWallet(user({ version: 1, status: "ready", litPkpId: "0x1", primaryDeviceIdHash: "a" })), undefined);
});

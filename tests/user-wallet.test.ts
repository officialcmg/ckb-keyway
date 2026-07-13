import assert from "node:assert/strict";
import test from "node:test";
import {
  parseWallet,
  rebindProvisioningWallet,
  rebindReadyWallet,
} from "../src/server/user-wallet.ts";

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
  assert.deepEqual(parseWallet(wallet), wallet);
});

test("rejects incomplete ready wallet metadata", () => {
  assert.equal(parseWallet({ version: 1, status: "ready", litPkpId: "0x1", primaryDeviceIdHash: "a" }), undefined);
});

test("rebinds a channel-free wallet when the previous device is inactive", () => {
  const wallet = parseWallet({
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
  })!;
  assert.equal(wallet.status, "ready");
  if (wallet.status !== "ready") throw new Error("Expected ready wallet");
  assert.equal(rebindReadyWallet(wallet, "b".repeat(64)).primaryDeviceIdHash, "b".repeat(64));
});

test("blocks rebinding when channel state or another active device exists", () => {
  const wallet = {
    version: 1,
    status: "ready",
    litPkpId: "0x1111111111111111111111111111111111111111",
    litPublicKey: `0x${"22".repeat(33)}`,
    ckbAddress: "ckt1test",
    encryptedFiberKey: "ciphertext",
    primaryDeviceIdHash: "a".repeat(64),
    hasOpenedChannel: true,
    createdAt: "2026-07-12T00:00:00.000Z",
    updatedAt: "2026-07-12T00:00:00.000Z",
  } as const;
  assert.throws(() => rebindReadyWallet(wallet, "b".repeat(64)), /CHANNEL_STATE_DEVICE_BOUND/);
  assert.throws(
    () => rebindReadyWallet({ ...wallet, hasOpenedChannel: false }, "b".repeat(64), "a".repeat(64)),
    /currently running/,
  );
});

test("rebinds an incomplete provisioning wallet without creating another PKP", () => {
  const wallet = {
    version: 1,
    status: "provisioning",
    litPkpId: "0x1111111111111111111111111111111111111111",
    primaryDeviceIdHash: "a".repeat(64),
    createdAt: "2026-07-12T00:00:00.000Z",
  } as const;
  const rebound = rebindProvisioningWallet(wallet, "b".repeat(64));
  assert.equal(rebound.litPkpId, wallet.litPkpId);
  assert.equal(rebound.primaryDeviceIdHash, "b".repeat(64));
});

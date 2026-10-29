// Turns recovery on for K with E1 as the only EVM backup, through the server's planner and checker, signed locally
// in Lit's place. Dry-runs with test_tx_pool_accept, sends, waits for the commit, and records the result.
import * as ccc from "@ckb-ccc/core";
import { signAccountGroups, formatCkbSignature } from "../../../src/server/funding-transaction.ts";
import { checkRecoveryTransaction, planRecovery } from "../../../src/server/recovery.ts";
import type { ReadyWallet } from "../../../src/server/user-wallet.ts";
import { client, evmAddressOf, loadKeys, localLitSignature, publicKeyOf, saveState, secpAddress, waitCommitted } from "./lib.ts";

const keys = loadKeys();
const publicKey = publicKeyOf(keys.K);
const wallet = {
  version: 1, status: "ready", litPkpId: "0xaudit-throwaway", litPublicKey: publicKey, ckbAddress: await secpAddress(keys.K),
  encryptedFiberKey: "unused", primaryDeviceIdHash: "0".repeat(64), hasOpenedChannel: false,
  createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
} as ReadyWallet;
const backups = [{ kind: "evm" as const, address: evmAddressOf(keys.E1) }];
const plan = await planRecovery(client, wallet, backups);
await checkRecoveryTransaction(client, plan.transaction, publicKey, backups);
const signed = await signAccountGroups(plan.transaction, [{ script: plan.secp, kind: "secp256k1" }], client, async (digest) => formatCkbSignature(localLitSignature(keys.K, digest)));
const cycles = await client.sendTransactionDry(signed, "passthrough");
console.log("dry run ok, cycles", cycles.toString(), "size", signed.toBytes().length + 4, "preview", plan.preview);
const hash = await client.sendTransaction(signed, "passthrough");
console.log("sent", hash);
saveState({ enableTx: hash, omnilockArgs: plan.omnilock.args, adminListTypeArgs: plan.adminListType.args, newAddress: plan.preview.newAddress, backup: backups[0].address });
await waitCommitted(hash);
console.log("committed", hash);

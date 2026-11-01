// Phase 3, step 3: the sign-in check. Runs src/server/legacy-sweep.ts unchanged against CKB testnet, with the
// local Postgres from step 1 (DATABASE_URL) and K's key where the Lit action would sign.
//   1. Negative dry runs: the planned sweep with every output sent to another destination is refused by the
//      policy, although the chain itself would accept it (test_tx_pool_accept), so the policy is what stops it.
//   2. Three sign-ins at once (tabs, devices): one sweep is built and sent; the others step aside.
//   3. A sign-in while that sweep is in the mempool doesn't rebuild it.
//   4. Once committed, a sign-in finds nothing left to move but the cell with data, which stays.
import * as ccc from "@ckb-ccc/core";
import { omnilockArgsFor } from "../../../src/sdk/browser/account-lock.ts";
import { formatCkbSignature, signAccountGroups } from "../../../src/server/funding-transaction.ts";
import { checkLegacySweepTransaction, planLegacySweep, sweepLegacyAddress, type LegacySweepContext } from "../../../src/server/legacy-sweep.ts";
import { readWallet, type ReadyWallet } from "../../../src/server/user-wallet.ts";
import { client, loadKeys, loadState, localLitSignature, publicKeyOf, saveState, secpLockOf, waitCommitted } from "./lib.ts";

const round = process.argv[2] ?? "mixed";
const keys = loadKeys();
const state = loadState();
const user = { id: state.userId as string };
const wallet = await readWallet(user) as ReadyWallet;
if (!wallet?.recovery) throw new Error("run step1-enable.ts first");
const signDigest = async (digest: ccc.Hex) => formatCkbSignature(localLitSignature(keys.K, digest));

// 1. Negative dry runs.
const plan = await planLegacySweep(client, wallet);
if (plan.status !== "ready") throw new Error(`nothing to sweep: ${plan.status}`);
await checkLegacySweepTransaction(client, plan.transaction, wallet.litPublicKey, wallet.recovery);
const destinations: Array<[string, ccc.Script]> = [
  ["I's address", await secpLockOf(publicKeyOf(keys.I))],
  ["K's old address", await secpLockOf(wallet.litPublicKey)],
  ["an Omnilock of K's key with another AdminList", await ccc.Script.fromKnownScript(client, ccc.KnownScript.OmniLock, omnilockArgsFor(wallet.litPublicKey, `0x${"99".repeat(32)}`))],
];
const negatives: Array<Record<string, string>> = [];
for (const [name, lock] of destinations) {
  const tx = plan.transaction.clone();
  tx.outputs.forEach((output) => { output.lock = lock; });
  let policy = "accepted";
  try { await checkLegacySweepTransaction(client, tx, wallet.litPublicKey, wallet.recovery); } catch (error) { policy = (error as Error).message; }
  let chain = "accepted";
  try { await client.sendTransactionDry(await signAccountGroups(tx, plan.groups, client, signDigest), "passthrough"); } catch (error) { chain = (error as Error).message.slice(0, 160); }
  negatives.push({ destination: name, policy, chain });
  console.log("negative:", name, "| policy:", policy, "| chain dry run:", chain);
  if (policy === "accepted") throw new Error("the policy accepted another destination");
}

// 2. Three concurrent sign-ins.
const context: LegacySweepContext = {
  user, client, signDigest,
  recordSigning: async () => undefined,
  broadcast: async (transaction) => {
    const cycles = await client.sendTransactionDry(transaction, "passthrough");
    console.log("test_tx_pool_accept ok, cycles", cycles.toString(), "size", transaction.toBytes().length + 4);
    return client.sendTransaction(transaction, "passthrough");
  },
};
const results = await Promise.all([1, 2, 3].map(() => sweepLegacyAddress(context)));
console.log("concurrent sign-ins:", JSON.stringify(results));
const swept = results.find((result) => result.status === "swept");
if (!swept || results.filter((result) => result.status === "swept").length !== 1) throw new Error("expected exactly one sweep");

// 3. A sign-in while it is in the mempool.
const again = await sweepLegacyAddress(context);
console.log("sign-in while in the mempool:", JSON.stringify(again));

// 4. After commit.
await waitCommitted(swept.transactionHash);
const after = await sweepLegacyAddress(context);
console.log("sign-in after commit:", JSON.stringify(after));
const committed = await client.getTransaction(swept.transactionHash);
saveState({ [`sweep-${round}`]: { ...swept, again, after, negatives, inputs: committed!.transaction.inputs.length, outputs: committed!.transaction.outputs.map((output, index) => ({ ckb: ccc.fixedPointToString(output.capacity), token: Boolean(output.type), data: committed!.transaction.outputsData[index] })) } });
process.exit(0);

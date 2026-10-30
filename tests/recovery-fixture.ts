// A recovery record the chain backs, for tests: the transaction that funded the account's secp256k1 address and
// the transaction that turned recovery on from it, which `answerTransactions` lets an offline client return.
import * as ccc from "@ckb-ccc/core";
import { adminListLock, adminListTypeScript, KEYWAY_OMNILOCK, omnilockArgsFor, secp256k1Lock, type KeyWayRecovery } from "../src/sdk/browser/account-lock.ts";
import type { RecoveryBackup } from "../src/sdk/browser/recovery-backups.ts";

const CKB = 100_000_000n;

export async function anchoredRecovery(publicKey: ccc.HexLike, options: { backups?: RecoveryBackup[]; seed?: number; client?: ccc.Client } = {}) {
  const client = options.client ?? new ccc.ClientPublicTestnet();
  const secp = await secp256k1Lock(client, publicKey);
  const funding = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: `0x${(options.seed ?? 7).toString(16).padStart(64, "0")}`, index: 0 } }],
    outputs: [{ lock: secp, capacity: 10_000n * CKB }],
    outputsData: ["0x"],
  });
  const input0 = ccc.CellInput.from({ previousOutput: { txHash: funding.hash(), index: 0 } });
  const adminListTypeArgs = ccc.hashTypeId(input0, 0);
  const adminListTypeHash = adminListTypeScript({ adminListTypeArgs }).hash();
  const omnilockArgs = omnilockArgsFor(publicKey, adminListTypeHash);
  const omnilock = KEYWAY_OMNILOCK.testnet;
  const enable = ccc.Transaction.from({
    inputs: [input0],
    outputs: [{ lock: adminListLock({ omnilock, omnilockArgs }), type: adminListTypeScript({ adminListTypeArgs }), capacity: 197n * CKB }],
    outputsData: ["0x"],
  });
  const recovery: KeyWayRecovery = {
    omnilockArgs,
    omnilock,
    adminListTypeArgs,
    adminListTypeHash,
    adminListOutPoint: { txHash: enable.hash(), index: 0 },
    enableTransactionHash: enable.hash(),
    legacyAddress: ccc.Address.fromScript(secp, client).toString(),
    enabledAt: "2026-10-29T00:00:00.000Z",
    ...(options.backups ? { backups: options.backups } : {}),
  };
  return { recovery, funding, enable, transactions: [funding, enable] };
}

/** Makes `client.getTransaction` answer these transactions as committed, and defer to `fallback` for others. */
export function answerTransactions(client: ccc.Client, transactions: ccc.Transaction[], fallback?: (hash: ccc.Hex) => Promise<unknown>): ccc.Client {
  const known = new Map(transactions.map((transaction) => [transaction.hash(), transaction]));
  const previous = client.getTransaction.bind(client);
  Object.assign(client, {
    getTransaction: async (hash: ccc.HexLike) => {
      const transaction = known.get(ccc.hexFrom(hash));
      if (transaction) return { transaction, status: "committed", blockNumber: 1n };
      return fallback ? fallback(ccc.hexFrom(hash)) : previous(hash);
    },
  });
  return client;
}

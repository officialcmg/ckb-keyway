// Regression test for the audit's M3 (audit/omnilock-fable-5-1). Everything a thief needs to drain a recovery
// account, except one signature, is public on chain, and Omnilock's flag 0x12 asked the backup's wallet to sign
// only "CKB transaction: 0x<sighash>", which names neither destination nor amount. Backups now approve a readable
// text naming the destination, the CKB, the token cells and the fee, which KeyWay's exec verifier rebuilds from the
// transaction (contracts/keyway-approval). A phishing page can still ask, but the wallet shows the thief's address
// and the whole balance; and a signature over a text with another destination or amount doesn't verify on chain
// (contracts/tests/tests/approval.rs, and the testnet dry runs in research/omnilock/audit-fixes-results.md).
import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { KEYWAY_OMNILOCK, omnilockArgsFor, omnilockScript } from "../src/sdk/browser/account-lock.ts";
import { recoveryApprovalText, rescueApproval } from "../src/sdk/browser/recovery-approval.ts";
import { backupAuth, evmPersonalSignAddress, type RecoveryBackup } from "../src/sdk/browser/recovery-backups.ts";
import { decodeRecoveryList, readRecoveryList, recoveryListRecord, recoveryListRecordOf, setRecoveryListRecord } from "../src/sdk/browser/recovery-list.ts";
import { adminListData, whitelistTree } from "../src/sdk/browser/recovery-smt.ts";
import { signRecoverySpendWithEvm } from "../src/sdk/browser/recovery-spend.ts";

const CKB = 100_000_000n;
const TYPE_ID = "0x00000000000000000000000000000000000000000000000000545950455f4944";
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true));
const backupKey = secp256k1.utils.randomSecretKey();
const backupAddress = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(backupKey, false).slice(1)).slice(12));
const thiefLock = ccc.Script.from({ codeHash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", hashType: "type", args: `0x${"ab".repeat(20)}` });

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

test("M3 fixed: the backup's wallet shows where everything goes and how much, and only that text verifies", async () => {
  const base = await offlineClient([]);
  const backups: RecoveryBackup[] = [{ kind: "evm", address: backupAddress }];
  const adminType = ccc.Script.from({ codeHash: TYPE_ID, hashType: "type", args: ccc.hexFrom(new Uint8Array(32).fill(0x42)) });
  const lock = omnilockScript({ omnilock: KEYWAY_OMNILOCK.testnet, omnilockArgs: omnilockArgsFor(publicKey, adminType.hash()) });
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
  const signed = await signRecoverySpendWithEvm(drain, { client, lock, omnilock: KEYWAY_OMNILOCK.testnet, list: list.entries, entry: list.entries[0], adminList: adminList.outPoint, inputCapacity: 10_000n * CKB }, wallet);

  assert.equal(requests.length, 1);
  const thief = ccc.Address.fromScript(thiefLock, client).toString();
  assert.equal(requests[0].split("\n").slice(0, 5).join("\n"), `KeyWay recovery\nMove everything to ${thief}\nCKB: 9,999\nTokens: none\nFee: 1 CKB`);
  assert.doesNotMatch(requests[0], /^CKB transaction: /);
  // The text ends with the group's sighash (witness lock zeroed at its final length), as Omnilock computes it,
  // and the verifier rebuilds every line from the transaction: the same text for another destination or amount
  // is a different text.
  const witnessArgs = signed.getWitnessArgsAt(0)!;
  const zeroed = signed.clone();
  zeroed.setWitnessArgsAt(0, ccc.WitnessArgs.from({ ...witnessArgs, lock: ccc.hexFrom(new Uint8Array(ccc.bytesFrom(witnessArgs.lock!).length)) }));
  const sighash = (await zeroed.getSignHashInfo(lock, client))!.message;
  assert.equal(requests[0], recoveryApprovalText(client, rescueApproval(signed, lock, 10_000n * CKB), sighash));
  const elsewhere = signed.clone();
  elsewhere.outputs[0].lock = ccc.Script.from({ ...thiefLock, args: `0x${"cd".repeat(20)}` });
  assert.notEqual(recoveryApprovalText(client, rescueApproval(elsewhere, lock, 10_000n * CKB), sighash), requests[0]);
  // The witness carries version 1 ‖ network ‖ the personal_sign signature, through the EVM exec verifier.
  const witness = ccc.bytesFrom(witnessArgs.lock!);
  assert.deepEqual([witness[20], witness[21]], [1, 0]);
  assert.equal(evmPersonalSignAddress(requests[0], witness.slice(22, 87)), backupAddress);
});

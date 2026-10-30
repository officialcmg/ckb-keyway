// Regression tests for the audit's M1 (audit/omnilock-fable-5-1): the rescue page trusted the CKB node for the
// capacity, data and identity of the cells it spends, so a lying node could make a backup sign a rescue that burns
// the balance as fee, burns tokens, or destroys the AdminList. These began as the audit's proof of concept; the page
// now reads every cell from the transaction that created it, after checking that transaction's hash against the
// out point, takes the AdminList from one place (under its owner-only lock) and never spends it.
import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { adminListLock, KEYWAY_OMNILOCK, omnilockArgsFor, omnilockScript, secp256k1Lock } from "../src/sdk/browser/account-lock.ts";
import { backupAuth, type RecoveryBackup } from "../src/sdk/browser/recovery-backups.ts";
import { recoveryListRecord, setRecoveryListRecord } from "../src/sdk/browser/recovery-list.ts";
import { adminListData, whitelistTree } from "../src/sdk/browser/recovery-smt.ts";
import { checkRescueTransaction, connectEvmBackup, openRescueAccount, planRescue, signRescueWithEvm } from "../src/rescue/rescue.ts";

const CKB = 100_000_000n;
const TYPE_ID = "0x00000000000000000000000000000000000000000000000000545950455f4944";
const litKey = secp256k1.utils.randomSecretKey();
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(litKey, true));
const evmKey = secp256k1.utils.randomSecretKey();
const evmAddress = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(evmKey, false).slice(1)).slice(12));

/** A testnet client answering from these cells and transactions, never reaching the network. */
async function offlineClient(cells: ccc.Cell[], transactions: ccc.Transaction[] = [], singleton?: ccc.Cell): Promise<ccc.Client> {
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  await client.cache.recordCells(cells);
  Object.assign(client, {
    findSingletonCellByType: async (type: ccc.ScriptLike) => singleton ?? cells.find((cell) => cell.cellOutput.type?.eq(ccc.Script.from(type))),
    getTransaction: async (hash: ccc.HexLike) => {
      // A lying node may answer any hash with any transaction; nothing checks the hash against the content.
      const transaction = transactions.find((candidate) => candidate.hash() === ccc.hexFrom(hash)) ?? (singleton ? transactions[0] : undefined);
      return transaction ? { transaction, status: "committed" } : undefined;
    },
    findCells: async function* () {},
    findCellsByLock: async function* (lock: ccc.ScriptLike) {
      for (const cell of cells) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell;
    },
  });
  return client;
}

let nextCell = 1;
const cell = (lock: ccc.Script, capacity: bigint, type?: ccc.Script, outputData: ccc.Hex = "0x", outPoint?: ccc.OutPointLike) =>
  ccc.Cell.from({ outPoint: outPoint ?? { txHash: `0x${(nextCell++).toString(16).padStart(64, "0")}`, index: 0 }, cellOutput: { lock, capacity, type }, outputData });
const amount = (value: bigint) => ccc.hexFrom(ccc.numLeToBytes(value, 16));

const evmWallet = () => ({
  request: async ({ method, params }: { method: string; params?: unknown[] }) => {
    if (method === "eth_requestAccounts") return [evmAddress];
    if (method !== "personal_sign") throw new Error(method);
    const bytes = ccc.bytesFrom(params![0] as string);
    const digest = keccak_256(ccc.bytesConcat(new TextEncoder().encode(`\x19Ethereum Signed Message:\n${bytes.length}`), bytes));
    const raw = secp256k1.sign(digest, evmKey, { prehash: false, format: "recovered" });
    return ccc.hexFrom(ccc.bytesConcat(raw.slice(1), [raw[0] + 27]));
  },
});

/** The account as it really is on chain: an AdminList with one EVM backup, 10,000 CKB and 2,500 of a token. */
async function realChain() {
  const base = await offlineClient([]);
  const backups: RecoveryBackup[] = [{ kind: "evm", address: evmAddress }];
  const adminType = ccc.Script.from({ codeHash: TYPE_ID, hashType: "type", args: ccc.hexFrom(new Uint8Array(32).fill(0x42)) });
  const lock = omnilockScript({ omnilock: KEYWAY_OMNILOCK.testnet, omnilockArgs: omnilockArgsFor(publicKey, adminType.hash()) });
  const listLock = adminListLock({ omnilock: KEYWAY_OMNILOCK.testnet, omnilockArgs: lock.args });
  const { root } = whitelistTree(await Promise.all(backups.map((backup) => backupAuth(base, backup))));
  const created = ccc.Transaction.from({ outputs: [{ lock: listLock, type: adminType, capacity: 165n * CKB }], outputsData: [adminListData(root)] });
  setRecoveryListRecord(created, 0, await recoveryListRecord(base, backups));
  const adminList = ccc.Cell.from({ outPoint: { txHash: created.hash(), index: 0 }, cellOutput: created.outputs[0], outputData: created.outputsData[0] });
  const xudt = await base.getKnownScript(ccc.KnownScript.XUdt);
  const token = ccc.Script.from({ codeHash: xudt.codeHash, hashType: xudt.hashType, args: `0x${"77".repeat(32)}` });
  const funding = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: `0x${"0f".repeat(32)}`, index: 0 } }],
    outputs: [{ lock, capacity: 10_000n * CKB }, { lock, capacity: 176n * CKB, type: token }],
    outputsData: ["0x", amount(2_500n)],
  });
  const [plain, tokenCell] = funding.outputs.map((cellOutput, index) => ccc.Cell.from({ outPoint: { txHash: funding.hash(), index }, cellOutput, outputData: funding.outputsData[index] }));
  const destination = ccc.Address.fromScript(await secp256k1Lock(base, ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true))), base).toString();
  const address = ccc.Address.fromScript(lock, base).toString();
  return { lock, listLock, address, adminList, created, funding, plain, tokenCell, token, destination };
}

const sumReal = (real: ccc.Cell[], transaction: ccc.Transaction) =>
  transaction.inputs.reduce((sum, input) => sum + real.find((cell) => cell.outPoint.eq(input.previousOutput))!.cellOutput.capacity, 0n);

test("M1 fixed: a node that under-reports a cell's capacity can't make the backup burn the difference as fee", async () => {
  const chain = await realChain();
  const real = [chain.adminList, chain.plain];
  // The node says the 10,000 CKB cell holds 200 CKB. Same out point, same lock, same (empty) data.
  const lying = [chain.adminList, cell(chain.lock, 200n * CKB, undefined, "0x", chain.plain.outPoint)];
  const node = await offlineClient(lying, [chain.created, chain.funding]);

  const account = await openRescueAccount(node, chain.address);
  assert.equal(account.ckb, 10_000n * CKB, "the page reads the cell from the transaction that created it");
  const entry = await connectEvmBackup(account, evmWallet());
  const plan = await planRescue(node, account, entry, chain.destination);
  const signed = await signRescueWithEvm(node, account, plan, evmWallet());

  const realFee = sumReal(real, signed) - signed.getOutputsCapacity();
  assert.equal(realFee, plan.fee);
  assert.ok(realFee < CKB / 1000n, `fee paid to the miner: ${ccc.fixedPointToString(realFee)} CKB`);
  assert.match(plan.approvalText, /\nCKB: 9,999\.\d+\nTokens: none\nFee: 0\.\d+ CKB\n/);
});

test("M1 fixed: a node that under-reports a token cell's amount can't make the rescue burn the token", async () => {
  const chain = await realChain();
  // The node reports the token cell with amount 1 instead of 2,500; the page reads 2,500 from the chain.
  const lying = [chain.adminList, chain.plain, cell(chain.lock, 176n * CKB, chain.token, amount(1n), chain.tokenCell.outPoint)];
  const node = await offlineClient(lying, [chain.created, chain.funding]);
  const account = await openRescueAccount(node, chain.address);
  assert.equal(account.tokens[0].amount, 2_500n);
  const entry = await connectEvmBackup(account, evmWallet());
  const plan = await planRescue(node, account, entry, chain.destination);
  const signed = await signRescueWithEvm(node, account, plan, evmWallet());
  const tokenOutput = signed.outputs.findIndex((output) => output.type?.eq(chain.token));
  assert.equal(ccc.numLeFromBytes(ccc.bytesFrom(signed.outputsData[tokenOutput]).slice(0, 16)), 2_500n, "every token moves");

  // A node that answers the out point's hash with a different transaction is refused.
  const forged = chain.funding.clone();
  forged.outputsData[1] = amount(1n);
  const swapped = await offlineClient(lying, [chain.created]);
  Object.assign(swapped, { getTransaction: async (hash: ccc.HexLike) => ({ transaction: ccc.hexFrom(hash) === chain.created.hash() ? chain.created : forged, status: "committed" }) });
  await assert.rejects(openRescueAccount(swapped, chain.address), /returned a transaction that doesn't match/);
});

test("M1 fixed: a node that reports the AdminList's out point as a plain cell can't make the rescue destroy the list", async () => {
  const chain = await realChain();
  // findSingletonCellByType answers with a decoy out point; findCellsByLock lists the real AdminList's out point
  // as plain CKB at the account. The page takes the list from under its owner-only lock, and the chain says the
  // listed "plain" cell isn't the account's, so it is never an input.
  const decoy = ccc.Cell.from({ outPoint: { txHash: `0x${"dd".repeat(32)}`, index: 0 }, cellOutput: chain.adminList.cellOutput, outputData: chain.adminList.outputData });
  const lying = [chain.adminList, chain.plain, cell(chain.lock, 165n * CKB, undefined, "0x", chain.adminList.outPoint)];
  const node = await offlineClient(lying, [chain.created, chain.funding], decoy);
  const account = await openRescueAccount(node, chain.address);
  assert.ok(account.adminList.outPoint.eq(chain.adminList.outPoint));
  assert.ok(!account.movable.some((movable) => movable.outPoint.eq(chain.adminList.outPoint)));
  const entry = await connectEvmBackup(account, evmWallet());
  const plan = await planRescue(node, account, entry, chain.destination);
  const signed = await signRescueWithEvm(node, account, plan, evmWallet());
  assert.ok(!signed.inputs.some((input) => input.previousOutput.eq(chain.adminList.outPoint)), "the AdminList isn't an input");
  assert.ok(signed.cellDeps.some(({ outPoint }) => outPoint.eq(chain.adminList.outPoint)), "it is a cell dep");
  const destination = (await ccc.Address.fromString(chain.destination, node)).script;
  const withList = plan.transaction.clone();
  withList.inputs.push(ccc.CellInput.from({ previousOutput: chain.adminList.outPoint }));
  assert.throws(() => checkRescueTransaction(withList, account, destination), /spends the recovery list|isn't one of the account's movable cells/);
});

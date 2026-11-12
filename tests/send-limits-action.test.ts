// Send limits in the policy Action (lit-actions/sign-ckb-transaction.js), run unchanged under the fake Lit runtime.
// Each test is an attack a compromised KeyWay server (or a leaked usage key) could try; see
// research/send-limits/README.md.
import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { chainOnSendLimit, decodeSendLimitSettings, encodeSendLimitSettings, sendLimitInputIndex, setSendLimitRecord, settingsFromDailyAmounts, type SendLimitHead, type SendLimitSettings } from "../src/sdk/browser/send-limits.ts";
import { dailyAllowance } from "../src/server/general-signing.ts";
import { loadLitAction } from "../src/server/lit-actions.ts";
import { litBackupIds, setEmailBinding } from "../src/server/lit-policy.ts";
import { planRecovery } from "../src/server/recovery.ts";
import type { ReadyWallet } from "../src/server/user-wallet.ts";
import { fakeEthers, fakeLit, litCodeIn, type ActionModule } from "./lit-action-fixture.ts";

const CKB = 100_000_000n;
const HOUR = 60 * 60_000;
const EMAIL = "user@example.com";
const FEE = 100_000n;

function key() {
  const privateKey = secp256k1.utils.randomSecretKey();
  const publicKey = ccc.hexFrom(secp256k1.getPublicKey(privateKey, true));
  const pkpId = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(privateKey, false).slice(1)).slice(12));
  const secp = ccc.Script.from({ codeHash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", hashType: "type", args: ccc.hashCkb(publicKey).slice(0, 42) });
  return { privateKey, publicKey, pkpId, secp };
}

const stranger = ccc.Script.from({ codeHash: `0x${"99".repeat(32)}`, hashType: "type", args: "0x" });
const fiberFunding = ccc.Script.from({ codeHash: "0x6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c", hashType: "type", args: `0x${"12".repeat(20)}` });
const typeIdScript = (args: ccc.HexLike) => ccc.Script.from({ codeHash: "0x00000000000000000000000000000000000000000000000000545950455f4944", hashType: "type", args });
const xudt = ccc.Script.from({ codeHash: "0x25c29dc317811a6f6f3985a7a9ebc4838bd388d19d0feeecf0bcd60f6c0975bb", hashType: "type", args: `0x${"ab".repeat(32)}` });
const nft = ccc.Script.from({ codeHash: `0x${"77".repeat(32)}`, hashType: "type", args: "0x01" });
const json = (tx: ccc.Transaction) => JSON.parse(ccc.stringify(tx));
let nonce = 1;
const outside = () => ({ previousOutput: { txHash: `0x${(nonce++).toString(16).padStart(64, "0")}`, index: 0 } });

type Cell = { outPoint: { txHash: ccc.Hex; index: number }; cellOutput: ccc.CellOutput; outputData: ccc.Hex };
const cellOf = (tx: ccc.Transaction, index: number): Cell => ({ outPoint: { txHash: tx.hash(), index }, cellOutput: tx.outputs[index], outputData: tx.outputsData[index] });

/** A fake chain for one key: transactions are committed or pending, committed ones optionally at a block time. */
async function account(options: { indexerLag?: (url: string) => number; tipAge?: (url: string) => number } = {}) {
  const k = key();
  const known = new Map<string, { tx: ccc.Transaction; status: string; blockHash?: string }>();
  const headers = new Map<string, number>();
  const lit = fakeLit({ privateKey: k.privateKey, pkpId: k.pkpId, lookup: (hash) => known.get(hash), transactions: () => [...known.values()].map(({ tx }) => tx), header: (hash) => headers.get(hash), indexerLag: options.indexerLag, tipAge: options.tipAge });
  const add = (tx: ccc.Transaction, status = "committed", time?: number) => {
    let blockHash: string | undefined;
    if (time !== undefined) { blockHash = ccc.hashCkb(ccc.numLeToBytes(time, 8)); headers.set(blockHash, time); }
    known.set(tx.hash(), { tx, status, blockHash });
    return tx;
  };
  const funding = add(ccc.Transaction.from({
    inputs: [outside()],
    outputs: [{ lock: k.secp, capacity: 1_000n * CKB }, { lock: k.secp, capacity: 300n * CKB }, { lock: k.secp, capacity: 500n * CKB }, { lock: k.secp, capacity: 400n * CKB }],
    outputsData: ["0x", "0x", "0x", "0x"],
  }));
  const action = await lit.load();
  const run = (mode: string, tx: ccc.Transaction, extra: Record<string, unknown> = {}) => action.main({ mode, pkpId: k.pkpId, publicKey: k.publicKey, transaction: json(tx), ...extra });
  return { ...k, ...lit, action, known, add, funding, run };
}
type Account = Awaited<ReturnType<typeof account>>;

/** Zero placeholders for the secp256k1 group's first witness, keeping any record already there. */
function prepare(env: Account, tx: ccc.Transaction, inputLocks: ccc.Script[]) {
  const first = inputLocks.findIndex((lock) => lock.eq(env.secp));
  const witness = tx.getWitnessArgsAt(first) ?? ccc.WitnessArgs.from({});
  witness.lock = ccc.hexFrom(new Uint8Array(65));
  tx.setWitnessArgsAt(first, witness);
}

type Plan = { needsCode: boolean; limits: string; record?: ccc.Hex; outflow: { ckb: string }; totals?: Record<string, string> };

async function codeFor(env: Account, tx: ccc.Transaction, email = EMAIL) {
  const sent = await env.run("send-code", tx, { email, emailApiKey: "re_test_sending_key", appName: "Demo" }) as { ticket: string; fingerprint?: ccc.Hex };
  return { sent, emailCode: { code: litCodeIn(env.emails[env.emails.length - 1]), ticket: sent.ticket } };
}

/** Turns limits on: a genesis from the given cell (the oldest plain one by default), signed with the code. */
async function turnOn(env: Account, settings: Partial<SendLimitSettings> = {}, from: Cell = cellOf(env.funding, 0)) {
  const full: SendLimitSettings = { fingerprint: ccc.hexFrom(new Uint8Array(32)), tokensUnlimited: false, tokens: new Map(), ...settings };
  const data = encodeSendLimitSettings(full);
  const capacity = BigInt(173 + (ccc.bytesFrom(data).length - 47)) * CKB + CKB;
  const input = ccc.CellInput.from({ previousOutput: from.outPoint });
  const tx = ccc.Transaction.from({
    inputs: [input],
    outputs: [{ lock: env.secp, type: typeIdScript(ccc.hashTypeId(input, 0)), capacity }, { lock: env.secp, capacity: from.cellOutput.capacity - capacity - FEE }],
    outputsData: [data, "0x"],
  });
  prepare(env, tx, [env.secp]);
  const { sent, emailCode } = await codeFor(env, tx);
  tx.outputsData[0] = encodeSendLimitSettings({ ...full, fingerprint: sent.fingerprint! });
  await env.run("transaction", tx, { email: EMAIL, emailCode });
  env.add(tx);
  return { genesis: tx, head: cellOf(tx, 0), change: cellOf(tx, 1) };
}

/** A send of `amount` CKB to a stranger from `from`, chained on `head` (unless null), with change back. */
function sendTx(env: Account, head: Cell | null, from: Cell[], amount: bigint, to = stranger) {
  const total = from.reduce((sum, cell) => sum + cell.cellOutput.capacity, 0n);
  const tx = ccc.Transaction.from({
    inputs: from.map((cell) => ({ previousOutput: cell.outPoint })),
    outputs: [{ lock: to, capacity: amount }, { lock: env.secp, capacity: total - amount - FEE }],
    outputsData: ["0x", "0x"],
  });
  if (head) chainOnSendLimit(tx, { ...head, recordEntriesBytes: 0 } as SendLimitHead);
  prepare(env, tx, [...from.map((cell) => cell.cellOutput.lock), ...(head ? [env.secp] : [])]);
  return tx;
}

/** Plans the send as the server does, puts the record in, and returns the plan. */
async function planned(env: Account, tx: ccc.Transaction, head: Cell | null): Promise<Plan> {
  const plan = await env.run("plan", tx) as Plan;
  if (head && plan.record) setSendLimitRecord(tx, sendLimitInputIndex(tx, head), plan.record);
  return plan;
}

const headAfter = (tx: ccc.Transaction) => cellOf(tx, tx.outputs.length - 1);
const changeOf = (tx: ccc.Transaction) => cellOf(tx, 1);

test("turning limits on binds only a fingerprint of the email, needs the code, spends the oldest plain cell and happens once", async () => {
  const env = await account();
  // Not the oldest plain cell: two geneses could then spend different cells.
  await assert.rejects(turnOn(env, { ckb: 100n * CKB }, cellOf(env.funding, 1)), /oldest plain cell/);
  const { genesis } = await turnOn(env, { ckb: 100n * CKB });
  const data = ccc.bytesFrom(genesis.outputsData[0]);
  assert.equal(data.length, 47);
  assert.equal(ccc.hexFrom(data.slice(5, 37)), ccc.hexFrom(await env.action.emailFingerprint(env.pkpId, EMAIL)));
  assert.ok(!Buffer.from(data).toString("latin1").includes("example"), "the address never goes on chain");
  assert.equal(decodeSendLimitSettings(genesis.outputsData[0]).ckb, 100n * CKB);
  // Once on, never a second chain, whichever cell it starts from.
  await assert.rejects(turnOn(env, { ckb: 1_000_000n * CKB }, cellOf(env.funding, 1)), /already on/);
  await assert.rejects(turnOn(env, { ckb: 1_000_000n * CKB }, cellOf(genesis, 1)), /already on/);
});

test("a genesis needs the code and an address matching its fingerprint", async () => {
  const env = await account();
  const input = ccc.CellInput.from({ previousOutput: cellOf(env.funding, 0).outPoint });
  const settings = { fingerprint: ccc.hexFrom(await env.action.emailFingerprint(env.pkpId, "attacker@example.com")), tokensUnlimited: false, ckb: 1n, tokens: new Map() };
  const tx = ccc.Transaction.from({
    inputs: [input],
    outputs: [{ lock: env.secp, type: typeIdScript(ccc.hashTypeId(input, 0)), capacity: 174n * CKB }, { lock: env.secp, capacity: 826n * CKB - FEE }],
    outputsData: [encodeSendLimitSettings(settings), "0x"],
  });
  prepare(env, tx, [env.secp]);
  await assert.rejects(env.run("transaction", tx), /eight-digit code/);
  // The user's code, but the cell names the attacker's address.
  const { emailCode } = await codeFor(env, tx);
  await assert.rejects(env.run("transaction", tx, { email: EMAIL, emailCode }), /isn't the email address bound/);
});

test("a send under the daily amount signs without a code; reaching it needs the code Lit emails to the bound address", async () => {
  const env = await account();
  const { head, change } = await turnOn(env, { ckb: 100n * CKB });
  const first = sendTx(env, head, [change], 50n * CKB);
  const plan1 = await planned(env, first, head);
  assert.equal(plan1.needsCode, false);
  assert.equal(plan1.limits, "chained");
  const signed = await env.run("transaction", first) as { limits: string; signatures: unknown[] };
  assert.equal(signed.limits, "chained");
  env.add(first, "pending");

  // Built on the first send's pending outputs, within seconds.
  const second = sendTx(env, headAfter(first), [changeOf(first)], 50n * CKB);
  const plan2 = await planned(env, second, headAfter(first));
  assert.equal(plan2.needsCode, true);
  assert.equal(plan2.totals?.ckb, (50n * CKB + FEE).toString());
  await assert.rejects(env.run("transaction", second), /eight-digit code/);
  // The server can't send the code anywhere else.
  await assert.rejects(codeFor(env, second, "attacker@example.com"), /isn't the email address bound/);
  const { emailCode } = await codeFor(env, second);
  assert.match(env.emails[env.emails.length - 1].text, /Already sent in the last 24 hours: 50.001 CKB/);
  await assert.rejects(env.run("transaction", second, { email: "attacker@example.com", emailCode }), /isn't the email address bound/);
  await env.run("transaction", second, { email: EMAIL, emailCode });
});

test("parallel requests all spend the one send-limit cell, so at most one of them can commit", async () => {
  const env = await account();
  const { head, change } = await turnOn(env, { ckb: 100n * CKB });
  // Each alone is under the amount, from different cells, all asked for at once.
  const sources = [change, cellOf(env.funding, 1), cellOf(env.funding, 2), cellOf(env.funding, 3)];
  const sends = sources.map((cell) => sendTx(env, head, [cell], 60n * CKB));
  for (const tx of sends) await planned(env, tx, head);
  await Promise.all(sends.map((tx) => env.run("transaction", tx)));
  const spends = sends.map((tx) => tx.inputs.filter((input) => input.previousOutput.eq(ccc.OutPoint.from(head.outPoint))).length);
  assert.deepEqual(spends, [1, 1, 1, 1], "every one spends the same cell, so the chain accepts only one");
  // Whichever commits, the next send descends from it and counts it.
  env.add(sends[2], "pending");
  const next = sendTx(env, headAfter(sends[2]), [changeOf(sends[2])], 60n * CKB);
  assert.equal((await planned(env, next, headAfter(sends[2]))).needsCode, true);
});

test("splitting the balance doesn't help: self-transfers are exempt, and a send that leaves the cell out needs the code", async () => {
  const env = await account();
  const { change } = await turnOn(env, { ckb: 100n * CKB });
  const split = ccc.Transaction.from({
    inputs: [{ previousOutput: change.outPoint }],
    outputs: Array.from({ length: 4 }, () => ({ lock: env.secp, capacity: 150n * CKB })),
    outputsData: ["0x", "0x", "0x", "0x"],
  });
  split.outputs.push(ccc.CellOutput.from({ lock: env.secp, capacity: change.cellOutput.capacity - 600n * CKB - FEE }));
  split.outputsData.push("0x");
  prepare(env, split, [env.secp]);
  assert.equal((await env.run("transaction", split) as { limits: string }).limits, "exempt");
  env.add(split);
  for (let i = 0; i < 4; i++) {
    const unchained = sendTx(env, null, [cellOf(split, i)], 90n * CKB);
    const plan = await planned(env, unchained, null);
    assert.equal(plan.limits, "unchained");
    assert.equal(plan.needsCode, true);
    await assert.rejects(env.run("transaction", unchained), /eight-digit code/);
  }
  // A fee above the exempt amount is a send like any other.
  const burn = ccc.Transaction.from({ inputs: [{ previousOutput: cellOf(split, 0).outPoint }], outputs: [{ lock: env.secp, capacity: 149n * CKB }], outputsData: ["0x"] });
  prepare(env, burn, [env.secp]);
  await assert.rejects(env.run("transaction", burn), /eight-digit code/);
});

test("a record that hides a recent send, changes one, or misstates this transaction is refused", async () => {
  const env = await account();
  const { head, change } = await turnOn(env, { ckb: 100n * CKB });
  const first = sendTx(env, head, [change], 50n * CKB);
  await planned(env, first, head);
  await env.run("transaction", first);
  env.add(first, "pending");
  const second = sendTx(env, headAfter(first), [changeOf(first)], 40n * CKB);
  const index = sendLimitInputIndex(second, headAfter(first));
  // Copies: CCC's bytes can be a Buffer, whose slice() shares memory.
  const record = Uint8Array.from(ccc.bytesFrom((await planned(env, second, headAfter(first))).record!));
  // Header, then the first send's entry (49 bytes), then this one's.
  assert.equal(record[5], 2);
  const withRecord = (bytes: Uint8Array) => { setSendLimitRecord(second, index, bytes); return env.run("transaction", second, { email: EMAIL }); };
  const hidden = ccc.bytesConcat(record.slice(0, 5), [1], record.slice(6 + 49));
  await assert.rejects(withRecord(hidden), /leaves out a recent send/);
  const lowered = Uint8Array.from(record); lowered[6 + 40] = 0; lowered[6 + 41] = 0; lowered[6 + 42] = 0; lowered[6 + 43] = 0;
  await assert.rejects(withRecord(lowered), /changes an earlier send/);
  const backdated = Uint8Array.from(record); backdated.set(ccc.numLeToBytes(Date.now() - 30 * HOUR, 8), 6 + 32);
  await assert.rejects(withRecord(backdated), /changes an earlier send|out of range/);
  const understated = Uint8Array.from(record); understated[6 + 49 + 43] = 0;
  await assert.rejects(withRecord(understated), /doesn't match this transaction/);
  // A record on another witness, where the account's signature over the send-limit input wouldn't cover it.
  setSendLimitRecord(second, index, record);
  const moved = second.clone();
  moved.witnesses.push(moved.witnesses[index]);
  await assert.rejects(env.run("transaction", moved), /only allowed on the send-limit input/);
  // Without a record at all.
  setSendLimitRecord(second, index, new Uint8Array(record.length));
  await assert.rejects(env.run("transaction", second), /carries no record/);
  setSendLimitRecord(second, index, record);
  assert.equal((await env.run("transaction", second) as { limits: string }).limits, "chained");
});

test("a send-limit cell someone else made can't stand in for the account's own", async () => {
  const env = await account();
  const { change } = await turnOn(env, { ckb: 100n * CKB });
  // Anyone can make a Type ID cell at the account's address with any settings.
  const theirs = env.add(ccc.Transaction.from({ inputs: [outside()], outputs: [{ lock: stranger, capacity: 500n * CKB }], outputsData: ["0x"] }));
  const input = ccc.CellInput.from({ previousOutput: cellOf(theirs, 0).outPoint });
  const forged = env.add(ccc.Transaction.from({
    inputs: [input],
    outputs: [{ lock: env.secp, type: typeIdScript(ccc.hashTypeId(input, 0)), capacity: 174n * CKB }],
    outputsData: [encodeSendLimitSettings({ fingerprint: ccc.hexFrom(new Uint8Array(32)), tokensUnlimited: true, tokens: new Map() })],
  }));
  // Chaining on it treats it as the ordinary cell it is, so its successor is a new send-limit cell, which is refused.
  const send = sendTx(env, cellOf(forged, 0), [change], 500n * CKB);
  await assert.rejects(env.run("plan", send), /new send-limit cell/);
  await assert.rejects(env.run("transaction", send), /new send-limit cell/);
  // The forged cell doesn't hide the real one, and doesn't count as limits on an account without any.
  const unchained = sendTx(env, null, [cellOf(env.funding, 1)], 90n * CKB);
  assert.equal((await planned(env, unchained, null)).limits, "unchained");
  const fresh = await account();
  fresh.add(ccc.Transaction.from({ inputs: [outside()], outputs: [{ lock: fresh.secp, type: typeIdScript(`0x${"42".repeat(32)}`), capacity: 174n * CKB }], outputsData: [encodeSendLimitSettings({ fingerprint: ccc.hexFrom(new Uint8Array(32)), tokensUnlimited: false, ckb: 1n, tokens: new Map() })] }));
  const legacy = sendTx(fresh, null, [cellOf(fresh.funding, 0)], 900n * CKB);
  assert.equal((await planned(fresh, legacy, null)).limits, "legacy");
});

test("a Fiber channel funding can't bypass the limit: it needs the code once limits are on", async () => {
  const env = await account();
  const funding = sendTx(env, null, [cellOf(env.funding, 1)], 100n * CKB, fiberFunding);
  // No limits yet: as today.
  assert.equal((await planned(env, funding, null)).limits, "legacy");
  await env.run("transaction", funding);
  await turnOn(env, { ckb: 1_000n * CKB });
  const plan = await planned(env, funding, null);
  assert.equal(plan.limits, "unchained");
  assert.equal(plan.needsCode, true, "even under the amount: Fiber picks the inputs, so it can't chain");
  await assert.rejects(env.run("transaction", funding), /eight-digit code/);
  const { emailCode } = await codeFor(env, funding);
  assert.match(env.emails[env.emails.length - 1].text, /opening a Fiber channel/);
  await env.run("transaction", funding, { email: EMAIL, emailCode });
});

test("the amount can't be raised and the email can't change without the code; lowering applies at once", async () => {
  const env = await account();
  const { head } = await turnOn(env, { ckb: 100n * CKB });
  const change = (settings: Partial<SendLimitSettings>, destroy = false) => {
    const before = decodeSendLimitSettings(head.outputData);
    const tx = ccc.Transaction.from({
      inputs: [ccc.CellInput.from({ previousOutput: head.outPoint })],
      outputs: destroy ? [{ lock: env.secp, capacity: head.cellOutput.capacity - FEE }] : [{ ...head.cellOutput, capacity: head.cellOutput.capacity - FEE }],
      outputsData: [destroy ? "0x" : encodeSendLimitSettings({ ...before, ...settings })],
    });
    setSendLimitRecord(tx, 0, new Uint8Array(0));
    prepare(env, tx, [env.secp]);
    return tx;
  };
  const raise = change({ ckb: 10_000n * CKB });
  const plan = await planned(env, raise, head);
  assert.equal(plan.needsCode, true);
  await assert.rejects(env.run("transaction", raise), /eight-digit code/);
  const { emailCode } = await codeFor(env, raise);
  assert.match(env.emails[env.emails.length - 1].text, /Change your daily send limits[\s\S]*New daily amount: 10000 CKB a day/);
  await env.run("transaction", raise, { email: EMAIL, emailCode });
  for (const weaker of [{ ckb: undefined }, { tokensUnlimited: true }]) {
    const tx = change(weaker);
    assert.equal((await planned(env, tx, head)).needsCode, true, JSON.stringify(Object.keys(weaker)));
  }
  const lower = change({ ckb: 10n * CKB });
  assert.equal((await planned(env, lower, head)).needsCode, false);
  await env.run("transaction", lower);
  const other = change({ fingerprint: ccc.hexFrom(await env.action.emailFingerprint(env.pkpId, "attacker@example.com")) });
  await assert.rejects(env.run("plan", other), /email bound to send limits can't change/);
  const destroyed = change({}, true);
  await assert.rejects(env.run("plan", destroyed), /can't be destroyed/);
});

test("sends older than 24 hours leave the window, judged by their block's time, which the record can't fake", async () => {
  const env = await account();
  const { head, change } = await turnOn(env, { ckb: 100n * CKB });
  const first = sendTx(env, head, [change], 90n * CKB);
  await planned(env, first, head);
  await env.run("transaction", first);

  const next = async (time: number) => {
    env.add(first, "committed", time);
    const tx = sendTx(env, headAfter(first), [changeOf(first)], 90n * CKB);
    return { tx, plan: await planned(env, tx, headAfter(first)) };
  };
  const recent = await next(Date.now() - HOUR);
  assert.equal(recent.plan.needsCode, true);
  const old = await next(Date.now() - 25 * HOUR);
  assert.equal(old.plan.needsCode, false);
  assert.equal(old.plan.totals?.ckb, "0");
  await env.run("transaction", old.tx);

  // The record fills in the committed time once; claiming an older one than the block's is refused.
  const again = await next(Date.now() - HOUR);
  const record = Uint8Array.from(ccc.bytesFrom(again.plan.record!));
  assert.equal(ccc.numLeFromBytes(record.slice(6 + 32, 6 + 40)) > 0n, true, "the plan filled in the block time");
  const faked = Uint8Array.from(record); faked.set(ccc.numLeToBytes(Date.now() - 25 * HOUR, 8), 6 + 32);
  setSendLimitRecord(again.tx, sendLimitInputIndex(again.tx, headAfter(first)), faked);
  await assert.rejects(env.run("transaction", again.tx), /changes an earlier send/);
});

test("on a cell with tokens not unlimited (written before they became the default), a token without its own limit always needs the code", async () => {
  const env = await account();
  const asset = xudt.hash();
  const tokens = env.add(ccc.Transaction.from({
    inputs: [outside()],
    outputs: [{ lock: env.secp, type: xudt, capacity: 200n * CKB }, { lock: env.secp, type: nft, capacity: 200n * CKB }],
    outputsData: [ccc.hexFrom(ccc.numLeToBytes(1_000n, 16)), "0x01"],
  }));
  const { head, change } = await turnOn(env, { ckb: 1_000n * CKB, tokens: new Map([[asset, 500n]]) });
  const tokenSend = (from: Cell, amount: bigint, chainHead: Cell) => {
    const left = ccc.numLeFromBytes(ccc.bytesFrom(from.outputData).slice(0, 16)) - amount;
    const tx = ccc.Transaction.from({
      inputs: [{ previousOutput: from.outPoint }, { previousOutput: change.outPoint }],
      outputs: [{ lock: stranger, type: xudt, capacity: 150n * CKB }, { lock: env.secp, type: xudt, capacity: 150n * CKB }, { lock: env.secp, capacity: from.cellOutput.capacity + change.cellOutput.capacity - 300n * CKB - FEE }],
      outputsData: [ccc.hexFrom(ccc.numLeToBytes(amount, 16)), ccc.hexFrom(ccc.numLeToBytes(left, 16)), "0x"],
    });
    chainOnSendLimit(tx, { ...chainHead, recordEntriesBytes: 0 } as SendLimitHead);
    prepare(env, tx, [env.secp]);
    return tx;
  };
  const first = tokenSend(cellOf(tokens, 0), 400n, head);
  assert.equal((await planned(env, first, head)).needsCode, false);
  await env.run("transaction", first);
  env.add(first, "pending");
  const second = ccc.Transaction.from({
    inputs: [{ previousOutput: cellOf(first, 1).outPoint }, { previousOutput: cellOf(first, 2).outPoint }],
    outputs: [{ lock: stranger, type: xudt, capacity: 150n * CKB }, { lock: env.secp, capacity: cellOf(first, 2).cellOutput.capacity - FEE }],
    outputsData: [ccc.hexFrom(ccc.numLeToBytes(600n, 16)), "0x"],
  });
  chainOnSendLimit(second, { ...headAfter(first), recordEntriesBytes: 0 } as SendLimitHead);
  prepare(env, second, [env.secp]);
  const plan = await planned(env, second, headAfter(first));
  assert.equal(plan.needsCode, true, "400 + 600 tokens reach the 500 limit");
  assert.equal(plan.totals?.[asset], "400");

  // An NFT (any type without an amount of its own) needs the code for every transfer.
  const nftSend = ccc.Transaction.from({
    inputs: [{ previousOutput: cellOf(tokens, 1).outPoint }],
    outputs: [{ lock: stranger, type: nft, capacity: 200n * CKB - FEE }],
    outputsData: ["0x01"],
  });
  chainOnSendLimit(nftSend, { ...headAfter(first), recordEntriesBytes: 0 } as SendLimitHead);
  prepare(env, nftSend, [env.secp]);
  assert.equal((await planned(env, nftSend, headAfter(first))).needsCode, true);
});

test("with the settings KeyWay writes, a token or NFT without its own amount has no limit, in the Action and on the server alike", async () => {
  const env = await account();
  const limited = ccc.Script.from({ ...xudt, args: `0x${"cd".repeat(32)}` });
  const tokens = env.add(ccc.Transaction.from({
    inputs: [outside()],
    outputs: [{ lock: env.secp, type: xudt, capacity: 200n * CKB }, { lock: env.secp, type: nft, capacity: 200n * CKB }, { lock: env.secp, type: limited, capacity: 200n * CKB }],
    outputsData: [ccc.hexFrom(ccc.numLeToBytes(1_000n, 16)), "0x01", ccc.hexFrom(ccc.numLeToBytes(1_000n, 16))],
  }));
  // The daily amounts the server keeps, and the cell it writes for them.
  const amounts = new Map([["ckb", 1_000n * CKB], [limited.hash(), 500n]]);
  const settings = settingsFromDailyAmounts(amounts, new Uint8Array(32));
  assert.equal(settings.tokensUnlimited, true);
  const { head, change } = await turnOn(env, settings);
  assert.equal(decodeSendLimitSettings(head.outputData).tokensUnlimited, true);
  // Each send moves one cell (all of a token's balance, or the NFT) to a stranger, chained on the cell.
  const send = (cell: Cell, type: ccc.Script) => {
    const tx = ccc.Transaction.from({
      inputs: [{ previousOutput: cell.outPoint }, { previousOutput: change.outPoint }],
      outputs: [{ lock: stranger, type, capacity: cell.cellOutput.capacity }, { lock: env.secp, capacity: change.cellOutput.capacity - FEE }],
      outputsData: [cell.outputData, "0x"],
    });
    chainOnSendLimit(tx, { ...head, recordEntriesBytes: 0 } as SendLimitHead);
    prepare(env, tx, [env.secp]);
    return tx;
  };
  for (const [name, index, type, needsCode] of [["a token without its own amount", 0, xudt, false], ["an NFT", 1, nft, false], ["a token past its own amount", 2, limited, true]] as const) {
    const tx = send(cellOf(tokens, index), type);
    const plan = await planned(env, tx, head);
    assert.equal(plan.needsCode, needsCode, `Action: ${name}`);
    // The server's rule for the same asset: no amount of its own means no limit.
    assert.equal(dailyAllowance(amounts, type.hash()) !== "unlimited", needsCode, `server: ${name}`);
    if (!needsCode) await env.run("transaction", tx);
    else await assert.rejects(env.run("transaction", tx), /eight-digit code/);
  }
});

test("a cell written before tokens became unlimited picks it up at its next settings change, which needs the code", async () => {
  const env = await account();
  const { head } = await turnOn(env, { ckb: 100n * CKB, tokensUnlimited: false });
  const before = decodeSendLimitSettings(head.outputData);
  // Lowering the CKB amount, written as the server now writes it: tokens turn unlimited too, which loosens the cell.
  const next = settingsFromDailyAmounts(new Map([["ckb", 10n * CKB]]), before.fingerprint);
  const tx = ccc.Transaction.from({
    inputs: [ccc.CellInput.from({ previousOutput: head.outPoint })],
    outputs: [{ ...head.cellOutput, capacity: head.cellOutput.capacity - FEE }],
    outputsData: [encodeSendLimitSettings(next)],
  });
  setSendLimitRecord(tx, 0, new Uint8Array(0));
  prepare(env, tx, [env.secp]);
  assert.equal((await planned(env, tx, head)).needsCode, true);
  await assert.rejects(env.run("transaction", tx), /eight-digit code/);
  const { emailCode } = await codeFor(env, tx);
  assert.match(env.emails[env.emails.length - 1].text, /Other tokens: no limit/);
  await env.run("transaction", tx, { email: EMAIL, emailCode });
});

test("an account without a send-limit cell signs as before, and accounts without limits never pay for the check twice", async () => {
  const env = await account();
  const tx = sendTx(env, null, [cellOf(env.funding, 0)], 900n * CKB);
  assert.equal((await env.run("transaction", tx) as { limits: string }).limits, "legacy");
  const before = env.requests.length;
  const exempt = ccc.Transaction.from({ inputs: [{ previousOutput: cellOf(env.funding, 1).outPoint }], outputs: [{ lock: env.secp, capacity: 300n * CKB - FEE }], outputsData: ["0x"] });
  prepare(env, exempt, [env.secp]);
  assert.equal((await env.run("transaction", exempt) as { limits: string }).limits, "exempt");
  assert.equal(env.requests.length - before, 1, "an exempt transaction reads only its inputs");
});

test("a record-shaped witness someone adds on their own input after signing can't break the chain", async () => {
  const env = await account();
  const { head, change } = await turnOn(env, { ckb: 1_000n * CKB });
  // Another party's input in the same transaction: its witness isn't covered by the account's signature.
  const theirs = env.add(ccc.Transaction.from({ inputs: [outside()], outputs: [{ lock: stranger, capacity: 100n * CKB }], outputsData: ["0x"] }));
  const send = sendTx(env, head, [change], 70n * CKB);
  send.inputs.unshift(ccc.CellInput.from({ previousOutput: cellOf(theirs, 0).outPoint }));
  send.witnesses.unshift("0x");
  send.outputs.splice(2, 0, ccc.CellOutput.from({ lock: stranger, capacity: 100n * CKB }));
  send.outputsData.splice(2, 0, "0x");
  await planned(env, send, head);
  await env.run("transaction", send);
  const index = sendLimitInputIndex(send, head);
  setSendLimitRecord(send, 0, send.getWitnessArgsAt(index)!.inputType!);
  env.add(send, "pending");
  const next = sendTx(env, headAfter(send), [changeOf(send)], 70n * CKB);
  const plan = await planned(env, next, headAfter(send));
  assert.equal(plan.limits, "chained");
  assert.equal(plan.totals?.ckb, (70n * CKB + FEE).toString());
  await env.run("transaction", next);
});

test("lowering the amount applies at once even when today's total is past the new one", async () => {
  const env = await account();
  const { head, change } = await turnOn(env, { ckb: 100n * CKB });
  const first = sendTx(env, head, [change], 99n * CKB);
  await planned(env, first, head);
  await env.run("transaction", first);
  env.add(first, "pending");
  const cell = headAfter(first);
  const before = decodeSendLimitSettings(cell.outputData);
  const lower = ccc.Transaction.from({
    inputs: [ccc.CellInput.from({ previousOutput: cell.outPoint })],
    outputs: [{ ...cell.cellOutput, capacity: cell.cellOutput.capacity - FEE }],
    outputsData: [encodeSendLimitSettings({ ...before, ckb: 10n * CKB })],
  });
  setSendLimitRecord(lower, 0, new Uint8Array(0));
  prepare(env, lower, [env.secp]);
  assert.equal((await planned(env, lower, cell)).needsCode, false);
  await env.run("transaction", lower);
});

test("CKB moved under a type script the account doesn't control counts as leaving, so it needs the code", async () => {
  const env = await account();
  await turnOn(env, { ckb: 100n * CKB });
  // Whoever wrote this type script decides when a cell under it can be spent again.
  const hostile = ccc.Script.from({ codeHash: `0x${"66".repeat(32)}`, hashType: "type", args: "0x" });
  const locked = ccc.Transaction.from({ inputs: [{ previousOutput: cellOf(env.funding, 2).outPoint }], outputs: [{ lock: env.secp, type: hostile, capacity: 500n * CKB - FEE }], outputsData: ["0x"] });
  prepare(env, locked, [env.secp]);
  const plan = await planned(env, locked, null);
  assert.equal(plan.limits, "unchained");
  assert.equal(plan.needsCode, true);
  await assert.rejects(env.run("transaction", locked), /eight-digit code/);

  // A small cell of the type planted at the address vouches for no more CKB than it holds.
  const planted = env.add(ccc.Transaction.from({ inputs: [outside()], outputs: [{ lock: env.secp, type: hostile, capacity: 100n * CKB }], outputsData: ["0x"] }));
  const topped = ccc.Transaction.from({
    inputs: [{ previousOutput: cellOf(planted, 0).outPoint }, { previousOutput: cellOf(env.funding, 3).outPoint }],
    outputs: [{ lock: env.secp, type: hostile, capacity: 500n * CKB - FEE }],
    outputsData: ["0x"],
  });
  prepare(env, topped, [env.secp]);
  assert.equal((await planned(env, topped, null)).needsCode, true);
  await assert.rejects(env.run("transaction", topped), /eight-digit code/);

  // Moving a cell under its own type, unchanged, and a plain self-transfer stay exempt.
  const moved = ccc.Transaction.from({ inputs: [{ previousOutput: cellOf(planted, 0).outPoint }], outputs: [{ lock: env.secp, type: hostile, capacity: 100n * CKB - FEE }], outputsData: ["0x"] });
  prepare(env, moved, [env.secp]);
  assert.equal((await env.run("transaction", moved) as { limits: string }).limits, "exempt");
  const self = ccc.Transaction.from({ inputs: [{ previousOutput: cellOf(env.funding, 3).outPoint }], outputs: [{ lock: env.secp, capacity: 400n * CKB - FEE }], outputsData: ["0x"] });
  prepare(env, self, [env.secp]);
  assert.equal((await env.run("transaction", self) as { limits: string }).limits, "exempt");
});

test("a token balance of an unlisted type (or xUDT referenced by data hash) can't leave in an 'exempt' transaction", async () => {
  const xudtByData = ccc.Script.from({ codeHash: "0x50bd8d6680b8b9cf98b73f3c08faf8b2a21914311954118ad6609be6e78a1b95", hashType: "data1", args: `0x${"cd".repeat(32)}` });
  const otherUdt = ccc.Script.from({ codeHash: `0x${"5a".repeat(32)}`, hashType: "type", args: `0x${"01".repeat(32)}` });
  for (const token of [xudtByData, otherUdt]) {
    const env = await account();
    const held = env.add(ccc.Transaction.from({ inputs: [outside()], outputs: [{ lock: env.secp, type: token, capacity: 200n * CKB }], outputsData: [ccc.hexFrom(ccc.numLeToBytes(1_000n, 16))] }));
    await turnOn(env, { ckb: 100n * CKB });
    // Someone else pays for the recipient's cell; an empty cell of the token comes back to the account.
    const payer = env.add(ccc.Transaction.from({ inputs: [outside()], outputs: [{ lock: stranger, capacity: 300n * CKB }], outputsData: ["0x"] }));
    const drain = ccc.Transaction.from({
      inputs: [{ previousOutput: cellOf(held, 0).outPoint }, { previousOutput: cellOf(payer, 0).outPoint }],
      outputs: [{ lock: env.secp, type: token, capacity: 200n * CKB }, { lock: stranger, type: token, capacity: 300n * CKB - FEE }],
      outputsData: [ccc.hexFrom(ccc.numLeToBytes(0n, 16)), ccc.hexFrom(ccc.numLeToBytes(1_000n, 16))],
    });
    prepare(env, drain, [env.secp, stranger]);
    const plan = await planned(env, drain, null);
    assert.notEqual(plan.limits, "exempt", token.codeHash);
    assert.equal(plan.needsCode, true, token.codeHash);
    await assert.rejects(env.run("transaction", drain), /eight-digit code/);
  }
});

test("Type ID cells anyone plants at the address don't block the send-limit lookup", async () => {
  const env = await account();
  // More than the 1024 the lookup reads; each locks its CKB at the account's address.
  const planted = env.add(ccc.Transaction.from({
    inputs: [outside()],
    outputs: Array.from({ length: 1100 }, (_, i) => ({ lock: env.secp, type: typeIdScript(ccc.hexFrom(ccc.numLeToBytes(i + 1, 32))), capacity: 125n * CKB })),
    outputsData: Array.from({ length: 1100 }, () => "0x"),
  }));
  const transfer = sendTx(env, null, [cellOf(env.funding, 1)], 90n * CKB);
  assert.equal((await planned(env, transfer, null)).limits, "legacy");
  // Clearing some of them out isn't exempt (they count as tokens), but it plans.
  const cleanup = ccc.Transaction.from({
    inputs: [0, 1, 2].map((i) => ({ previousOutput: cellOf(planted, i).outPoint })),
    outputs: [{ lock: env.secp, capacity: 375n * CKB - FEE }],
    outputsData: ["0x"],
  });
  prepare(env, cleanup, [env.secp]);
  assert.equal((await planned(env, cleanup, null)).limits, "legacy");
  await turnOn(env, { ckb: 100n * CKB });
  assert.equal((await planned(env, transfer, null)).limits, "unchained");
});

test("the code email names where the funds go, so a swapped recipient shows", async () => {
  const env = await account();
  const { head, change } = await turnOn(env, { ckb: 100n * CKB });
  const address = (lock: ccc.Script) => ccc.Address.fromScript(lock, new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" })).toString();
  const x = ccc.Script.from({ codeHash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", hashType: "type", args: `0x${"aa".repeat(20)}` });
  const y = ccc.Script.from({ codeHash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", hashType: "type", args: `0x${"bb".repeat(20)}` });
  const emailFor = async (to: ccc.Script) => {
    const tx = sendTx(env, head, [change], 150n * CKB, to);
    await planned(env, tx, head);
    await codeFor(env, tx);
    return env.emails[env.emails.length - 1].text;
  };
  const toX = await emailFor(x);
  const toY = await emailFor(y);
  assert.ok(toX.includes(`To ${address(x)}: 150 CKB`), toX);
  assert.ok(toY.includes(`To ${address(y)}: 150 CKB`), toY);
  assert.ok(!toY.includes(address(x)));
  const body = (text: string) => text.replace(/Transaction 0x[0-9a-f]+…/, "").replace(/code is \d{8}/, "");
  assert.notEqual(body(toX), body(toY), "the same amount to another address reads differently");

  // A channel funding says so; an unchained send to an ordinary address doesn't read like one.
  const funding = sendTx(env, null, [cellOf(env.funding, 1)], 100n * CKB, fiberFunding);
  await codeFor(env, funding);
  assert.ok(env.emails[env.emails.length - 1].text.includes(`To a Fiber channel (${address(fiberFunding)}): 100 CKB`));
  const unchained = sendTx(env, null, [cellOf(env.funding, 2)], 100n * CKB, x);
  await codeFor(env, unchained);
  const text = env.emails[env.emails.length - 1].text;
  assert.ok(text.includes(`To ${address(x)}: 100 CKB`), text);
  assert.ok(!text.includes("To a Fiber channel"));
});

/** A testnet client that answers from the account's committed transactions and never reaches the network. */
async function offlineClient(env: Account): Promise<ccc.Client> {
  const transactions = [...env.known.values()].filter(({ status }) => status === "committed").map(({ tx }) => tx);
  const spent = new Set(transactions.flatMap((tx) => tx.inputs.map((input) => `${input.previousOutput.txHash}:${Number(input.previousOutput.index)}`)));
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  const cells = transactions.flatMap((tx) => tx.outputs.map((cellOutput, index) => ccc.Cell.from({ outPoint: { txHash: tx.hash(), index }, cellOutput, outputData: tx.outputsData[index] })));
  await client.cache.recordCells(cells);
  const live = cells.filter((cell) => !spent.has(`${cell.outPoint.txHash}:${Number(cell.outPoint.index)}`));
  Object.assign(client, {
    findCells: async function* () {},
    findCellsByLock: async function* (lock: ccc.ScriptLike) { for (const cell of live) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell; },
  });
  return client;
}

/**
 * An account with limits on (100 CKB a day, bound to EMAIL) and recovery off, and the transaction turning recovery
 * on that a compromised server would plan: every plain cell to an address its own backup can spend.
 */
async function limitedEnable(before: (env: Account) => void = () => {}) {
  const env = await account();
  await turnOn(env, { ckb: 100n * CKB });
  before(env);
  const client = await offlineClient(env);
  const wallet = { version: 1, status: "ready", litPkpId: env.pkpId, litPublicKey: env.publicKey, ckbAddress: "ckt1test", encryptedFiberKey: "x", primaryDeviceIdHash: "a".repeat(64), hasOpenedChannel: false, createdAt: "2026-11-10T00:00:00.000Z", updatedAt: "2026-11-10T00:00:00.000Z" } as ReadyWallet;
  const backup = { kind: "evm" as const, address: ccc.hexFrom(keccak_256(Uint8Array.of(0xbb)).slice(12)) };
  const plan = await planRecovery(client, wallet, [backup], { emailBinding: true });
  const backups = await litBackupIds(client, [backup]);
  const binding = async (email: string) => ccc.hexFrom(ccc.bytesConcat("0x4b57454202", await env.action.emailFingerprint(env.pkpId, email)));
  return { env, tx: plan.transaction, backups, binding, moved: plan.transaction.outputs.reduce((sum, output) => sum + output.capacity, 0n) };
}

test("with send limits on, turning recovery on needs the code at the limits' bound address, not one the server names", async () => {
  const attacker = "attacker@example.com";
  const { env, tx, backups, binding, moved } = await limitedEnable();
  assert.ok(moved > 1_000n * CKB, "the enable moves far more than the daily amount");

  // send-code to the server's own address: refused, nothing emailed, no binding handed back.
  const sentBefore = env.emails.length;
  await assert.rejects(env.run("send-code", tx, { email: attacker, emailApiKey: "re_test_sending_key", appName: "Demo", backups }), /bound to this account's send limits/);
  assert.equal(env.emails.length, sentBefore);

  // Transaction mode bound to the server's address, holding a valid code for it: refused for the address.
  const action = new Function("Lit", "ethers", "fetch", `${await loadLitAction("sign-ckb-transaction")}\nreturn { codeFor };`)(env.Lit, fakeEthers, env.fetch) as { codeFor: (pkpId: string, txHash: Uint8Array, email: string, ticket: string) => Promise<string> };
  const forged = tx.clone();
  setEmailBinding(forged, await binding(attacker));
  const { transactionHash } = await env.run("plan", forged, { backups }) as { transactionHash: ccc.Hex };
  const ticket = `v1.${Date.now() + 5 * 60_000}.${"ab".repeat(16)}`;
  const code = await action.codeFor(env.pkpId, ccc.bytesFrom(transactionHash), attacker, ticket);
  await assert.rejects(env.run("transaction", forged, { email: attacker, backups, emailCode: { code, ticket } }), /bound to this account's send limits/);
  // Nor can the bound address sign a binding to another one.
  await assert.rejects(env.run("transaction", forged, { email: EMAIL, backups, emailCode: { code, ticket } }), /bound to this account's recovery/);

  // The bound address works in both modes, and the code goes only there.
  const sent = await env.run("send-code", tx, { email: EMAIL, emailApiKey: "re_test_sending_key", appName: "Demo", backups }) as { ticket: string; binding: ccc.Hex; sentTo: string };
  assert.equal(sent.sentTo, EMAIL);
  assert.deepEqual(env.emails.slice(sentBefore).map((email) => email.to), [[EMAIL]]);
  setEmailBinding(tx, sent.binding);
  const signed = await env.run("transaction", tx, { email: EMAIL, backups, emailCode: { code: litCodeIn(env.emails[env.emails.length - 1]), ticket: sent.ticket } }) as { operation: string; signatures: unknown[] };
  assert.equal(signed.operation, "enable");
  assert.ok(signed.signatures.length > 0);
});

test("turning recovery on is refused while the account shows two send-limit cells", async () => {
  const { env, tx, backups } = await limitedEnable((env) => {
    // A second send-limit cell this key made (spending its own cell), as a conflicting genesis would leave.
    const input = ccc.CellInput.from({ previousOutput: cellOf(env.funding, 3).outPoint });
    const settings: SendLimitSettings = { fingerprint: `0x${"11".repeat(32)}`, tokensUnlimited: false, tokens: new Map(), ckb: 100n * CKB };
    env.add(ccc.Transaction.from({
      inputs: [input],
      outputs: [{ lock: env.secp, type: typeIdScript(ccc.hashTypeId(input, 0)), capacity: 174n * CKB }, { lock: env.secp, capacity: 226n * CKB - FEE }],
      outputsData: [encodeSendLimitSettings(settings), "0x"],
    }));
  });
  const sentBefore = env.emails.length;
  await assert.rejects(env.run("send-code", tx, { email: EMAIL, emailApiKey: "re_test_sending_key", appName: "Demo", backups }), /more than one send-limit cell/);
  assert.equal(env.emails.length, sentBefore);
});

// ---------- run-3 audit: the policy Action's remaining gaps (issue #25) ----------

const dao = ccc.Script.from({ codeHash: "0x82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e", hashType: "type", args: "0x" });

/** A cell under `lock` (and `type`) holding `data`, committed in a transaction of its own. */
function plant(env: Account, output: { lock: ccc.Script; type?: ccc.Script; capacity: bigint }, data: ccc.HexLike = "0x") {
  return cellOf(env.add(ccc.Transaction.from({ inputs: [outside()], outputs: [output], outputsData: [ccc.hexFrom(data)] })), 0);
}

test("M5/M26: 1100 planted look-alike send-limit cells in one block hide neither the account's own cell nor its absence, and one can be cleaned up", async () => {
  const lookalikes = (env: Account) => env.add(ccc.Transaction.from({
    inputs: [outside()],
    outputs: Array.from({ length: 1100 }, (_, i) => ({ lock: env.secp, type: typeIdScript(ccc.hexFrom(ccc.numLeToBytes(i + 1, 32))), capacity: 174n * CKB })),
    outputsData: Array.from({ length: 1100 }, () => encodeSendLimitSettings({ fingerprint: `0x${"11".repeat(32)}`, tokensUnlimited: true, ckb: 1n, tokens: new Map() })),
  }));
  // Without limits: still no limits, and turning them on still works.
  const fresh = await account();
  const planted = lookalikes(fresh);
  assert.equal((await planned(fresh, sendTx(fresh, null, [cellOf(fresh.funding, 1)], 90n * CKB), null)).limits, "legacy");
  await turnOn(fresh, { ckb: 100n * CKB });
  // With limits on: a send that leaves the cell out still finds it, so it needs the code.
  const unchained = sendTx(fresh, null, [cellOf(fresh.funding, 1)], 90n * CKB);
  const plan = await planned(fresh, unchained, null);
  assert.equal(plan.limits, "unchained");
  assert.equal(plan.needsCode, true);
  // A planted look-alike is an ordinary Type ID cell: destroying it, its CKB back at the address, is exempt and signs.
  const cleanup = ccc.Transaction.from({ inputs: [{ previousOutput: cellOf(planted, 0).outPoint }], outputs: [{ lock: fresh.secp, capacity: 174n * CKB - FEE }], outputsData: ["0x"] });
  prepare(fresh, cleanup, [fresh.secp]);
  assert.equal((await fresh.run("plan", cleanup) as Plan).limits, "exempt");
  assert.ok((await fresh.run("transaction", cleanup) as { signatures: unknown[] }).signatures.length > 0);
});

test("M26: one transaction can destroy many well-formed look-alikes within Lit's request limit", async () => {
  const env = await account();
  // Each look-alike has a correct Type ID from its creator's input 0 (an outsider's cell) and minimal "KWSL" data.
  const planted = Array.from({ length: 60 }, () => {
    const source = plant(env, { lock: stranger, capacity: 200n * CKB });
    const input = ccc.CellInput.from({ previousOutput: source.outPoint });
    return cellOf(env.add(ccc.Transaction.from({ inputs: [input], outputs: [{ lock: env.secp, type: typeIdScript(ccc.hashTypeId(input, 0)), capacity: 130n * CKB }], outputsData: ["0x4b57534c"] })), 0);
  });
  const cleanup = ccc.Transaction.from({ inputs: planted.map((cell) => ({ previousOutput: cell.outPoint })), outputs: [{ lock: env.secp, capacity: 60n * 130n * CKB - FEE }], outputsData: ["0x"] });
  prepare(env, cleanup, [env.secp]);
  const before = env.requests.length;
  assert.equal((await env.run("plan", cleanup) as Plan).limits, "exempt");
  // The creators' inputs, their blocks and the key's history there are each read in one batch, not one request per
  // look-alike.
  assert.ok(env.requests.length - before <= 5, `${env.requests.length - before} requests`);
});

test("M27: an indexer behind its chain is never read as 'no send limits'", async () => {
  const lagging = await account({ indexerLag: (url) => (url === "https://testnet.ckb.dev/" ? 10 : 0) });
  await turnOn(lagging, { ckb: 100n * CKB });
  const send = sendTx(lagging, null, [cellOf(lagging.funding, 1)], 90n * CKB);
  // The first node lags, so the second one answers: limits are on.
  assert.equal((await planned(lagging, send, null)).limits, "unchained");
  await assert.rejects(lagging.run("transaction", send), /eight-digit code/);
  // When every node lags, nothing is signed.
  const behind = await account({ indexerLag: () => 10 });
  const blind = sendTx(behind, null, [cellOf(behind.funding, 1)], 90n * CKB);
  await assert.rejects(behind.run("plan", blind), /indexer is behind/);
  await assert.rejects(behind.run("transaction", blind), /indexer is behind/);
});

test("M16: the interest a Nervos DAO withdrawal adds counts as the account's, so sending it away isn't exempt", async () => {
  const env = await account();
  const withdrawing = plant(env, { lock: env.secp, type: dao, capacity: 10_000n * CKB }, ccc.numLeToBytes(1234, 8));
  const plain = cellOf(env.funding, 1);
  const away = ccc.Transaction.from({
    inputs: [{ previousOutput: withdrawing.outPoint }, { previousOutput: plain.outPoint }],
    outputs: [{ lock: env.secp, capacity: 10_300n * CKB - FEE }, { lock: stranger, capacity: 300n * CKB }],
    outputsData: ["0x", "0x"],
  });
  prepare(env, away, [env.secp, env.secp]);
  const plan = await env.run("plan", away) as Plan;
  assert.notEqual(plan.limits, "exempt");
  assert.ok(BigInt(plan.outflow.ckb) >= 300n * CKB, plan.outflow.ckb);
  // Everything back to the account, interest included, is still exempt; so is a withdrawal request (phase 1).
  const home = ccc.Transaction.from({ inputs: [{ previousOutput: withdrawing.outPoint }], outputs: [{ lock: env.secp, capacity: 10_250n * CKB }], outputsData: ["0x"] });
  prepare(env, home, [env.secp]);
  assert.equal((await env.run("plan", home) as Plan).limits, "exempt");
  const deposit = plant(env, { lock: env.secp, type: dao, capacity: 5_000n * CKB }, new Uint8Array(8));
  const request = ccc.Transaction.from({ inputs: [{ previousOutput: deposit.outPoint }], outputs: [{ lock: env.secp, type: dao, capacity: 5_000n * CKB - FEE }], outputsData: [ccc.hexFrom(ccc.numLeToBytes(99, 8))] });
  prepare(env, request, [env.secp]);
  assert.equal((await env.run("plan", request) as Plan).limits, "exempt");
});

test("M17: minting a token the account issued to someone else counts as that token leaving", async () => {
  const env = await account();
  const own = ccc.Script.from({ codeHash: xudt.codeHash, hashType: xudt.hashType, args: env.secp.hash() });
  const theirs = plant(env, { lock: stranger, capacity: 200n * CKB });
  const mint = ccc.Transaction.from({
    inputs: [{ previousOutput: cellOf(env.funding, 1).outPoint }, { previousOutput: theirs.outPoint }],
    outputs: [{ lock: env.secp, capacity: 300n * CKB - FEE }, { lock: stranger, type: own, capacity: 200n * CKB }],
    outputsData: ["0x", ccc.hexFrom(ccc.numLeToBytes(10n ** 30n, 16))],
  });
  prepare(env, mint, [env.secp, stranger]);
  const plan = await env.run("plan", mint) as Plan & { outflow: { tokens: Array<{ asset: string; amount: string }> } };
  assert.notEqual(plan.limits, "exempt");
  assert.deepEqual(plan.outflow.tokens, [{ asset: own.hash(), amount: (10n ** 30n).toString() }]);
  // Minting to the account itself nets out; another issuer's token isn't the account's to count.
  const toSelf = mint.clone();
  toSelf.outputs[1].lock = env.secp;
  assert.equal((await env.run("plan", toSelf) as Plan).limits, "exempt");
  const foreign = mint.clone();
  foreign.outputs[1].type = xudt;
  assert.equal((await env.run("plan", foreign) as Plan).limits, "exempt");
});

test("M18: inputs under a lock this key can unlock in a form KeyWay doesn't use (anyone-can-pay, other Omnilocks) are refused", async () => {
  const env = await account();
  const blake160 = ccc.bytesFrom(env.secp.args);
  const shapes = [
    ccc.Script.from({ codeHash: "0x3419a1c09eb2567f6552ee7a8ecffd64155cffe0f1796e6e61ec088d740c1356", hashType: "type", args: env.secp.args }),
    ccc.Script.from({ codeHash: "0xd369597ff47f29fbc0d47d2e3775370d1250b85140c670e4718af712983a2354", hashType: "type", args: ccc.bytesConcat(blake160, [0x01]) }),
    ccc.Script.from({ codeHash: "0xf329effd1c475a2978453c8600e1eaf0bc2087ee093c3ee64cc96ec6847752cb", hashType: "type", args: ccc.bytesConcat([0x00], blake160, [0x00]) }),
  ];
  for (const lock of shapes) {
    const held = plant(env, { lock, capacity: 50_000n * CKB });
    const drain = ccc.Transaction.from({
      inputs: [{ previousOutput: cellOf(env.funding, 1).outPoint }, { previousOutput: held.outPoint }],
      outputs: [{ lock: env.secp, capacity: 300n * CKB - FEE }, { lock: stranger, capacity: 50_000n * CKB }],
      outputsData: ["0x", "0x"],
    });
    drain.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(65)) }));
    drain.setWitnessArgsAt(1, ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(65)) }));
    await assert.rejects(env.run("plan", drain), /form KeyWay doesn't use/, lock.codeHash);
    await assert.rejects(env.run("transaction", drain), /form KeyWay doesn't use/, lock.codeHash);
  }
});

test("M30: a token counted per cell needs the code whenever it has a daily amount, whatever the amount", async () => {
  const env = await account();
  const unlisted = ccc.Script.from({ codeHash: `0x${"5a".repeat(32)}`, hashType: "type", args: "0x01" });
  const { head, change } = await turnOn(env, { ckb: 1_000_000n * CKB, tokensUnlimited: true, tokens: new Map([[unlisted.hash(), 1_000_000n]]) });
  const token = plant(env, { lock: env.secp, type: unlisted, capacity: 200n * CKB }, ccc.numLeToBytes(10n ** 12n, 16));
  const whole = ccc.Transaction.from({
    inputs: [{ previousOutput: token.outPoint }, { previousOutput: change.outPoint }],
    outputs: [{ lock: stranger, type: unlisted, capacity: 200n * CKB }, { lock: env.secp, capacity: change.cellOutput.capacity - FEE }],
    outputsData: [token.outputData, "0x"],
  });
  chainOnSendLimit(whole, { ...head, recordEntriesBytes: 0 } as SendLimitHead);
  prepare(env, whole, [env.secp, env.secp, env.secp]);
  const plan = await planned(env, whole, head);
  assert.equal(plan.limits, "chained");
  assert.equal(plan.needsCode, true);
  await assert.rejects(env.run("transaction", whole), /eight-digit code/);
});

test("review: a record-shaped witness on someone else's input of the genesis doesn't turn the account's own send-limit cell into a look-alike", async () => {
  const env = await account();
  const foreign = plant(env, { lock: stranger, capacity: 200n * CKB });
  const from = cellOf(env.funding, 0);
  const settings: SendLimitSettings = { fingerprint: ccc.hexFrom(new Uint8Array(32)), tokensUnlimited: false, tokens: new Map(), ckb: 100n * CKB };
  const input = ccc.CellInput.from({ previousOutput: from.outPoint });
  const genesis = ccc.Transaction.from({
    inputs: [input, { previousOutput: foreign.outPoint }],
    outputs: [{ lock: env.secp, type: typeIdScript(ccc.hashTypeId(input, 0)), capacity: 200n * CKB }, { lock: env.secp, capacity: from.cellOutput.capacity - 200n * CKB }, { lock: stranger, capacity: foreign.cellOutput.capacity - FEE }],
    outputsData: [encodeSendLimitSettings(settings), "0x", "0x"],
  });
  prepare(env, genesis, [env.secp, stranger]);
  const { sent, emailCode } = await codeFor(env, genesis);
  genesis.outputsData[0] = encodeSendLimitSettings({ ...settings, fingerprint: sent.fingerprint! });
  assert.equal((await env.run("transaction", genesis, { email: EMAIL, emailCode }) as { limits: string }).limits, "genesis");
  // After signing, a record shape on the other party's input (its witness isn't covered by the account's signature).
  genesis.setWitnessArgsAt(1, ccc.WitnessArgs.from({ inputType: "0x4b5753520100" }));
  env.add(genesis);
  const destroy = ccc.Transaction.from({ inputs: [{ previousOutput: cellOf(genesis, 0).outPoint }], outputs: [{ lock: env.secp, capacity: 200n * CKB - FEE }], outputsData: ["0x"] });
  prepare(env, destroy, [env.secp]);
  await assert.rejects(env.run("transaction", destroy), /can't be destroyed/);
  const send = sendTx(env, null, [cellOf(env.funding, 1)], 290n * CKB);
  assert.equal((await planned(env, send, null)).limits, "unchained");
  await assert.rejects(env.run("transaction", send), /eight-digit code/);
});

test("review: a node that strips a chained cell's record can't make it pass for a look-alike", async () => {
  const env = await account();
  const { head, change } = await turnOn(env, { ckb: 100n * CKB });
  const send = sendTx(env, head, [change], 10n * CKB);
  await planned(env, send, head);
  await env.run("transaction", send);
  env.add(send);
  // The node now serves the chained transaction without its record (witnesses aren't in the hash it's checked against).
  const served = env.known.get(send.hash())!.tx;
  served.witnesses = served.witnesses.map(() => ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(65)) }).toBytes()));
  const destroy = ccc.Transaction.from({ inputs: [{ previousOutput: headAfter(send).outPoint }], outputs: [{ lock: env.secp, capacity: headAfter(send).cellOutput.capacity - FEE }], outputsData: ["0x"] });
  prepare(env, destroy, [env.secp]);
  await assert.rejects(env.run("transaction", destroy), /can't be read/);
});

test("review: no input under a lock naming this key in a form KeyWay doesn't use (secp256k1 by data hash, KeyWay's Omnilock as data2) is signed for, whatever its witness", async () => {
  const env = await account();
  const blake160 = ccc.bytesFrom(env.secp.args);
  const shapes = [
    ccc.Script.from({ codeHash: "0x709f3fda12f561cfacf92273c57a98fede188a3f1a59b1f888d113f9cce08649", hashType: "data1", args: env.secp.args }),
    ccc.Script.from({ codeHash: "0x6b29b6f10346b43c540e53806ba88ba0fe3a0c3a29d7448ef555840c8f8318fa", hashType: "data2", args: ccc.bytesConcat([0x00], blake160, [0x00]) }),
  ];
  for (const lock of shapes) {
    // The other input's witness is chosen by whoever builds the transaction and can change after signing, so the
    // refusal can't depend on it: absent, empty, a short lock or a full one.
    for (const otherWitness of [undefined, ccc.hexFrom("0x"), ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(64)) }).toBytes()), ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(65).fill(7)) }).toBytes())]) {
      const held = plant(env, { lock, capacity: 50_000n * CKB });
      const drain = ccc.Transaction.from({
        inputs: [{ previousOutput: cellOf(env.funding, 1).outPoint }, { previousOutput: held.outPoint }],
        outputs: [{ lock: env.secp, capacity: 300n * CKB - FEE }, { lock: stranger, capacity: 50_000n * CKB }],
        outputsData: ["0x", "0x"],
      });
      drain.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(65)) }));
      if (otherWitness !== undefined) drain.witnesses[1] = otherWitness;
      await assert.rejects(env.run("plan", drain), /form KeyWay doesn't use/, `${lock.hashType} ${otherWitness}`);
      await assert.rejects(env.run("transaction", drain), /form KeyWay doesn't use/, `${lock.hashType} ${otherWitness}`);
    }
  }
  // An ordinary input of someone else's (another key) still signs.
  const theirs = plant(env, { lock: ccc.Script.from({ ...env.secp, args: `0x${"cd".repeat(20)}` }), capacity: 100n * CKB });
  const together = ccc.Transaction.from({
    inputs: [{ previousOutput: cellOf(env.funding, 2).outPoint }, { previousOutput: theirs.outPoint }],
    outputs: [{ lock: env.secp, capacity: 500n * CKB - FEE }, { lock: stranger, capacity: 100n * CKB }],
    outputsData: ["0x", "0x"],
  });
  together.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(65)) }));
  together.setWitnessArgsAt(1, ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(65)) }));
  assert.ok((await env.run("transaction", together) as { signatures: unknown[] }).signatures.length > 0);
});

test("review: a token whose owner is the type of one of the account's cells counts as leaving when minted away", async () => {
  const env = await account();
  const issuer = plant(env, { lock: env.secp, type: typeIdScript(`0x${"31".repeat(32)}`), capacity: 150n * CKB });
  const owned = ccc.Script.from({ codeHash: xudt.codeHash, hashType: xudt.hashType, args: ccc.bytesConcat(ccc.bytesFrom(issuer.cellOutput.type!.hash()), ccc.numLeToBytes(0x80000000, 4)) });
  const theirs = plant(env, { lock: stranger, capacity: 200n * CKB });
  const mint = ccc.Transaction.from({
    inputs: [{ previousOutput: issuer.outPoint }, { previousOutput: theirs.outPoint }],
    outputs: [{ lock: env.secp, type: issuer.cellOutput.type, capacity: 150n * CKB - FEE }, { lock: stranger, type: owned, capacity: 200n * CKB }],
    outputsData: ["0x", ccc.hexFrom(ccc.numLeToBytes(10n ** 20n, 16))],
  });
  prepare(env, mint, [env.secp, stranger]);
  const plan = await env.run("plan", mint) as Plan & { outflow: { tokens: Array<{ asset: string; amount: string }> } };
  assert.notEqual(plan.limits, "exempt");
  assert.deepEqual(plan.outflow.tokens, [{ asset: owned.hash(), amount: (10n ** 20n).toString() }]);
});

test("review: a node whose whole chain has stalled isn't believed either", async () => {
  const stalled = await account();
  await turnOn(stalled, { ckb: 100n * CKB });
  const fresh = await account({ tipAge: () => 0 });
  void fresh;
  const behind = await account({ tipAge: () => 20 * 60_000 });
  const send = sendTx(behind, null, [cellOf(behind.funding, 1)], 90n * CKB);
  await assert.rejects(behind.run("plan", send), /chain is behind the network/);
});

test("review: a look-alike in a block padded with 4,100 cells for the key blocks neither sends nor its own cleanup", async () => {
  const env = await account();
  // One outsider transaction: a send-limit-shaped look-alike with a correct Type ID, plus 4,100 small cells at the key.
  const source = plant(env, { lock: stranger, capacity: 300_000n * CKB });
  const input = ccc.CellInput.from({ previousOutput: source.outPoint });
  const padded = env.add(ccc.Transaction.from({
    inputs: [input],
    outputs: [{ lock: env.secp, type: typeIdScript(ccc.hashTypeId(input, 0)), capacity: 130n * CKB }, ...Array.from({ length: 4100 }, () => ({ lock: env.secp, capacity: 61n * CKB }))],
    outputsData: ["0x4b57534c", ...Array.from({ length: 4100 }, () => "0x")],
  }));
  const send = sendTx(env, null, [cellOf(env.funding, 1)], 90n * CKB);
  assert.equal((await planned(env, send, null)).limits, "legacy");
  const cleanup = ccc.Transaction.from({ inputs: [{ previousOutput: cellOf(padded, 0).outPoint }], outputs: [{ lock: env.secp, capacity: 130n * CKB - FEE }], outputsData: ["0x"] });
  prepare(env, cleanup, [env.secp]);
  assert.equal((await env.run("plan", cleanup) as Plan).limits, "exempt");
  assert.ok((await env.run("transaction", cleanup) as { signatures: unknown[] }).signatures.length > 0);
});

// The server's send-limit flows with the policy Action under the fake Lit runtime: turning limits on, sending under
// and over the amount, and a channel funding, through Postgres.
import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1Lock } from "../src/sdk/browser/account-lock.ts";
import { chainOnSendLimit, decodeSendLimitSettings, DEFAULT_DAILY_LIMIT_SHANNONS, isSendLimitCell, type SendLimitHead } from "../src/sdk/browser/send-limits.ts";
import { database } from "../src/server/database.ts";
import { fundingCode, fundingNeedsLitCode, hashText, issueFundingCodeRequest, issueRequest, sendCode, sendFundingCode, sendLimitOffer, signingSettings, transactionSigning, type SigningContext } from "../src/server/general-signing.ts";
import { litSignerOverride } from "../src/server/lit-config.ts";
import { litPolicyRunner } from "../src/server/lit-policy.ts";
import { listPendingTransactions } from "../src/server/pending-transactions.ts";
import { sendLimitHead, sendLimitPlanner, sendLimitRpc } from "../src/server/send-limits.ts";
import { previewGeneralTransaction } from "../src/server/transaction-policy.ts";
import type { ReadyWallet } from "../src/server/user-wallet.ts";
import { fakeLit, litCodeIn } from "./lit-action-fixture.ts";

const enabled = Boolean(process.env.KEYWAY_AUTH_TEST_DATABASE_URL);
const CKB = 100_000_000n;
const EMAIL = "ana@acmepay.example";
process.env.LIT_USAGE_API_KEY ??= "test-usage-key";
process.env.RESEND_API_KEY ??= "re_test_sending_key";

const privateKey = secp256k1.utils.randomSecretKey();
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(privateKey, true));
const pkpId = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(privateKey, false).slice(1)).slice(12));
const stranger = ccc.Script.from({ codeHash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", hashType: "type", args: `0x${"77".repeat(20)}` });
const fiberFunding = ccc.Script.from({ codeHash: "0x6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c", hashType: "type", args: `0x${"12".repeat(20)}` });

/** One chain both the CCC client and the fake Lit runtime read: committed transactions, then pending ones. */
function chain() {
  const known = new Map<string, { tx: ccc.Transaction; status: string }>();
  const add = (tx: ccc.Transaction, status = "committed") => { known.set(tx.hash(), { tx, status }); return tx; };
  const committed = () => [...known.values()].filter(({ status }) => status === "committed").map(({ tx }) => tx);
  const outputOf = (outPoint: ccc.OutPoint) => {
    const tx = known.get(outPoint.txHash)?.tx;
    const index = Number(outPoint.index);
    return tx && index < tx.outputs.length ? ccc.Cell.from({ outPoint, cellOutput: tx.outputs[index], outputData: tx.outputsData[index] }) : undefined;
  };
  const client = () => {
    const fresh = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
    Object.assign(fresh, {
      findSingletonCellByType: async () => undefined,
      getCell: async (outPoint: ccc.OutPointLike) => outputOf(ccc.OutPoint.from(outPoint)),
      getTransaction: async (hash: ccc.HexLike) => {
        const found = known.get(ccc.hexFrom(hash));
        return found ? { transaction: found.tx, status: found.status } : undefined;
      },
      getFeeRate: async () => 1_000n,
      requestor: { request: async (_method: string, [hash]: [string]) => ({ tx_status: { status: known.get(hash)?.status ?? "unknown" } }) },
      // The indexer: committed cells no committed transaction spent, oldest first.
      findCellsOnChain: async function* (key: ccc.ClientIndexerSearchKeyLike) {
        const search = ccc.ClientIndexerSearchKey.from(key);
        const spent = new Set(committed().flatMap((tx) => tx.inputs.map((input) => `${input.previousOutput.txHash}:${input.previousOutput.index}`)));
        for (const tx of committed()) {
          for (let index = 0; index < tx.outputs.length; index++) {
            const output = tx.outputs[index];
            if (spent.has(`${tx.hash()}:${index}`) || !output.lock.eq(search.script)) continue;
            const typeLength = BigInt(output.type ? output.type.toBytes().length : 0);
            const dataLength = BigInt(ccc.bytesFrom(tx.outputsData[index]).length);
            const range = search.filter?.scriptLenRange;
            if (range && (typeLength < range[0] || typeLength >= range[1])) continue;
            const dataRange = search.filter?.outputDataLenRange;
            if (dataRange && (dataLength < dataRange[0] || dataLength >= dataRange[1])) continue;
            if (search.filter?.script && !(output.type && output.type.codeHash === search.filter.script.codeHash && output.type.hashType === search.filter.script.hashType)) continue;
            yield ccc.Cell.from({ outPoint: { txHash: tx.hash(), index }, cellOutput: output, outputData: tx.outputsData[index] });
          }
        }
      },
    });
    return fresh;
  };
  const lit = fakeLit({ privateKey, pkpId, lookup: (hash) => known.get(hash), transactions: committed });
  return { known, add, client, lit };
}

async function setUp() {
  process.env.DATABASE_URL = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;
  const world = chain();
  const secp = await secp256k1Lock(world.client(), publicKey);
  const funding = world.add(ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: `0x${"0f".repeat(32)}`, index: 0 } }],
    outputs: [{ lock: secp, capacity: 2_000n * CKB }, { lock: secp, capacity: 500n * CKB }],
    outputsData: ["0x", "0x"],
  }));
  const action = await world.lit.load();
  litSignerOverride.mode = "policy";
  litPolicyRunner.run = async (_config, params) => action.main(params);
  sendLimitPlanner.run = async (params) => action.main(params);
  sendLimitRpc.fetch = world.lit.fetch;
  const user = { id: crypto.randomUUID() };
  const wallet = { version: 1, status: "ready", litPkpId: pkpId, litPublicKey: publicKey, ckbAddress: "ckt1test", encryptedFiberKey: "x", primaryDeviceIdHash: "a".repeat(64), hasOpenedChannel: false, createdAt: "", updatedAt: "" } as unknown as ReadyWallet;
  const sent: ccc.Transaction[] = [];
  const context: SigningContext = {
    user, wallet, appName: "Acme Pay",
    email: async () => EMAIL,
    sendEmail: async () => { throw new Error("the server sends no code of its own here"); },
    rateLimit: async () => ({ allowed: true, retryAfter: null }),
    recordSigning: async () => undefined,
    preview: (w, input) => previewGeneralTransaction(w, input, world.client()),
    client: world.client(),
    broadcast: async (tx) => { sent.push(tx); world.add(tx, "pending"); return tx.hash(); },
  };
  return { world, secp, funding, action, user, wallet, context, sent };
}

/** The client side of a send: inputs, change and the send-limit cell, as KeyWaySigner prepares them. */
function buildSend(secp: ccc.Script, from: ccc.Cell, amount: bigint, head?: SendLimitHead, to = stranger) {
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: from.outPoint, cellOutput: from.cellOutput, outputData: from.outputData }],
    outputs: [{ lock: to, capacity: amount }, { lock: secp, capacity: from.cellOutput.capacity - amount - 100_000n }],
    outputsData: ["0x", "0x"],
  });
  if (head) chainOnSendLimit(tx, head);
  const witness = tx.getWitnessArgsAt(0) ?? ccc.WitnessArgs.from({});
  witness.lock = ccc.hexFrom(new Uint8Array(65));
  tx.setWitnessArgsAt(0, witness);
  return JSON.parse(ccc.stringify(tx));
}

const codeFrom = (world: ReturnType<typeof chain>) => litCodeIn(world.lit.emails[world.lit.emails.length - 1]);

test("send limits through the server: turning them on, sending under and over the amount, and a channel funding", { skip: !enabled }, async (t) => {
  const { world, secp, funding, user, wallet, context, sent } = await setUp();
  t.after(() => { litSignerOverride.mode = undefined; });

  await t.test("turning limits on builds the genesis, asks for the Lit code and binds only a fingerprint", async () => {
    const asked = await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (150n * CKB).toString() }) as { requiresEmailCode: boolean; codeLength: number; confirmationNonce: string; sentTo: string };
    assert.equal(asked.requiresEmailCode, true);
    assert.equal(asked.codeLength, 8);
    assert.equal(asked.sentTo, EMAIL);
    assert.match(world.lit.emails.at(-1)!.text, /Turn on daily send limits/);
    await assert.rejects(signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (150n * CKB).toString(), confirmationNonce: asked.confirmationNonce, emailCode: "00000000" }), /isn't right/);
    const done = await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (150n * CKB).toString(), confirmationNonce: asked.confirmationNonce, emailCode: codeFrom(world) }) as { dailyAmounts: Record<string, string>; enforcedByLit: boolean };
    assert.deepEqual(done.dailyAmounts, { ckb: (150n * CKB).toString() });
    assert.equal(done.enforcedByLit, true);
    const genesis = sent.at(-1)!;
    assert.ok(isSendLimitCell(genesis.outputs[0], genesis.outputsData[0], secp));
    assert.ok(genesis.inputs[0].previousOutput.eq(ccc.OutPoint.from({ txHash: funding.hash(), index: 0 })), "from the oldest plain cell");
    const settings = decodeSendLimitSettings(genesis.outputsData[0]);
    assert.equal(settings.ckb, 150n * CKB);
    assert.equal(settings.tokensUnlimited, true, "tokens without an amount of their own have no limit");
    assert.notEqual(settings.fingerprint, `0x${"00".repeat(32)}`);
    world.add(genesis, "committed");
  });

  let head: SendLimitHead;
  await t.test("a send under the amount needs no code and carries its record", async () => {
    head = (await sendLimitHead(context.client!, wallet, await listPendingTransactions(user.id, async () => "committed")))!;
    assert.ok(head, "the server finds the new cell");
    const change = world.known.get(head.outPoint.txHash)!.tx;
    const from = ccc.Cell.from({ outPoint: { txHash: change.hash(), index: 1 }, cellOutput: change.outputs[1], outputData: "0x" });
    const transaction = buildSend(secp, from, 70n * CKB, head);
    const preview = await transactionSigning(context, { operation: "preview", transaction }) as { requiresEmailCode: boolean; confirmationNonce: string };
    assert.equal(preview.requiresEmailCode, false);
    const signed = ccc.Transaction.from((await transactionSigning(context, { operation: "sign", transaction, confirmationNonce: preview.confirmationNonce }) as { transaction: ccc.TransactionLike }).transaction);
    const index = signed.inputs.findIndex((input) => input.previousOutput.eq(ccc.OutPoint.from(head.outPoint)));
    assert.match(signed.getWitnessArgsAt(index)!.inputType!, /^0x4b575352/);
    world.add(signed, "pending");
    const listed = await listPendingTransactions(user.id, async (hash) => world.known.get(hash)?.status);
    assert.ok(listed.some(({ transaction }) => transaction.hash() === signed.hash()), "listed for other clients");
    head = (await sendLimitHead(context.client!, wallet, listed))!;
    assert.equal(head.outPoint.txHash, signed.hash(), "the next send chains on the pending one");
  });

  await t.test("the next send, made before the first confirms, reaches the amount and needs the Lit code", async () => {
    const previous = world.known.get(head.outPoint.txHash)!.tx;
    const from = ccc.Cell.from({ outPoint: { txHash: previous.hash(), index: 1 }, cellOutput: previous.outputs[1], outputData: "0x" });
    const transaction = buildSend(secp, from, 90n * CKB, head);
    const preview = await transactionSigning(context, { operation: "preview", transaction }) as { requiresEmailCode: boolean; confirmationNonce: string };
    assert.equal(preview.requiresEmailCode, true);
    const asked = await transactionSigning(context, { operation: "request-email-code", transaction, confirmationNonce: preview.confirmationNonce }) as { codeLength: number; sentTo: string };
    assert.equal(asked.codeLength, 8);
    assert.match(world.lit.emails.at(-1)!.text, /Already sent in the last 24 hours: 70\.001 CKB/);
    await assert.rejects(transactionSigning(context, { operation: "sign", transaction, confirmationNonce: preview.confirmationNonce, emailCode: "12345678" }), /isn't right/);
    const signed = await transactionSigning(context, { operation: "sign", transaction, confirmationNonce: preview.confirmationNonce, emailCode: codeFrom(world) }) as { transaction: unknown };
    assert.ok(signed.transaction);
  });

  await t.test("a channel funding needs the Lit code once limits are on", async () => {
    const from = ccc.Cell.from({ outPoint: { txHash: funding.hash(), index: 1 }, cellOutput: funding.outputs[1], outputData: "0x" });
    const transaction = ccc.Transaction.from(buildSend(secp, from, 100n * CKB, undefined, fiberFunding));
    assert.equal(await fundingNeedsLitCode(wallet, transaction), true);
    const serialized = JSON.stringify(JSON.parse(ccc.stringify(transaction)));
    const nonce = await issueFundingCodeRequest(user as never, serialized);
    const asked = await sendFundingCode(context, nonce, serialized, transaction) as { codeLength: number };
    assert.equal(asked.codeLength, 8);
    assert.match(world.lit.emails.at(-1)!.text, /opening a Fiber channel/);
    const coded = await fundingCode(context, nonce, serialized, codeFrom(world));
    assert.ok(coded);
    assert.equal(await fundingCode(context, crypto.randomUUID(), serialized, codeFrom(world)), undefined, "an ordinary funding approval isn't a code request");
  });

  await t.test("raising the amount needs the code; lowering it applies at once", async () => {
    const raise = await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (1_000n * CKB).toString() }) as { requiresEmailCode?: boolean };
    assert.equal(raise.requiresEmailCode, true);
    const lower = await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (10n * CKB).toString() }) as { dailyAmounts: Record<string, string>; requiresEmailCode?: boolean };
    assert.equal(lower.requiresEmailCode, undefined);
    assert.deepEqual(lower.dailyAmounts, { ckb: (10n * CKB).toString() });
    assert.equal(decodeSendLimitSettings(sent.at(-1)!.outputsData[sent.at(-1)!.outputs.findIndex((output, i) => isSendLimitCell(output, sent.at(-1)!.outputsData[i], secp))]).ckb, 10n * CKB);
  });

  t.after(async () => {
    const sql = await database();
    await sql`delete from keyway_v2_pending_transactions where user_id = ${user.id}`;
  });
});

test("send limits are offered by default to an account that could have them", { skip: !enabled }, async (t) => {
  const { world, user, wallet } = await setUp();
  t.after(() => { litSignerOverride.mode = undefined; });
  // The indexer's capacity sum over the same committed cells the fake client lists.
  const withCapacity = (plain: bigint) => Object.assign(world.client(), { getCellsCapacity: async () => plain });
  const head = { outPoint: { txHash: `0x${"ab".repeat(32)}`, index: 0 }, cellOutput: { lock: wallet.litPublicKey, capacity: 0n }, outputData: "0x", recordEntriesBytes: 0 } as unknown as SendLimitHead;

  assert.deepEqual(await sendLimitOffer(user, wallet, undefined, withCapacity(2_500n * CKB)), { ckb: DEFAULT_DAILY_LIMIT_SHANNONS }, "100,000 CKB a day by default");
  assert.equal(await sendLimitOffer(user, wallet, head, withCapacity(2_500n * CKB)), undefined, "not once limits are on");
  assert.equal(await sendLimitOffer(user, wallet, undefined, withCapacity(235n * CKB)), undefined, "not before the account can afford the cell");
  assert.equal(await sendLimitOffer(user, { ...wallet, recovery: { omnilockArgs: "0x00" } } as unknown as ReadyWallet, undefined, withCapacity(2_500n * CKB)), undefined, "not for a recovery account, which can't hold the cell yet");

  // An account that already chose an amount (kept by the server while it couldn't afford the cell) starts from it.
  const sql = await database();
  await sql`insert into keyway_v2_daily_amounts (user_id, asset, amount) values (${user.id}, 'ckb', ${(7_000n * CKB).toString()})`;
  assert.deepEqual(await sendLimitOffer(user, wallet, undefined, withCapacity(2_500n * CKB)), { ckb: 7_000n * CKB });

  litSignerOverride.mode = "digest";
  assert.equal(await sendLimitOffer(user, wallet, undefined, withCapacity(2_500n * CKB)), undefined, "not without the policy signer, which enforces them");
});

test("a token without an amount of its own sends without a code through the server and the Action", { skip: !enabled }, async (t) => {
  const { world, secp, user, wallet, context, sent } = await setUp();
  t.after(() => { litSignerOverride.mode = undefined; });
  const xudt = ccc.Script.from({ codeHash: "0x25c29dc317811a6f6f3985a7a9ebc4838bd388d19d0feeecf0bcd60f6c0975bb", hashType: "type", args: `0x${"ab".repeat(32)}` });
  const asked = await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (1_000n * CKB).toString() }) as { confirmationNonce: string };
  await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (1_000n * CKB).toString(), confirmationNonce: asked.confirmationNonce, emailCode: codeFrom(world) });
  const genesis = world.add(sent.at(-1)!, "committed");
  const tokens = world.add(ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: `0x${"0e".repeat(32)}`, index: 0 } }],
    outputs: [{ lock: secp, type: xudt, capacity: 200n * CKB }],
    outputsData: [ccc.hexFrom(ccc.numLeToBytes(1_000_000n, 16))],
  }));
  const head = (await sendLimitHead(context.client!, wallet, await listPendingTransactions(user.id, async () => "committed")))!;
  const token = ccc.Cell.from({ outPoint: { txHash: tokens.hash(), index: 0 }, cellOutput: tokens.outputs[0], outputData: tokens.outputsData[0] });
  const change = ccc.Cell.from({ outPoint: { txHash: genesis.hash(), index: 1 }, cellOutput: genesis.outputs[1], outputData: "0x" });
  const tx = ccc.Transaction.from({
    inputs: [token, change].map((cell) => ({ previousOutput: cell.outPoint, cellOutput: cell.cellOutput, outputData: cell.outputData })),
    outputs: [{ lock: stranger, type: xudt, capacity: 200n * CKB }, { lock: secp, capacity: change.cellOutput.capacity - 100_000n }],
    outputsData: [token.outputData, "0x"],
  });
  chainOnSendLimit(tx, head);
  const witness = tx.getWitnessArgsAt(0) ?? ccc.WitnessArgs.from({});
  witness.lock = ccc.hexFrom(new Uint8Array(65));
  tx.setWitnessArgsAt(0, witness);
  const transaction = JSON.parse(ccc.stringify(tx));
  // The whole balance of a token the user set no amount for, with the CKB amount set: no code, from either side.
  const preview = await transactionSigning(context, { operation: "preview", transaction }) as { requiresEmailCode: boolean; confirmationNonce: string };
  assert.equal(preview.requiresEmailCode, false);
  const signed = await transactionSigning(context, { operation: "sign", transaction, confirmationNonce: preview.confirmationNonce }) as { transaction: unknown };
  assert.ok(signed.transaction);
  t.after(async () => {
    const sql = await database();
    await sql`delete from keyway_v2_pending_transactions where user_id = ${user.id}`;
  });
});

/** Turns limits on (genesis committed) at this CKB amount; returns a setter and a reader for the server's amounts. */
async function limitsOn(world: ReturnType<typeof chain>, context: SigningContext, sent: ccc.Transaction[], amount: bigint) {
  const set = (value: bigint | null, extra: Record<string, unknown> = {}) => signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: value?.toString() ?? null, ...extra }) as Promise<Record<string, unknown>>;
  const amounts = async () => ((await signingSettings(context, { operation: "get" })) as { dailyAmounts: Record<string, string> }).dailyAmounts;
  const asked = await set(amount);
  await set(amount, { confirmationNonce: asked.confirmationNonce, emailCode: codeFrom(world) });
  world.add(sent.at(-1)!, "committed");
  return { set, amounts };
}

test("send-limit settings changes are rate limited, and nothing is signed when the cell already holds the amounts (audit M23)", { skip: !enabled }, async (t) => {
  const { world, user, context, sent } = await setUp();
  t.after(() => { litSignerOverride.mode = undefined; });
  const limited: string[] = [];
  let allow = true;
  context.rateLimit = async (key) => { limited.push(key); return { allowed: allow, retryAfter: allow ? null : 42 }; };
  let signings = 0;
  const run = litPolicyRunner.run;
  litPolicyRunner.run = async (config, params) => { if ((params as { mode?: string }).mode !== "send-code") signings++; return run(config, params); };
  t.after(() => { litPolicyRunner.run = run; });

  const { set } = await limitsOn(world, context, sent, 150n * CKB);
  assert.ok(limited.includes(`settings:${user.id}`), "a settings change is rate limited");
  assert.ok(!limited.includes(`sign:${user.id}`), "in its own bucket: signing requests can't use it up");

  // The same amounts the cell already holds: nothing to build, sign or send.
  const before = { sent: sent.length, signings };
  assert.deepEqual((await set(150n * CKB)).dailyAmounts, { ckb: (150n * CKB).toString() });
  assert.equal(sent.length, before.sent, "no transaction for an unchanged amount");
  assert.equal(signings, before.signings, "no Lit signing for an unchanged amount");

  allow = false;
  await assert.rejects(set(100n * CKB), /Too many/);
  assert.equal(sent.length, before.sent);

  t.after(async () => {
    const sql = await database();
    await sql`delete from keyway_v2_pending_transactions where user_id = ${user.id}`;
  });
});

test("a send-limit change never leaves the server's daily amounts looser than the chain's (audit L2)", { skip: !enabled }, async (t) => {
  const { world, user, context, sent } = await setUp();
  t.after(() => { litSignerOverride.mode = undefined; });
  const { set, amounts } = await limitsOn(world, context, sent, 150n * CKB);

  // Lowering it: the node takes the change, then the server goes away before it hears back. The server's amount,
  // the one hosted Fiber payments use, is already the lower one.
  const broadcast = context.broadcast!;
  context.broadcast = async (tx) => { await broadcast(tx); throw new Error("connection reset"); };
  await assert.rejects(set(10n * CKB), /connection reset/);
  assert.deepEqual(await amounts(), { ckb: (10n * CKB).toString() });
  world.add(sent.at(-1)!, "committed");

  // Raising it fails to send: the server keeps the stricter amount.
  context.broadcast = async () => { throw new Error("connection reset"); };
  const raise = await set(1_000n * CKB);
  assert.equal(raise.requiresEmailCode, true);
  await assert.rejects(set(1_000n * CKB, { confirmationNonce: raise.confirmationNonce, emailCode: codeFrom(world) }), /connection reset/);
  assert.deepEqual(await amounts(), { ckb: (10n * CKB).toString() });

  t.after(async () => {
    const sql = await database();
    await sql`delete from keyway_v2_pending_transactions where user_id = ${user.id}`;
  });
});

test("loosening amounts kept on the server alone goes through the server's code, showing them before and after (audit L13)", { skip: !enabled }, async (t) => {
  const { world, user, context, sent } = await setUp();
  t.after(() => { litSignerOverride.mode = undefined; });
  // An amount the account chose while it couldn't afford the send-limit cell, so the server alone keeps it.
  const sql = await database();
  await sql`insert into keyway_v2_daily_amounts (user_id, asset, amount) values (${user.id}, 'ckb', ${(10n * CKB).toString()})`;
  const emails: string[] = [];
  context.sendEmail = async (_to, message) => { emails.push(message.plaintext); };
  const litEmails = world.lit.emails.length;

  const asked = await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (100n * CKB).toString() }) as { requiresEmailCode: boolean; enforcedByLit: boolean; confirmationNonce: string };
  assert.equal(asked.requiresEmailCode, true);
  assert.equal(asked.enforcedByLit, false);
  assert.equal(world.lit.emails.length, litEmails, "not a 'turn on daily send limits' email from the Action");
  assert.equal(sent.length, 0);
  assert.match(emails.at(-1)!, /Email confirmation for CKB: once 10 CKB is sent in 24 hours/);
  assert.match(emails.at(-1)!, /Change: once 100 CKB is sent in 24 hours/);
  const code = /\b(\d{6})\b/.exec(emails.at(-1)!)![1];
  const done = await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (100n * CKB).toString(), confirmationNonce: asked.confirmationNonce, emailCode: code }) as { dailyAmounts: Record<string, string> };
  assert.deepEqual(done.dailyAmounts, { ckb: (100n * CKB).toString() });
  assert.equal(sent.length, 0);
});

test("daily amounts the send-limit cell can't hold are refused, so turning limits on can't fail later (audit M28)", { skip: !enabled }, async (t) => {
  const { world, context, sent } = await setUp();
  t.after(() => { litSignerOverride.mode = undefined; });
  // The server's own amounts (a test signer, so nothing is built on chain), as an account without the cell keeps them.
  const serverOnly = { ...context, signDigest: async () => "0x" as ccc.Hex };
  const set = (asset: string, amount: bigint | null) => signingSettings(serverOnly, { operation: "set-daily-amount", asset, amount: amount?.toString() ?? null });
  const token = (i: number) => `0x${i.toString(16).padStart(2, "0").repeat(32)}`;

  await assert.rejects(set(token(1), 1n << 128n), /too large/);
  await assert.rejects(set("ckb", (1n << 64n) - 1n), /too large/, "the cell's own 'no limit' value");
  for (let i = 1; i <= 8; i++) await set(token(i), 1_000n);
  await assert.rejects(set(token(9), 1_000n), /At most 8 tokens/);
  await set(token(8), 10n);

  // Turning limits on from these amounts still builds the cell.
  const asked = await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (100n * CKB).toString() }) as { requiresEmailCode: boolean; confirmationNonce: string };
  assert.equal(asked.requiresEmailCode, true);
  await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (100n * CKB).toString(), confirmationNonce: asked.confirmationNonce, emailCode: codeFrom(world) });
  assert.equal(decodeSendLimitSettings(sent.at(-1)!.outputsData[0]).tokens.size, 8);
});

test("setting the old amount again while a tightening is being signed can't leave the server looser than the chain", { skip: !enabled }, async (t) => {
  const { world, secp, user, context, sent } = await setUp();
  t.after(() => { litSignerOverride.mode = undefined; });
  const { set, amounts } = await limitsOn(world, context, sent, 150n * CKB);
  // A node: a transaction spending a cell an accepted one already spent is refused.
  const accepted = new Set<string>();
  const broadcast = context.broadcast!;
  context.broadcast = async (tx) => {
    const spends = tx.inputs.map((input) => `${input.previousOutput.txHash}:${input.previousOutput.index}`);
    if (spends.some((outPoint) => accepted.has(outPoint))) throw new Error("PoolRejectedRBF: conflicting transaction");
    spends.forEach((outPoint) => accepted.add(outPoint));
    return broadcast(tx);
  };
  // While the user's lowering to 10 CKB is being signed, the same session asks for 150 CKB again.
  let raced: Promise<unknown> | undefined;
  context.recordSigning = async () => {
    if (raced) return;
    raced = set(150n * CKB).catch((error: Error) => error);
    // Give it time to run alongside, as far as it can, without waiting on it (it may be waiting on this change).
    await Promise.race([raced, new Promise((resolve) => setTimeout(resolve, 1_000))]);
  };
  const lowered = await set(10n * CKB).catch((error: Error) => error);
  await raced;
  // Whichever change reached the node, the server's amount is no looser than the cell's.
  const onChain = decodeSendLimitSettings(sent.at(-1)!.outputsData[sent.at(-1)!.outputs.findIndex((output, i) => isSendLimitCell(output, sent.at(-1)!.outputsData[i], secp))]).ckb!;
  const server = BigInt((await amounts()).ckb);
  assert.ok(server <= onChain, `server ${server} looser than chain ${onChain} (lowering: ${lowered instanceof Error ? lowered.message : "sent"})`);

  t.after(async () => {
    const sql = await database();
    await sql`delete from keyway_v2_pending_transactions where user_id = ${user.id}`;
  });
});

/** The amount in the account's newest send-limit cell among these transactions: the one no other of them spends. */
function newestCellAmount(sent: ccc.Transaction[], secp: ccc.Script): bigint | undefined {
  const spent = new Set(sent.flatMap((tx) => tx.inputs.map((input) => `${input.previousOutput.txHash}:${Number(input.previousOutput.index)}`)));
  for (const tx of sent) {
    const index = tx.outputs.findIndex((output, i) => isSendLimitCell(output, tx.outputsData[i], secp));
    if (index !== -1 && !spent.has(`${tx.hash()}:${index}`)) return decodeSendLimitSettings(tx.outputsData[index]).ckb;
  }
  return undefined;
}

test("a lowering made while a raise is being sent leaves the server no looser than the chain", { skip: !enabled }, async (t) => {
  const { world, secp, user, context, sent } = await setUp();
  t.after(() => { litSignerOverride.mode = undefined; });
  const { set, amounts } = await limitsOn(world, context, sent, 150n * CKB);
  const raise = await set(1_000n * CKB);
  // The raise reaches the node; before the server hears back, the same session lowers the amount to 50 CKB.
  const broadcast = context.broadcast!;
  let lowering: Promise<unknown> | undefined;
  context.broadcast = async (tx) => {
    const hash = await broadcast(tx);
    if (!lowering) {
      lowering = set(50n * CKB).catch((error: Error) => error);
      await Promise.race([lowering, new Promise((resolve) => setTimeout(resolve, 4_000))]);
    }
    return hash;
  };
  // The raise reached the node, but the server keeps the lowering made meanwhile, and says so.
  await assert.rejects(set(1_000n * CKB, { confirmationNonce: raise.confirmationNonce, emailCode: codeFrom(world) }), /changed while this was waiting/);
  const lowered = await lowering;
  assert.ok(!(lowered instanceof Error), lowered instanceof Error ? lowered.message : "");
  const onChain = newestCellAmount(sent, secp)!;
  assert.equal(onChain, 50n * CKB, "the lowering is the newest cell");
  assert.deepEqual(await amounts(), { ckb: onChain.toString() });

  t.after(async () => {
    const sql = await database();
    await sql`delete from keyway_v2_pending_transactions where user_id = ${user.id}`;
  });
});

test("two token amounts added at once can't take the account past the eight the send-limit cell holds", { skip: !enabled }, async (t) => {
  const { world, context } = await setUp();
  t.after(() => { litSignerOverride.mode = undefined; });
  const token = (i: number) => `0x${i.toString(16).padStart(2, "0").repeat(32)}`;
  const quick = { ...context, signDigest: async () => "0x" as ccc.Hex };
  for (let i = 1; i <= 7; i++) await signingSettings(quick, { operation: "set-daily-amount", asset: token(i), amount: "1000" });
  // An account that can't afford the send-limit cell (no plain cell, found after a slow lookup) keeps its amounts
  // on the server; the lookup sits between reading the amounts and writing the new one.
  const slow = Object.assign(world.client(), { findCellsOnChain: async function* () { await new Promise((resolve) => setTimeout(resolve, 300)); } });
  const set = (asset: string) => signingSettings({ ...context, client: slow }, { operation: "set-daily-amount", asset, amount: "1000" });
  const results = await Promise.allSettled([set(token(8)), set(token(9))]);
  assert.equal(results.filter(({ status }) => status === "rejected").length, 1, JSON.stringify(results.map((result) => result.status === "rejected" ? String(result.reason) : "ok")));
  assert.match(String((results.find(({ status }) => status === "rejected") as PromiseRejectedResult).reason), /At most 8 tokens/);
  const stored = (await signingSettings(context, { operation: "get" }) as { dailyAmounts: Record<string, string> }).dailyAmounts;
  assert.equal(Object.keys(stored).length, 8);
});

test("raising the server's amount back to the cell's takes the server's code, even when the cell needs no change", { skip: !enabled }, async (t) => {
  const { world, user, context, sent } = await setUp();
  t.after(() => { litSignerOverride.mode = undefined; });
  const { set, amounts } = await limitsOn(world, context, sent, 150n * CKB);
  const emails: string[] = [];
  context.sendEmail = async (_to, message) => { emails.push(message.plaintext); };
  // A lowering that never reached the node: the server holds 10 CKB, the cell still 150.
  const broadcast = context.broadcast!;
  context.broadcast = async () => { throw new Error("connection reset"); };
  await assert.rejects(set(10n * CKB), /connection reset/);
  context.broadcast = broadcast;
  assert.deepEqual(await amounts(), { ckb: (10n * CKB).toString() });

  const litEmails = world.lit.emails.length;
  const asked = await set(150n * CKB);
  assert.equal(asked.requiresEmailCode, true, "loosening the server's amount needs a code");
  assert.equal(world.lit.emails.length, litEmails, "the cell allows it already, so the code is the server's");
  assert.deepEqual(await amounts(), { ckb: (10n * CKB).toString() });
  assert.match(emails.at(-1)!, /CKB: once 10 CKB is sent in 24 hours → once 150 CKB is sent in 24 hours/);
  await assert.rejects(set(150n * CKB, { confirmationNonce: asked.confirmationNonce, emailCode: "000000" }), /isn't right/);
  const code = /code is (\d{6})/.exec(emails.at(-1)!)![1];
  const done = await set(150n * CKB, { confirmationNonce: asked.confirmationNonce, emailCode: code });
  assert.deepEqual(done.dailyAmounts, { ckb: (150n * CKB).toString() });

  t.after(async () => {
    const sql = await database();
    await sql`delete from keyway_v2_pending_transactions where user_id = ${user.id}`;
  });
});

test("a change asked for while the account had no send-limit cell can't be confirmed once limits are on", { skip: !enabled }, async (t) => {
  const { world, user, context, sent } = await setUp();
  t.after(() => { litSignerOverride.mode = undefined; });
  const emails: string[] = [];
  // A server-only raise to 1,000 CKB, asked for before limits were on, then limits turned on at 150 CKB.
  const lines = ["Email confirmation for CKB: once 150 CKB is sent in 24 hours", "Change: once 1000 CKB is sent in 24 hours"];
  await limitsOn(world, context, sent, 150n * CKB);
  const nonce = await issueRequest(user, "settings", hashText(`daily-amount:ckb:${(1_000n * CKB).toString()}`), { lines }, true);
  await sendCode({ ...context, sendEmail: async (_to, message) => { emails.push(message.plaintext); } }, "settings", nonce, "Confirm a security change", lines, { limited: true });
  const code = /code is (\d{6})/.exec(emails.at(-1)!)![1];
  await assert.rejects(signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (1_000n * CKB).toString(), confirmationNonce: nonce, emailCode: code }), /turned on since/);
  const stored = (await signingSettings(context, { operation: "get" }) as { dailyAmounts: Record<string, string> }).dailyAmounts;
  assert.deepEqual(stored, { ckb: (150n * CKB).toString() });

  t.after(async () => {
    const sql = await database();
    await sql`delete from keyway_v2_pending_transactions where user_id = ${user.id}`;
  });
});

test("lowering an amount applies on the server at once, even while turning limits on waits for the Lit code", { skip: !enabled }, async (t) => {
  const { world, user, context, sent } = await setUp();
  t.after(() => { litSignerOverride.mode = undefined; });
  const sql = await database();
  await sql`insert into keyway_v2_daily_amounts (user_id, asset, amount) values (${user.id}, 'ckb', ${(100n * CKB).toString()})`;
  const asked = await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (50n * CKB).toString() }) as { requiresEmailCode: boolean; confirmationNonce: string };
  assert.equal(asked.requiresEmailCode, true, "turning limits on binds the email with the Lit code");
  assert.match(world.lit.emails.at(-1)!.text, /Turn on daily send limits/);
  assert.equal(sent.length, 0);
  const stored = (await signingSettings(context, { operation: "get" }) as { dailyAmounts: Record<string, string> }).dailyAmounts;
  assert.deepEqual(stored, { ckb: (50n * CKB).toString() }, "the lower amount already gates what the server checks");
});

test("a raise approved with the Lit code isn't sent once a stricter amount was set meanwhile", { skip: !enabled }, async (t) => {
  const { world, user, context, sent } = await setUp();
  t.after(() => { litSignerOverride.mode = undefined; });
  const { set, amounts } = await limitsOn(world, context, sent, 10n * CKB);
  const raise = await set(100n * CKB);
  assert.equal(raise.requiresEmailCode, true);
  const code = codeFrom(world);
  // A lowering to 5 CKB whose broadcast failed: the server holds 5, the cell is still unspent at 10.
  const broadcast = context.broadcast!;
  context.broadcast = async () => { throw new Error("connection reset"); };
  await assert.rejects(set(5n * CKB), /connection reset/);
  context.broadcast = broadcast;
  const before = sent.length;
  await assert.rejects(set(100n * CKB, { confirmationNonce: raise.confirmationNonce, emailCode: code }), /changed while this was waiting/);
  assert.equal(sent.length, before, "the stale raise never reaches the chain");
  assert.deepEqual(await amounts(), { ckb: (5n * CKB).toString() });

  t.after(async () => {
    const sql = await database();
    await sql`delete from keyway_v2_pending_transactions where user_id = ${user.id}`;
  });
});

test("an account already past eight token amounts can only remove them until it is back within the cell's eight", { skip: !enabled }, async (t) => {
  const { user, context } = await setUp();
  t.after(() => { litSignerOverride.mode = undefined; });
  const serverOnly = { ...context, signDigest: async () => "0x" as ccc.Hex };
  const token = (i: number) => `0x${i.toString(16).padStart(2, "0").repeat(32)}`;
  const sql = await database();
  for (let i = 1; i <= 9; i++) await sql`insert into keyway_v2_daily_amounts (user_id, asset, amount) values (${user.id}, ${token(i)}, '1000')`;
  const set = (asset: string, amount: bigint | null) => signingSettings(serverOnly, { operation: "set-daily-amount", asset, amount: amount?.toString() ?? null });
  await assert.rejects(set(token(1), 10n), /At most 8 tokens/);
  await assert.rejects(set("ckb", 100n * CKB), /At most 8 tokens/);
  // Removing one is a loosening, confirmed with the server's code, and brings the account back within the cell.
  const emails: string[] = [];
  const confirm = { ...serverOnly, sendEmail: async (_to: string, message: { plaintext: string }) => { emails.push(message.plaintext); } };
  const asked = await signingSettings(confirm, { operation: "set-daily-amount", asset: token(9), amount: null }) as { confirmationNonce: string };
  await signingSettings(confirm, { operation: "set-daily-amount", asset: token(9), amount: null, confirmationNonce: asked.confirmationNonce, emailCode: /code is (\d{6})/.exec(emails.at(-1)!)![1] });
  await set(token(1), 10n);
});

// Send limits on by default: before an account's first send, KeyWay offers to turn them on (100,000 CKB a day, which
// the user can change). The offer comes with the pending list; the signer asks once, turns them on through the
// signing-settings flow (with the Lit code), then builds the send on the new send-limit cell.
import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { secp256k1Lock } from "../src/sdk/browser/account-lock.ts";
import type { KeyWayApiClient } from "../src/sdk/browser/api-client.ts";
import { collectsForSend, KeyWaySigner, type ApproveDailyLimit } from "../src/sdk/browser/keyway-signer.ts";
import { DEFAULT_DAILY_LIMIT_SHANNONS, decodeSendLimitSettings, encodeSendLimitSettings, sendLimitInputIndex, type SendLimitHead } from "../src/sdk/browser/send-limits.ts";
import { formatCkbInput, parseCkbAmount } from "../src/sdk/react/signing-modals.tsx";

const CKB = 100_000_000n;
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true));
const stranger = ccc.Script.from({ codeHash: `0x${"99".repeat(32)}`, hashType: "type", args: "0x" });
const typeId = ccc.Script.from({ codeHash: "0x00000000000000000000000000000000000000000000000000545950455f4944", hashType: "type", args: `0x${"42".repeat(32)}` });

let nextHash = 1;
const cell = (lock: ccc.Script, capacity: bigint, type?: ccc.Script, outputData: ccc.Hex = "0x") =>
  ccc.Cell.from({ outPoint: { txHash: `0x${(nextHash++).toString(16).padStart(64, "0")}`, index: 0 }, cellOutput: { lock, capacity, type }, outputData });

function chain(cells: ccc.Cell[]) {
  const fresh = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  Object.assign(fresh, {
    findSingletonCellByType: async () => undefined,
    findCellsOnChain: async function* (key: ccc.ClientIndexerSearchKeyLike) {
      const search = ccc.ClientIndexerSearchKey.from(key);
      for (const live of cells) {
        if (!live.cellOutput.lock.eq(search.script)) continue;
        const [min, max] = search.filter?.scriptLenRange ?? [0n, 1n << 64n];
        const typeLength = BigInt(live.cellOutput.type ? live.cellOutput.type.toBytes().length : 0);
        if (search.filter?.scriptLenRange && (typeLength < min || typeLength >= max)) continue;
        yield live;
      }
    },
    getCell: async (outPoint: ccc.OutPointLike) => cells.find((live) => live.outPoint.eq(ccc.OutPoint.from(outPoint))),
  });
  return fresh;
}

/**
 * KeyWay's server, as far as these flows go: it lists what it signed with the newest send-limit cell, or the offer
 * when there is none; turning limits on asks for the code, then "sends" a genesis that spends the oldest cell.
 */
function server(secp: ccc.Script, funds: ccc.Cell, options: { offer?: boolean; head?: SendLimitHead; settingsError?: string; serverOnlyFirst?: boolean } = {}) {
  const signed: ccc.Transaction[] = [];
  const settingsCalls: Array<Record<string, unknown>> = [];
  let head = options.head;
  const api = {
    pendingTransactions: async () => ({
      transactions: signed.map((tx) => JSON.parse(ccc.stringify(tx))),
      ...(head ? { sendLimit: head } : options.offer ? { sendLimitOffer: { ckb: DEFAULT_DAILY_LIMIT_SHANNONS.toString() } } : {}),
    }),
    signingSettings: async (_token: string, body: Record<string, unknown>) => {
      settingsCalls.push(body);
      if (options.settingsError) throw new Error(options.settingsError);
      // Raising an amount the server alone keeps: its own six-digit code, then the amount is written, limits still off.
      if (options.serverOnlyFirst && settingsCalls.length <= 2) {
        if (body.confirmationNonce === undefined) return { requiresEmailCode: true, confirmationNonce: "server", sentTo: "u***@example.com", enforcedByLit: false };
        return { dailyAmounts: { ckb: String(body.amount) }, enforcedByLit: false };
      }
      if (body.confirmationNonce === undefined) return { requiresEmailCode: true, confirmationNonce: "nonce", sentTo: "u***@example.com", codeLength: 8 };
      const data = encodeSendLimitSettings({ fingerprint: `0x${"11".repeat(32)}`, tokensUnlimited: false, ckb: BigInt(String(body.amount)), tokens: new Map() });
      const genesis = ccc.Transaction.from({
        inputs: [{ previousOutput: funds.outPoint }],
        outputs: [{ lock: secp, type: typeId, capacity: 174n * CKB }, { lock: secp, capacity: funds.cellOutput.capacity - 175n * CKB }],
        outputsData: [data, "0x"],
      });
      signed.push(genesis);
      head = { outPoint: { txHash: genesis.hash(), index: 0 }, cellOutput: genesis.outputs[0], outputData: data, recordEntriesBytes: 0 };
      return { dailyAmounts: { ckb: String(body.amount) }, enforcedByLit: true };
    },
    signTransaction: async (_token: string, body: Record<string, unknown>) => {
      const transaction = ccc.Transaction.from(body.transaction as ccc.TransactionLike);
      if (body.operation === "preview") return { preview: { transactionHash: transaction.hash() }, confirmationNonce: crypto.randomUUID(), requiresEmailCode: false };
      signed.push(transaction);
      return { transaction: JSON.parse(ccc.stringify(transaction)) };
    },
  } as unknown as KeyWayApiClient;
  return { api, signed, settingsCalls, head: () => head };
}

function handlers(approveDailyLimit?: ApproveDailyLimit) {
  const codes: string[] = [];
  return {
    codes,
    handlers: {
      approveCkbTransaction: () => true,
      approveCkbMessage: () => false,
      requestEmailCode: async (request: { reason: string }) => { codes.push(request.reason); return "12345678"; },
      ...(approveDailyLimit ? { approveDailyLimit } : {}),
    },
  };
}

async function send(signer: KeyWaySigner, amount: bigint) {
  const tx = ccc.Transaction.from({ outputs: [{ lock: stranger, capacity: amount }] });
  await tx.completeInputsByCapacity(signer);
  await tx.completeFeeBy(signer, 1_000n);
  return signer.signOnlyTransaction(tx);
}

async function account() {
  const secp = await secp256k1Lock(new ccc.ClientPublicTestnet(), publicKey);
  const funds = cell(secp, 1_000n * CKB);
  return { secp, funds };
}

test("the first send asks for the daily limit once, turns limits on with the amount chosen, and chains on the new cell", async () => {
  const { secp, funds } = await account();
  const keyway = server(secp, funds, { offer: true });
  const offers: bigint[] = [];
  const { handlers: h, codes } = handlers((offer) => { offers.push(offer.ckb); return 25_000n * CKB; });
  const signer = new KeyWaySigner("token", publicKey, h, chain([funds]), keyway.api);
  const sent = await send(signer, 100n * CKB);

  assert.deepEqual(offers, [DEFAULT_DAILY_LIMIT_SHANNONS], "asked once, starting from 100,000 CKB");
  assert.deepEqual(keyway.settingsCalls.map((call) => [call.operation, call.asset, call.amount]), [["set-daily-amount", "ckb", (25_000n * CKB).toString()], ["set-daily-amount", "ckb", (25_000n * CKB).toString()]]);
  assert.deepEqual(codes, ["settings"], "the emailed code confirms it");
  assert.equal(decodeSendLimitSettings(keyway.head()!.outputData).ckb, 25_000n * CKB, "the edited amount is what's on chain");
  assert.notEqual(sendLimitInputIndex(sent, keyway.head()!), -1, "the send chains on the new send-limit cell");
  assert.ok(!sent.inputs.some((input) => input.previousOutput.eq(funds.outPoint)), "and never spends the cell the genesis spent");

  // Limits are on: the next send doesn't ask again.
  await send(signer, 10n * CKB);
  assert.equal(offers.length, 1);
});

test("raising an amount the server alone kept takes the server's code, then still turns limits on before the send (audit L13)", async () => {
  const { secp, funds } = await account();
  const keyway = server(secp, funds, { offer: true, serverOnlyFirst: true });
  const { handlers: h, codes } = handlers(() => 150_000n * CKB);
  const signer = new KeyWaySigner("token", publicKey, h, chain([funds]), keyway.api);
  const sent = await send(signer, 100n * CKB);
  assert.deepEqual(codes, ["settings", "settings"], "the server's code for the raise, then the Lit code for the cell");
  assert.equal(decodeSendLimitSettings(keyway.head()!.outputData).ckb, 150_000n * CKB);
  assert.notEqual(sendLimitInputIndex(sent, keyway.head()!), -1, "the send chains on the new send-limit cell");
});

test("without an app dialog, the offered amount is used as it is", async () => {
  const { secp, funds } = await account();
  const keyway = server(secp, funds, { offer: true });
  const signer = new KeyWaySigner("token", publicKey, handlers().handlers, chain([funds]), keyway.api);
  await send(signer, 100n * CKB);
  assert.equal(decodeSendLimitSettings(keyway.head()!.outputData).ckb, DEFAULT_DAILY_LIMIT_SHANNONS);
});

test("nothing is asked when the account already has limits, or KeyWay offers none (recovery account, low balance)", async () => {
  const { secp, funds } = await account();
  const data = encodeSendLimitSettings({ fingerprint: `0x${"11".repeat(32)}`, tokensUnlimited: false, ckb: 500n * CKB, tokens: new Map() });
  const limitCell = cell(secp, 174n * CKB, typeId, data);
  const head = { outPoint: { txHash: limitCell.outPoint.txHash, index: 0 }, cellOutput: limitCell.cellOutput, outputData: data, recordEntriesBytes: 0 };
  let asked = 0;
  const withLimits = server(secp, funds, { offer: true, head });
  await send(new KeyWaySigner("token", publicKey, handlers(() => { asked++; return 1n; }).handlers, chain([funds, limitCell]), withLimits.api), 100n * CKB);
  const noOffer = server(secp, funds);
  const plain = await send(new KeyWaySigner("token", publicKey, handlers(() => { asked++; return 1n; }).handlers, chain([funds]), noOffer.api), 100n * CKB);
  assert.equal(asked, 0);
  assert.equal(withLimits.settingsCalls.length + noOffer.settingsCalls.length, 0);
  assert.ok(plain.inputs.some((input) => input.previousOutput.eq(funds.outPoint)), "the send goes out as before");
});

test("cancelling the dialog cancels the send, and the next send asks again", async () => {
  const { secp, funds } = await account();
  const keyway = server(secp, funds, { offer: true });
  const answers: Array<bigint | null> = [null, 50_000n * CKB];
  const { handlers: h } = handlers(() => answers.shift()!);
  const signer = new KeyWaySigner("token", publicKey, h, chain([funds]), keyway.api);
  await assert.rejects(send(signer, 100n * CKB), /not approved/);
  assert.equal(keyway.settingsCalls.length, 0);
  assert.equal(keyway.signed.length, 0);
  await send(signer, 100n * CKB);
  assert.equal(decodeSendLimitSettings(keyway.head()!.outputData).ckb, 50_000n * CKB);
});

test("a zero amount is refused before anything is sent", async () => {
  const { secp, funds } = await account();
  const keyway = server(secp, funds, { offer: true });
  const signer = new KeyWaySigner("token", publicKey, handlers(() => 0n).handlers, chain([funds]), keyway.api);
  await assert.rejects(send(signer, 100n * CKB), /above 0 CKB/);
  assert.equal(keyway.settingsCalls.length, 0);
});

test("if a pending send holds the cell limits start from, this send goes out as before", async () => {
  const { secp, funds } = await account();
  const keyway = server(secp, funds, { offer: true, settingsError: "Wait for your pending send to confirm, then turn send limits on" });
  let asked = 0;
  const signer = new KeyWaySigner("token", publicKey, handlers(() => { asked++; return DEFAULT_DAILY_LIMIT_SHANNONS; }).handlers, chain([funds]), keyway.api);
  const sent = await send(signer, 100n * CKB);
  assert.equal(asked, 1);
  assert.ok(sent.inputs.some((input) => input.previousOutput.eq(funds.outPoint)));
});

test("only CCC collecting inputs for a send turns limits on; other lookups don't", async () => {
  assert.equal(collectsForSend({ scriptLenRange: [0, 1], outputDataLenRange: [0, 1] }), true, "plain CKB for a send");
  assert.equal(collectsForSend({ script: typeId }), true, "a token's cells for a transfer");
  assert.equal(collectsForSend({}), false);
  assert.equal(collectsForSend(undefined as unknown as Parameters<typeof collectsForSend>[0]), false);
  assert.equal(collectsForSend({ outputDataLenRange: [0, 1] }), false);
});

test("the dialog's amount field reads and writes CKB the way people type it", () => {
  assert.equal(formatCkbInput(DEFAULT_DAILY_LIMIT_SHANNONS), "100,000");
  assert.equal(formatCkbInput(2_500n * CKB + 50_000_000n), "2,500.5");
  assert.equal(parseCkbAmount("100,000"), 100_000n * CKB);
  assert.equal(parseCkbAmount(" 2500.5 "), 2_500n * CKB + 50_000_000n);
  for (const bad of ["", "0", "0.0", "-5", "abc", "1.123456789", "1e5"]) assert.equal(parseCkbAmount(bad), undefined, bad);
});

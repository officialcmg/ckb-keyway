import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { checkTokenFunding } from "../src/server/funding-transaction.ts";
import { describePayment } from "../src/sdk/browser/fiber-payment.ts";
import { formatAsset, tokenAsset } from "../src/sdk/browser/tokens.ts";

const XUDT = { codeHash: `0x${"aa".repeat(32)}` as ccc.Hex, hashType: "type" as const };
const client = { getKnownScript: async (script: ccc.KnownScript) => script === ccc.KnownScript.XUdt ? XUDT : { codeHash: `0x${"bb".repeat(32)}`, hashType: "type" } } as unknown as ccc.Client;
const own = ccc.Script.from({ codeHash: `0x${"11".repeat(32)}`, hashType: "type", args: "0x01" });
const peer = ccc.Script.from({ codeHash: `0x${"11".repeat(32)}`, hashType: "type", args: "0x02" });
const funding = ccc.Script.from({ codeHash: `0x${"6c".repeat(32)}`, hashType: "type", args: "0x" });
const rusd = ccc.Script.from({ ...XUDT, args: `0x${"cd".repeat(32)}` });
const other = ccc.Script.from({ ...XUDT, args: `0x${"ef".repeat(32)}` });
const amount = (value: bigint) => ccc.hexFrom(ccc.numLeToBytes(value, 16));

function tx(outputs: Array<{ lock: ccc.Script; type?: ccc.Script; data?: ccc.Hex }>) {
  return ccc.Transaction.from({
    outputs: outputs.map(({ lock, type }) => ({ lock, type, capacity: 200n * 100_000_000n })),
    outputsData: outputs.map(({ data }) => data ?? "0x"),
  });
}
const inputs = [
  { cellOutput: ccc.CellOutput.from({ lock: own, type: rusd, capacity: 143n * 100_000_000n }), outputData: amount(50n) },
  { cellOutput: ccc.CellOutput.from({ lock: own, capacity: 1000n * 100_000_000n }), outputData: "0x" as ccc.Hex },
];

test("token channel funding: the token goes only into the channel and back to the account", async () => {
  const good = tx([{ lock: funding, type: rusd, data: amount(20n) }, { lock: own, type: rusd, data: amount(30n) }, { lock: own }]);
  assert.deepEqual(await checkTokenFunding(client, good, inputs, own, good.outputs[0]), { asset: rusd.hash(), amount: 20n });

  const leak = tx([{ lock: funding, type: rusd, data: amount(20n) }, { lock: peer, type: rusd, data: amount(30n) }]);
  await assert.rejects(() => checkTokenFunding(client, leak, inputs, own, leak.outputs[0]), /only the channel output and your own change/i);

  const twoTokens = tx([{ lock: funding, type: rusd, data: amount(20n) }, { lock: own, type: other, data: amount(1n) }]);
  await assert.rejects(() => checkTokenFunding(client, twoTokens, inputs, own, twoTokens.outputs[0]), /only one token/);

  const odd = ccc.Script.from({ codeHash: `0x${"99".repeat(32)}`, hashType: "type", args: "0x" });
  const unknown = tx([{ lock: funding, type: odd, data: amount(20n) }]);
  await assert.rejects(() => checkTokenFunding(client, unknown, [], own, unknown.outputs[0]), /standard xUDT or sUDT/);

  const ckb = tx([{ lock: funding }, { lock: own }]);
  assert.equal(await checkTokenFunding(client, ckb, [inputs[1]], own, ckb.outputs[0]), undefined);
  const data = tx([{ lock: funding }, { lock: own, data: "0x1234" }]);
  await assert.rejects(() => checkTokenFunding(client, data, [inputs[1]], own, data.outputs[0]), /Unexpected funding output data/);
});

test("token payments are counted in the token, fee included", async () => {
  const typeScript = { code_hash: rusd.codeHash, hash_type: "type", args: rusd.args };
  const described = await describePayment("sendPayment", { invoice: "fibt1x", udt_type_script: typeScript }, {
    parseInvoice: async () => ({ invoice: { amount: "0x77359400", data: { attrs: [{ description: "coffee" }] } } }) as never,
    dryRun: async () => ({ fee: "0x3e8" }),
  });
  assert.equal(described.asset, rusd.hash());
  assert.equal(described.outflow, 2_000_000_000n + 1000n);
  assert.equal(tokenAsset(ccc.hexFrom(rusd.toBytes())), rusd.hash());
  const known = "0x45b32a2bc4285d0a09678eb11960ddc8707bc2779887a09d482e9bfe9a2cdf52";
  assert.equal(formatAsset(2_000_000_000n, known), "20 RUSD");
  assert.equal(formatAsset(150_000_000n, "ckb"), "1.5 CKB");
  assert.match(formatAsset(5n, rusd.hash()), /^5 of token 0x/);
});

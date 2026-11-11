// The rescue approval counts token cells ("Tokens: 2 token cells") rather than naming them, so the SDK, like the
// on-chain verifiers (contracts/keyway-approval, chain::rescue_text), builds a text only when the token cells are
// exactly the account's own, moved unchanged. contracts/tests/tests/approval.rs runs the same cases on chain.
import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { recoveryApprovalText, rescueApproval, type RescueInputCell } from "../src/sdk/browser/recovery-approval.ts";

const client = new ccc.ClientPublicTestnet();
const CKB = 100_000_000n;
const account = ccc.Script.from({ codeHash: `0x${"0a".repeat(32)}`, hashType: "data1", args: `0x${"00".repeat(21)}01${"5a".repeat(32)}` });
const destination = ccc.Script.from({ codeHash: `0x${"9b".repeat(32)}`, hashType: "type", args: `0x${"77".repeat(20)}` });
const stranger = ccc.Script.from({ codeHash: `0x${"9b".repeat(32)}`, hashType: "type", args: `0x${"ee".repeat(20)}` });
const udt = (byte: string) => ccc.Script.from({ codeHash: `0x${"5d".repeat(32)}`, hashType: "type", args: `0x${byte.repeat(32)}` });
const amount = (value: bigint) => ccc.hexFrom(ccc.numLeToBytes(value, 16));

type Cell = { lock?: ccc.Script; type?: ccc.Script; data?: ccc.Hex; capacity: bigint };
function rescue(inputs: Cell[], outputs: Cell[]) {
  const transaction = ccc.Transaction.from({
    inputs: inputs.map((_, index) => ({ previousOutput: { txHash: ccc.hexFrom(ccc.numBeToBytes(index + 1, 32)), index: 0 } })),
    outputs: outputs.map(({ lock, type, capacity }) => ({ lock: lock ?? destination, type, capacity })),
    outputsData: outputs.map(({ data }) => data ?? "0x"),
  });
  const cells: RescueInputCell[] = inputs.map(({ lock, type, data, capacity }) => ({ cellOutput: { lock: lock ?? account, type, capacity }, outputData: data ?? "0x" }));
  return () => rescueApproval(transaction, account, cells);
}

// The account holds two token cells of one token and plain CKB.
const held: Cell[] = [
  { type: udt("a1"), data: amount(1_000n), capacity: 143n * CKB },
  { type: udt("a1"), data: amount(25n), capacity: 143n * CKB },
  { capacity: 1_000n * CKB },
];
const honest: Cell[] = [
  { type: udt("a1"), data: amount(25n), capacity: 143n * CKB },
  { type: udt("a1"), data: amount(1_000n), capacity: 143n * CKB },
  { capacity: 999n * CKB },
];

test("the honest rescue moves each of the account's token cells as it is", () => {
  const approval = rescue(held, honest)();
  assert.equal(approval.tokenCells, 2);
  assert.equal(approval.fee, CKB);
  assert.match(recoveryApprovalText(client, approval, `0x${"01".repeat(32)}`), /\nTokens: 2 token cells\n/);
});

test("refuses token cells that aren't the account's own, moved unchanged, behind the same token count", () => {
  const attempts: Array<[string, Cell[], Cell[]]> = [
    ["a token cell changed, its tokens burned", held, [honest[0], { ...honest[1], data: amount(1n) }, honest[2]]],
    ["the same data under another type script", held, [honest[0], { ...honest[1], type: udt("b2") }, honest[2]]],
    ["one token cell burned, CKB under the builder's own type script in its place", held, [honest[0], honest[2], { type: udt("c3"), capacity: 143n * CKB }]],
    ["one token cell burned, its CKB moved as plain CKB", held, [honest[0], { capacity: 1_142n * CKB }]],
    ["one token cell moved twice", held, [honest[1], honest[1], honest[2]]],
    ["a token cell taken from someone else's input", [{ ...held[0], lock: stranger }, held[1], held[2]], honest],
    ["the plain CKB locked under the builder's own type script", held, [honest[0], honest[1], { ...honest[2], type: udt("d4") }]],
  ];
  for (const [what, inputs, outputs] of attempts) {
    assert.throws(rescue(inputs, outputs), /can't be approved by a backup: .*token cell/, what);
  }
});

test("someone else's token cell may be spent beside the rescue, and isn't counted", () => {
  const approval = rescue([...held, { lock: stranger, type: udt("f6"), data: amount(5n), capacity: 143n * CKB }], [...honest, { capacity: 143n * CKB }])();
  assert.equal(approval.tokenCells, 2);
});

test("refuses more token cells than the verifiers move at once", () => {
  const many = Array.from({ length: 257 }, (_, index): Cell => ({ type: udt("a1"), data: amount(BigInt(index)), capacity: 143n * CKB }));
  assert.throws(rescue([...many, { capacity: 1_000n * CKB }], many), /more than 256 token cells/);
});

import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { serializeCccTransaction, serializeCccTransactionForRpc } from "../src/sdk/browser/ccc-transaction.ts";
import { JsonRpcTransformers } from "@ckb-ccc/core/advanced";

const ZERO_HASH = `0x${"00".repeat(32)}`;

test("serializes CCC bigint transaction fields as CKB RPC hex", () => {
  const transaction = serializeCccTransaction({
    version: "0x0",
    cellDeps: [],
    headerDeps: [],
    inputs: [{
      since: "0x0",
      previousOutput: { txHash: ZERO_HASH, index: "0x1" },
    }],
    outputs: [{
      capacity: "0x174876e800",
      lock: { codeHash: ZERO_HASH, hashType: "type", args: "0x" },
    }],
    outputsData: ["0x"],
    witnesses: ["0x"],
  });

  assert.equal(transaction.version, "0x0");
  assert.equal((transaction.inputs as Array<Record<string, unknown>>)[0].since, "0x0");
  assert.equal(
    ((transaction.inputs as Array<{ previousOutput: { index: unknown } }>)[0]).previousOutput.index,
    "0x1",
  );
  assert.equal((transaction.outputs as Array<Record<string, unknown>>)[0].capacity, "0x174876e800");
  assert.doesNotThrow(() => JSON.stringify(transaction));
});

test("RPC serialization excludes cached input metadata without changing transaction or witnesses", () => {
  const transaction = ccc.Transaction.from({
    inputs: [{
      since: 0,
      previousOutput: { txHash: ZERO_HASH, index: 1 },
      cellOutput: { capacity: 100_000_000n, lock: { codeHash: ZERO_HASH, hashType: "type", args: "0x" } },
      outputData: "0x1234",
    }],
    witnesses: ["0x1234"],
  });
  const rpc = serializeCccTransactionForRpc(transaction);
  assert.deepEqual(Object.keys(rpc.inputs[0]).sort(), ["previous_output", "since"]);
  assert.equal(rpc.inputs[0].previous_output.index, "0x1");
  assert.deepEqual(rpc.witnesses, transaction.witnesses);
  assert.equal(JsonRpcTransformers.transactionTo(rpc).hash(), transaction.hash());
});

import assert from "node:assert/strict";
import test from "node:test";
import { serializeCccTransaction } from "../src/sdk/browser/ccc-transaction.ts";

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

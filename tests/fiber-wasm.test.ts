import assert from "node:assert/strict";
import test from "node:test";
import { ConfigBuilder } from "@fiber-pay/sdk/browser";
import { withFiberContracts } from "../src/sdk/browser/fiber-wasm.ts";

const LIVE_TESTNET_CKB_AUTH = "0x12c569a258dd9c5bd99f632bb8314b1263b90921ba31496467580d6b79dd14a7";
const MISSING_CKB_AUTH = "0x5a5288769cecde6451cb5d301416c297a6da43dc3ac2f3253542b4082478b19b";

test("the browser node's testnet config uses the ckb_auth cell from Fiber's own testnet config", () => {
  const config = withFiberContracts(ConfigBuilder.build({ network: "testnet" }), "testnet");
  // One ckb_auth cell dep each for the funding lock and the commitment lock.
  assert.equal(config.split(LIVE_TESTNET_CKB_AUTH).length - 1, 2);
  assert.ok(!config.includes(MISSING_CKB_AUTH));
});

test("leaves configs without the missing cell unchanged", () => {
  const config = "fiber:\n  chain: testnet\n";
  assert.equal(withFiberContracts(config, "testnet"), config);
  assert.equal(withFiberContracts(config, "mainnet"), config);
});

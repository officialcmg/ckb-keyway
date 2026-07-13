import assert from "node:assert/strict";
import test from "node:test";
import { formatFiberOutpoint } from "../src/sdk/browser/channel-evidence.ts";

test("formats Fiber outpoints across runtime representations", () => {
  const packed = `0x${"ab".repeat(32)}00000000`;
  assert.equal(formatFiberOutpoint(packed), packed);
  assert.equal(formatFiberOutpoint({ tx_hash: "0x01", index: "0x2" }), "0x01:0x2");
  assert.equal(formatFiberOutpoint({ txHash: "0x03", index: 4n }), "0x03:0x4");
  assert.equal(formatFiberOutpoint(null, "pending"), "pending");
});

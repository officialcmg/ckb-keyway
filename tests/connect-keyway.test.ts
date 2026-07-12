import assert from "node:assert/strict";
import test from "node:test";
import { normalizeFiberPubkey } from "../src/sdk/browser/fiber-pubkey.ts";

test("accepts Fiber peer keys with or without a hex prefix", () => {
  const bare = `02${"11".repeat(32)}`;
  assert.equal(normalizeFiberPubkey(bare), `0x${bare}`);
  assert.equal(normalizeFiberPubkey(`0x${bare}`), `0x${bare}`);
});

test("rejects malformed or uncompressed peer keys", () => {
  assert.throws(() => normalizeFiberPubkey(`04${"11".repeat(32)}`), /invalid peer identity/);
  assert.throws(() => normalizeFiberPubkey("0x02"), /invalid peer identity/);
});

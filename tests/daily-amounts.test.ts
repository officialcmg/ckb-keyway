// The server's daily-amount rule and the send-limit cell it writes: only assets with an amount of their own are
// limited, so a token (or NFT, or any cell KeyWay can't read) without one has no limit.
import assert from "node:assert/strict";
import test from "node:test";
import { decodeSendLimitSettings, encodeSendLimitSettings, settingsFromDailyAmounts } from "../src/sdk/browser/send-limits.ts";
import { dailyAllowance, weakens } from "../src/server/general-signing.ts";

const CKB = 100_000_000n;
const TOKEN = `0x${"45".repeat(32)}`;
const FINGERPRINT = new Uint8Array(32).fill(7);

test("an asset without an amount of its own has no limit; CKB keeps its amount", () => {
  const amounts = new Map([["ckb", 100_000n * CKB]]);
  assert.equal(dailyAllowance(amounts, "ckb"), 100_000n * CKB);
  assert.equal(dailyAllowance(amounts, TOKEN), "unlimited");
  assert.equal(dailyAllowance(new Map([["ckb", 1n], [TOKEN, 5n]]), TOKEN), 5n);
  assert.equal(dailyAllowance(new Map(), TOKEN), "unlimited");
});

test("giving a token its own amount is stricter; raising or removing it loosens", () => {
  const ckbOnly = new Map([["ckb", 1_000n * CKB]]);
  const withToken = new Map([["ckb", 1_000n * CKB], [TOKEN, 100n]]);
  assert.equal(weakens(ckbOnly, withToken), false);
  assert.equal(weakens(withToken, ckbOnly), true);
  assert.equal(weakens(withToken, new Map([["ckb", 1_000n * CKB], [TOKEN, 101n]])), true);
  assert.equal(weakens(withToken, new Map([["ckb", 1_000n * CKB], [TOKEN, 99n]])), false);
  // Removing the CKB amount while a token keeps its own still loosens CKB.
  assert.equal(weakens(withToken, new Map([[TOKEN, 100n]])), true);
});

test("the send-limit cell KeyWay writes has tokens unlimited, with only the listed tokens limited", () => {
  for (const amounts of [new Map([["ckb", 100_000n * CKB]]), new Map([["ckb", 1n], [TOKEN, 5n]]), new Map([[TOKEN, 5n]]), new Map<string, bigint>()]) {
    const settings = settingsFromDailyAmounts(amounts, FINGERPRINT);
    assert.equal(settings.tokensUnlimited, true);
    const data = encodeSendLimitSettings(settings);
    assert.equal(data.slice(2 + 37 * 2, 2 + 38 * 2), "01", "flag bit 0 is set in the cell");
    const decoded = decodeSendLimitSettings(data);
    assert.equal(decoded.tokensUnlimited, true);
    assert.deepEqual([...decoded.tokens], [...amounts].filter(([asset]) => asset !== "ckb"));
    assert.equal(decoded.ckb, amounts.get("ckb"));
  }
});

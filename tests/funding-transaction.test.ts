import assert from "node:assert/strict";
import test from "node:test";
import { calculateFundingSpend, formatCkbSignature } from "../src/server/funding-transaction.ts";

test("formats Lit components as CKB r-s-recovery signature bytes", () => {
  const signature = formatCkbSignature({
    r: `0x${"11".repeat(32)}`,
    s: `0x${"22".repeat(32)}`,
    recoveryParam: 1,
  });

  assert.equal(signature, `0x${"11".repeat(32)}${"22".repeat(32)}01`);
  assert.equal((signature.length - 2) / 2, 65);
});

test("rejects malformed Lit signature components", () => {
  assert.throws(
    () => formatCkbSignature({ r: "0x11", s: `0x${"22".repeat(32)}`, recoveryParam: 0 }),
    /malformed signature/,
  );
});

test("allows peer inputs while limiting the KeyWay wallet's own channel spend", () => {
  const spend = calculateFundingSpend({
    ownedInputCapacity: 1100n * 100_000_000n,
    ownedChangeCapacity: 9_999_900_000n,
    totalInputCapacity: 1350n * 100_000_000n,
    totalOutputCapacity: 134_999_900_000n,
  });

  assert.deepEqual(spend, {
    fundingAmount: 1000n * 100_000_000n,
    fee: 100_000n,
  });
});

test("rejects collaborative funding that overspends the KeyWay wallet", () => {
  assert.throws(() => calculateFundingSpend({
    ownedInputCapacity: 1200n * 100_000_000n,
    ownedChangeCapacity: 9_999_900_000n,
    totalInputCapacity: 1450n * 100_000_000n,
    totalOutputCapacity: 144_999_900_000n,
  }), /funding exceeds/);
});

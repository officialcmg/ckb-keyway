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

test("allows any channel size and rejects funding that spends nothing from the wallet", () => {
  assert.equal(calculateFundingSpend({
    ownedInputCapacity: 50_000n * 100_000_000n,
    ownedChangeCapacity: 0n,
    totalInputCapacity: 50_000n * 100_000_000n,
    totalOutputCapacity: 50_000n * 100_000_000n - 100_000n,
  }).fundingAmount, 50_000n * 100_000_000n - 100_000n);
  assert.throws(() => calculateFundingSpend({
    ownedInputCapacity: 100n * 100_000_000n,
    ownedChangeCapacity: 100n * 100_000_000n,
    totalInputCapacity: 100n * 100_000_000n,
    totalOutputCapacity: 100n * 100_000_000n,
  }), /must spend from the KeyWay wallet/);
});

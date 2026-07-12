import assert from "node:assert/strict";
import test from "node:test";
import { formatCkbSignature } from "../src/server/funding-transaction.ts";

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

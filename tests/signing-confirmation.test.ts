import assert from "node:assert/strict";
import test from "node:test";
import type { User } from "stytch";
import { verifyConfirmation } from "../src/server/signing-confirmation.ts";
import { sha256 } from "@noble/hashes/sha2.js";

function digest(value: string): string {
  return Buffer.from(sha256(new TextEncoder().encode(value))).toString("hex");
}

test("binds a signing confirmation to the exact prepared transaction", () => {
  const transaction = '{"version":"0x0","witnesses":["0x"]}';
  const user = {
    user_id: "user-test",
    trusted_metadata: {
      keywaySigningConfirmation: {
        nonce: "nonce-test",
        transactionDigest: digest(transaction),
        expiresAt: new Date(Date.now() + 30_000).toISOString(),
      },
    },
  } as unknown as User;

  assert.doesNotThrow(() => verifyConfirmation(user, "nonce-test", transaction));
  assert.throws(
    () => verifyConfirmation(user, "nonce-test", transaction.replace('"0x"', '"0x01"')),
    /invalid or expired/,
  );
});

test("rejects expired signing confirmations", () => {
  const user = {
    user_id: "user-test",
    trusted_metadata: {
      keywaySigningConfirmation: {
        nonce: "nonce-test",
        transactionDigest: digest("transaction"),
        expiresAt: new Date(Date.now() - 1).toISOString(),
      },
    },
  } as unknown as User;

  assert.throws(() => verifyConfirmation(user, "nonce-test", "transaction"), /invalid or expired/);
});

import assert from "node:assert/strict";
import test from "node:test";
import type { User } from "stytch";
import {
  consumeConfirmation,
  issueConfirmation,
} from "../src/server/signing-confirmation.ts";

test("binds a signing confirmation to the exact prepared transaction", { skip: !process.env.DATABASE_URL }, async () => {
  const user = { user_id: `confirmation-test-${crypto.randomUUID()}` } as User;
  const transaction = '{"version":"0x0","witnesses":["0x"]}';
  const nonce = await issueConfirmation(user, transaction);
  await assert.rejects(
    consumeConfirmation(user, nonce, transaction.replace('"0x"', '"0x01"')),
    /invalid or expired/,
  );
  await consumeConfirmation(user, nonce, transaction);
  await assert.rejects(consumeConfirmation(user, nonce, transaction), /invalid or expired/);
});

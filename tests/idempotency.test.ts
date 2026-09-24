import assert from "node:assert/strict";
import test from "node:test";
import { runIdempotentMutation } from "../src/server/idempotency.ts";

test("returns the first managed mutation result without running it twice", { skip: !process.env.DATABASE_URL }, async () => {
  const userId = `idempotency-test-${crypto.randomUUID()}`;
  const key = crypto.randomUUID();
  let executions = 0;
  const mutation = () => runIdempotentMutation(userId, "payment", key, { invoice: "fibt-test" }, async () => {
    executions += 1;
    return { paymentHash: "0x1234" };
  });

  assert.deepEqual(await mutation(), { paymentHash: "0x1234" });
  assert.deepEqual(await mutation(), { paymentHash: "0x1234" });
  assert.equal(executions, 1);
  await assert.rejects(
    runIdempotentMutation(userId, "payment", key, { invoice: "fibt-other" }, async () => ({})),
    /another request/,
  );
});

test("allows only one concurrent mutation to claim an idempotency key", { skip: !process.env.DATABASE_URL }, async () => {
  const userId = `idempotency-concurrent-${crypto.randomUUID()}`;
  const key = crypto.randomUUID();
  let release!: () => void;
  const blocked = new Promise<void>((resolve) => { release = resolve; });
  const first = runIdempotentMutation(userId, "payment", key, { invoice: "fibt-test" }, async () => {
    await blocked;
    return { paymentHash: "0x1234" };
  });

  await new Promise((resolve) => setTimeout(resolve, 20));
  await assert.rejects(
    runIdempotentMutation(userId, "payment", key, { invoice: "fibt-test" }, async () => ({})),
    /still in progress/,
  );
  release();
  assert.deepEqual(await first, { paymentHash: "0x1234" });
});

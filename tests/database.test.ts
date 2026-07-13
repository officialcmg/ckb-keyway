import assert from "node:assert/strict";
import test from "node:test";
import { withUserLock } from "../src/server/database.ts";

test("serializes wallet mutations for the same user", { skip: !process.env.DATABASE_URL }, async () => {
  let active = 0;
  let maxActive = 0;
  const userId = `lock-test-${crypto.randomUUID()}`;
  const operation = () => withUserLock(userId, async () => {
    active += 1;
    maxActive = Math.max(maxActive, active);
    await new Promise((resolve) => setTimeout(resolve, 50));
    active -= 1;
  });

  await Promise.all([operation(), operation()]);
  assert.equal(maxActive, 1);
});

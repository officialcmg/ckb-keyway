import assert from "node:assert/strict";
import test from "node:test";
import { createManagedKeyWay } from "../src/sdk/browser/create-managed-keyway.ts";

test("managed payments reuse the exact preflight confirmation once", async () => {
  const requests: Array<{ body: Record<string, unknown>; key?: string }> = [];
  const api = {
    managedNode: async (_token: string, body: Record<string, unknown>, key?: string) => {
      requests.push({ body, key });
      if (body.operation === "preflight-payment") {
        return { routable: true, fee: "0x1", confirmationNonce: "confirmation-1" };
      }
      if (body.operation === "send-payment") {
        return { payment_hash: `0x${"22".repeat(32)}`, fee: "0x1", status: "Created" };
      }
      throw new Error("Unexpected managed request");
    },
  };
  const keyway = createManagedKeyWay({
    authToken: "session",
    ckbPublicKey: `0x02${"11".repeat(32)}`,
    confirmFunding: () => true,
    apiClient: api as never,
  });
  const params = { invoice: "fibt-test", max_fee_amount: "0x64" as const };

  const preflight = await keyway.preflightPayment(params);
  assert.deepEqual(preflight, { routable: true, feeShannons: 1n });
  await keyway.sendPayment(params);

  assert.equal(requests.filter(({ body }) => body.operation === "preflight-payment").length, 1);
  assert.equal(requests[1].body.confirmationNonce, "confirmation-1");
  assert.match(requests[1].key ?? "", /^[0-9a-f-]{36}$/);
});

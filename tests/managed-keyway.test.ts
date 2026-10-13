import assert from "node:assert/strict";
import test from "node:test";
import { createManagedKeyWay } from "../src/sdk/browser/create-managed-keyway.ts";

test("hosted payments: preview, the app's optional approval, then send with the exact approval", async () => {
  const requests: Array<{ body: Record<string, unknown>; key?: string }> = [];
  const approvals: unknown[] = [];
  const api = {
    managedNode: async (_token: string, body: Record<string, unknown>, key?: string) => {
      requests.push({ body, key });
      if (body.operation === "call") return { payment_hash: `0x${"22".repeat(32)}`, fee: "0x1", status: "Created" };
      if (body.stage === "preview") return { preview: { amountCkb: "1", feeCkb: "0.00000001" }, confirmationNonce: "nonce-1", requiresEmailCode: false };
      if (body.stage === "send") return { payment_hash: `0x${"22".repeat(32)}`, fee: "0x1", status: "Created" };
      throw new Error("Unexpected managed request");
    },
  };
  const keyway = createManagedKeyWay({
    authToken: "session",
    ckbPublicKey: `0x02${"11".repeat(32)}`,
    approveFiberChannelOpen: () => true,
    approveFiberPayment: (preview) => { approvals.push(preview); return true; },
    apiClient: api as never,
  });
  const params = { invoice: "fibt-test", max_fee_amount: "0x64" as const };

  assert.deepEqual(await keyway.estimatePayment(params), { routable: true, fee: 1n });
  assert.deepEqual(requests[0].body, { operation: "call", method: "sendPayment", params: { ...params, dry_run: true } });
  await keyway.sendPayment(params);
  assert.equal(approvals.length, 1);
  assert.deepEqual(requests[2].body, { operation: "pay", method: "sendPayment", params, confirmationNonce: "nonce-1", stage: "send" });
  assert.match(requests[2].key ?? "", /^[0-9a-f-]{36}$/);
});

test("hosted payments stop when the app declines, and ask for the emailed code past the daily amount", async () => {
  const stages: string[] = [];
  let approve = false;
  const keyway = createManagedKeyWay({
    authToken: "session",
    ckbPublicKey: `0x02${"11".repeat(32)}`,
    approveFiberChannelOpen: () => true,
    approveFiberPayment: () => approve,
    requestEmailCode: async () => "123456",
    apiClient: {
      managedNode: async (_token: string, body: Record<string, unknown>) => {
        stages.push(`${body.stage}${body.emailCode ? `:${body.emailCode}` : ""}`);
        if (body.stage === "preview") return { preview: {}, confirmationNonce: "nonce-2", requiresEmailCode: true };
        return body.stage === "send" ? { payment_hash: "0x", status: "Created", fee: "0x0" } : { sent: true };
      },
    } as never,
  });
  await assert.rejects(() => keyway.sendPayment({ invoice: "fibt-test" }), /not approved/);
  assert.deepEqual(stages, ["preview"]);
  approve = true;
  await keyway.sendPayment({ invoice: "fibt-test" });
  assert.deepEqual(stages, ["preview", "preview", "request-email-code", "send:123456"]);
});

test("managed invoices go through the free-method call with the caller's parameters", async () => {
  const bodies: Array<Record<string, unknown>> = [];
  const keyway = createManagedKeyWay({
    authToken: "session",
    ckbPublicKey: `0x02${"11".repeat(32)}`,
    approveFiberChannelOpen: () => true,
    apiClient: {
      managedNode: async (_token: string, body: Record<string, unknown>) => {
        bodies.push(body);
        return { invoice_address: "fibt-test" };
      },
    } as never,
  });

  await keyway.newInvoice({ amount: "0x64", currency: "Fibt", description: "tea", expiry: "0xe10" });
  await keyway.newInvoice({ amount: "0x64", currency: "Fibt" });

  assert.deepEqual(bodies[0], { operation: "call", method: "newInvoice", params: { amount: "0x64", currency: "Fibt", description: "tea", expiry: "0xe10" } });
  assert.deepEqual(bodies[1], { operation: "call", method: "newInvoice", params: { amount: "0x64", currency: "Fibt" } });
});

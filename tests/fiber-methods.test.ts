import assert from "node:assert/strict";
import test from "node:test";
import { FIBER_METHODS, FREE_FIBER_METHODS, freeFiberParams } from "../src/sdk/browser/fiber-methods.ts";
import { listLoggedPayments } from "../src/sdk/browser/fiber-node.ts";
import { KeyWayError } from "../src/sdk/browser/keyway-error.ts";
import { managedNodeRequest } from "../src/server/managed-node.ts";

const hash = (byte: string) => `0x${byte.repeat(32)}`;

test("every Fiber method is classified, and the dangerous ones are blocked", () => {
  for (const method of ["openChannel", "acceptChannel", "abandonChannel"] as const) {
    assert.equal(FIBER_METHODS[method].kind, "blocked");
  }
  assert.equal(FIBER_METHODS.sendPayment.kind, "payment");
  assert.equal(FIBER_METHODS.shutdownChannel.kind, "approve");
  assert.deepEqual([...FREE_FIBER_METHODS].sort(), [
    "buildRouter", "cancelInvoice", "getInvoice", "getPayment", "graphChannels", "graphNodes",
    "listChannels", "listPayments", "listPeers", "newInvoice", "nodeInfo", "parseInvoice", "settleInvoice",
  ]);
});

test("free-method checks refuse everything that isn't free, known and well-formed", () => {
  for (const method of ["sendPayment", "abandonChannel", "openChannel", "invokeCommand", "watchtower_create", "__proto__"]) {
    assert.throws(() => freeFiberParams(method, {}, "testnet"), (error: unknown) => error instanceof KeyWayError && error.code === "UNSUPPORTED_METHOD");
  }
  assert.throws(() => freeFiberParams("listChannels", { include_closed: true, extra: 1 }, "testnet"), /Unsupported parameter: extra/);
  assert.throws(() => freeFiberParams("graphNodes", { limit: "0x101" }, "testnet"), /at most 256/);
  assert.throws(() => freeFiberParams("getPayment", {}, "testnet"), /payment_hash is required/);
  assert.throws(() => freeFiberParams("parseInvoice", { invoice: "fibb1mainnet" }, "testnet"), /testnet Fiber invoice/);
});

test("invoices: currency and expiry default, hold invoices allowed, fallback addresses refused", () => {
  assert.deepEqual(freeFiberParams("newInvoice", { amount: "0x64" }, "testnet"), { currency: "Fibt", expiry: "0x15180", amount: "0x64" });
  assert.deepEqual(freeFiberParams("newInvoice", { amount: "0x64", payment_hash: hash("ab"), expiry: "0xe10" }, "testnet"), {
    currency: "Fibt", expiry: "0xe10", amount: "0x64", payment_hash: hash("ab"),
  });
  assert.throws(() => freeFiberParams("newInvoice", { amount: "0x64", fallback_address: "ckt1q" }, "testnet"), /fallback address/);
  assert.throws(() => freeFiberParams("newInvoice", { amount: "0x64", currency: "Fibb" }, "testnet"), /currency must be one of: Fibt/);
  assert.throws(() => freeFiberParams("newInvoice", { amount: "0x64", payment_hash: hash("ab"), payment_preimage: hash("cd") }, "testnet"), /not both/);
  assert.deepEqual(freeFiberParams("settleInvoice", { payment_hash: hash("ab"), payment_preimage: hash("cd") }, "testnet"), {
    payment_hash: hash("ab"), payment_preimage: hash("cd"),
  });
});

test("hosted nodes run free methods by their Fiber RPC name and hide the host's internals", async () => {
  const calls: Array<{ method: string; params: unknown[] }> = [];
  const node = {
    nodeInfo: async () => ({ pubkey: "0x02", addresses: ["/ip4/10.0.0.1/tcp/8228"], default_funding_lock_script: { args: "0x" }, version: "0.9.1" }),
    call: async (method: string, params: unknown[]) => { calls.push({ method, params }); return { ok: true }; },
  };
  assert.deepEqual(await managedNodeRequest("user-1", { operation: "call", method: "nodeInfo" }, node as never), { pubkey: "0x02", version: "0.9.1" });
  await managedNodeRequest("user-1", { operation: "call", method: "listPayments", params: { status: "Success", limit: "0xa" } }, node as never);
  await managedNodeRequest("user-1", { operation: "call", method: "listPeers" }, node as never);
  assert.deepEqual(calls, [
    { method: "list_payments", params: [{ status: "Success", limit: "0xa" }] },
    { method: "list_peers", params: [] },
  ]);
  await assert.rejects(() => managedNodeRequest("user-1", { operation: "call", method: "abandonChannel", params: { channel_id: hash("aa") } }, node as never), /isn't available through KeyWay/);
  assert.equal(calls.length, 2, "refused methods never reach the node");
});

test("browser payment history pages through the SDK's own log", async () => {
  const hashes = [hash("03"), hash("02"), hash("01")];
  const status: Record<string, string> = { [hash("03")]: "Success", [hash("02")]: "Failed", [hash("01")]: "Success" };
  const getPayment = async ({ payment_hash }: { payment_hash: string }) => ({ payment_hash, status: status[payment_hash] }) as never;
  const first = await listLoggedPayments(hashes, { limit: "0x2" }, getPayment);
  assert.deepEqual(first.payments.map((payment: { payment_hash: string }) => payment.payment_hash), [hash("03"), hash("02")]);
  const next = await listLoggedPayments(hashes, { after: first.last_cursor }, getPayment);
  assert.deepEqual(next.payments.map((payment: { payment_hash: string }) => payment.payment_hash), [hash("01")]);
  const successes = await listLoggedPayments(hashes, { status: "Success" }, getPayment);
  assert.equal(successes.payments.length, 2);
});

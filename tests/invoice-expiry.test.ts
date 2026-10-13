import assert from "node:assert/strict";
import test from "node:test";
import { freeFiberParams } from "../src/sdk/browser/fiber-methods.ts";
import { DEFAULT_INVOICE_EXPIRY } from "../src/sdk/browser/invoice-expiry.ts";

test("invoices default to a 24 hour expiry in Fiber's seconds unit, in both node modes", () => {
  assert.equal(DEFAULT_INVOICE_EXPIRY, "0x15180");
  assert.equal(BigInt(DEFAULT_INVOICE_EXPIRY), 24n * 60n * 60n);
  // Both modes build invoice parameters through the shared method table.
  assert.equal(freeFiberParams("newInvoice", { amount: "0x64" }, "testnet").expiry, "0x15180");
  assert.equal(freeFiberParams("newInvoice", { amount: "0x64", expiry: "0xe10" }, "testnet").expiry, "0xe10");
});

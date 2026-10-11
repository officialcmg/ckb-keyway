import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { DEFAULT_INVOICE_EXPIRY, withDefaultInvoiceExpiry } from "../src/sdk/browser/invoice-expiry.ts";

test("browser invoices default to a 24 hour expiry in Fiber's seconds unit", () => {
  assert.equal(DEFAULT_INVOICE_EXPIRY, "0x15180");
  assert.equal(BigInt(DEFAULT_INVOICE_EXPIRY), 24n * 60n * 60n);
  assert.deepEqual(withDefaultInvoiceExpiry({ amount: "0x64", currency: "Fibt" }), {
    amount: "0x64",
    currency: "Fibt",
    expiry: "0x15180",
  });
  assert.equal(withDefaultInvoiceExpiry({ amount: "0x64", currency: "Fibt", expiry: "0xe10" }).expiry, "0xe10");
});

test("browser mode applies the default expiry before calling the node", async () => {
  const source = await readFile(new URL("../src/sdk/browser/create-keyway.ts", import.meta.url), "utf8");
  assert.match(source, /newInvoice: \(params: NewInvoiceParams\) => node\.newInvoice\(withDefaultInvoiceExpiry\(params\)\)/);
});

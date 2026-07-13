import assert from "node:assert/strict";
import test from "node:test";
import { friendlyKeyWayError } from "../src/sdk/browser/friendly-error.ts";

test("maps common Fiber failures to actionable guidance", () => {
  assert.equal(
    friendlyKeyWayError("Failed to build route, insufficient liquidity"),
    "No Fiber route currently has enough liquidity for this payment. Try a smaller amount or another receiver.",
  );
  assert.equal(
    friendlyKeyWayError("Feature not enabled: allow_self_payment is not enabled"),
    "This invoice belongs to the same wallet. Use an invoice from another Fiber receiver.",
  );
  assert.equal(
    friendlyKeyWayError("Invoice has expired"),
    "This Fiber invoice has expired. Ask the receiver to create a new one.",
  );
});

test("preserves unknown errors for diagnostics", () => {
  assert.equal(friendlyKeyWayError("Unexpected peer response"), "Unexpected peer response");
});

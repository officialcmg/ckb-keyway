import assert from "node:assert/strict";
import test from "node:test";
import { formatDuration, settingText } from "../src/sdk/react/signing-modals.tsx";

const RUSD = "0x45b32a2bc4285d0a09678eb11960ddc8707bc2779887a09d482e9bfe9a2cdf52";

test("channel settings read in people's units", () => {
  assert.equal(settingText("tlc_expiry_delta", "0x5265c00"), "24 hours");
  assert.equal(settingText("tlc_expiry_delta", "5400000"), "1 hour 30 minutes");
  assert.equal(formatDuration(45_000n), "45 seconds");
  assert.equal(formatDuration(500n), "500 ms");
  assert.equal(settingText("tlc_minimum_value", "0x5f5e100"), "1 CKB");
  assert.equal(settingText("tlc_minimum_value", "0x2faf080", RUSD), "0.5 RUSD");
  assert.equal(settingText("tlc_fee_proportional_millionths", "0x3e8"), "0.1%");
  assert.equal(settingText("enabled", "false"), "off");
  assert.equal(settingText("tlc_minimum_value", undefined), "—");
});

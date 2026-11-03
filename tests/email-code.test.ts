import assert from "node:assert/strict";
import test from "node:test";
import { canRetryCode, isRequestExpired, withEmailCode, type RequestEmailCode } from "../src/sdk/browser/email-code.ts";

const WRONG = "That email code isn't right";
const EXPIRED = "This request expired. Start again.";

test("a prompt can check codes itself and stays the same prompt after a wrong one", async () => {
  const tried: string[] = [];
  const seen: Array<{ sentTo?: string; error?: string }> = [];
  const prompt: RequestEmailCode = async ({ verify, sentTo, error }) => {
    seen.push({ sentTo, error });
    await assert.rejects(verify!("000000"), new RegExp(WRONG));
    await verify!("482913");
    return "482913";
  };
  const result = await withEmailCode(prompt, "transaction", async () => ({ sent: true, sentTo: "ana@acmepay.example" }), async (code) => {
    tried.push(code);
    if (code !== "482913") throw new Error(WRONG);
    return "signed";
  });
  assert.equal(result, "signed");
  assert.deepEqual(tried, ["000000", "482913"], "the accepted code isn't submitted twice");
  assert.deepEqual(seen, [{ sentTo: "ana@acmepay.example", error: undefined }], "one prompt, showing where the code went");
});

test("prompts that only return a code keep working, and see the wrong code on the next ask", async () => {
  const codes = ["000000", "482913"];
  const errors: Array<string | undefined> = [];
  const result = await withEmailCode(async ({ error }) => { errors.push(error); return codes.shift(); }, "payment", async () => undefined, async (code) => {
    if (code === "000000") throw new Error(WRONG);
    return code;
  });
  assert.equal(result, "482913");
  assert.deepEqual(errors, [undefined, WRONG]);
});

test("an expired request ends the flow with its own message, not as a cancel", async () => {
  await assert.rejects(withEmailCode(async ({ verify }) => {
    await assert.rejects(verify!("482913"), /expired/);
    return undefined;
  }, "recovery", async () => undefined, async () => { throw new Error(EXPIRED); }), new RegExp(EXPIRED));
  await assert.rejects(withEmailCode(async ({ resend }) => {
    await assert.rejects(resend(), /expired/);
    return undefined;
  }, "recovery-backup", (() => { let sends = 0; return async () => { if (sends++) throw new Error(EXPIRED); }; })(), async () => "never"), new RegExp(EXPIRED));
});

test("a check still running when the prompt closes decides the outcome", async () => {
  let finish!: () => void;
  const result = await withEmailCode(async ({ verify }) => {
    void verify!("482913");
    return undefined;
  }, "transaction", async () => undefined, () => new Promise<string>((resolve) => { finish = () => resolve("signed"); setTimeout(finish, 20); }));
  assert.equal(result, "signed", "a code accepted after the prompt closed still returns the signed result");
});

test("settings pass the response that already sent the first code", async () => {
  let sends = 0;
  const seen: Array<string | undefined> = [];
  await withEmailCode(async ({ sentTo }) => { seen.push(sentTo); return "482913"; }, "settings", async () => { sends++; }, async () => "ok", { sentTo: "ana@acmepay.example" });
  assert.equal(sends, 0);
  assert.deepEqual(seen, ["ana@acmepay.example"]);
});

test("classifies refusals the user can fix in the same prompt", () => {
  for (const message of [WRONG, "Enter the six-digit code from your email", "The email code has expired. Request a new one", "Too many wrong codes. Request a new one"]) assert.equal(canRetryCode(message), true, message);
  for (const message of [EXPIRED, "Lit signature does not match the KeyWay wallet"]) assert.equal(canRetryCode(message), false, message);
  assert.equal(isRequestExpired(EXPIRED), true);
  assert.equal(isRequestExpired("The email code has expired. Request a new one"), false);
});

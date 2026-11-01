import assert from "node:assert/strict";
import test from "node:test";
import { createOtpEmailTemplate, createRecoveryNoticeEmailTemplate } from "../src/server/email-template";

test("OTP email keeps the code selectable, prominent, and paired with a plaintext alternative", () => {
  const email = createOtpEmailTemplate("My Fiber App", "{{ STYTCH_VARIABLE }}");
  assert.match(email.html, /font-size:40px/);
  assert.match(email.html, /{{ STYTCH_VARIABLE }}/);
  assert.match(email.plaintext, /expires in 10 minutes/);
  assert.equal(email.subject, "Your login code for My Fiber App");
  assert.doesNotMatch(email.html, /<script|<img|<form/);
});

test("application names cannot inject email markup", () => {
  const email = createOtpEmailTemplate('<img src=x onerror="alert(1)">', "123456");
  assert.doesNotMatch(email.html, /<img/);
  assert.match(email.html, /&lt;img/);
  assert.throws(() => createOtpEmailTemplate("", "123456"));
  assert.throws(() => createOtpEmailTemplate("App", ""));
});

test("recovery notice gives the full address, the backups and the rescue page, escaped", () => {
  const address = `ckt1${"q".repeat(100)}`;
  const email = createRecoveryNoticeEmailTemplate("<b>App</b>", { heading: "Account recovery is on", address, backups: ["EVM wallet 0xabc", "<script>"], network: "CKB testnet" });
  assert.equal(email.subject, "Account recovery is on in <b>App</b>");
  assert.ok(email.plaintext.includes(address) && email.html.includes(address));
  assert.match(email.plaintext, /https:\/\/ckbkeyway\.dev\/rescue/);
  assert.doesNotMatch(email.html, /<script>|<b>App/);
  assert.throws(() => createRecoveryNoticeEmailTemplate("App", { heading: "x", address: "not an address", backups: [], network: "CKB testnet" }));
});

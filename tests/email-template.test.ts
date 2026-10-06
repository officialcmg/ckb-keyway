import assert from "node:assert/strict";
import test from "node:test";
import { createOtpEmailTemplate } from "../src/server/email-template";

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

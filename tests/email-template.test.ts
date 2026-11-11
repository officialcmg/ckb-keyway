import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { createConfirmationEmailTemplate, createOtpEmailTemplate, createRecoveryNoticeEmailTemplate } from "../src/server/email-template";
import { previewSummaryLines, type TransactionPreview } from "../src/server/transaction-policy.ts";

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

const client = new ccc.ClientPublicTestnet();
const address = (byte: number) => ccc.Address.fromScript(ccc.Script.from({
  codeHash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", hashType: "type", args: `0x${byte.toString(16).padStart(2, "0").repeat(20)}`,
}), client).toString();

function preview(recipients: number): TransactionPreview {
  return {
    network: "CKB testnet", sendingCkb: "1100", receivingCkb: "0", feeCkb: "0.0001",
    tokens: [{ id: "0x55555555…5555", asset: `0x${"55".repeat(32)}`, standard: "xUDT", amount: "-1000", amountText: `-1000 of token 0x${"55".repeat(32)}` }],
    nfts: [], dao: [],
    recipients: Array.from({ length: recipients }, (_, index) => ({ address: address(index + 1), kind: "wallet" as const, walletType: "standard", ckb: "100", tokens: [], nfts: [] })),
    unrecognized: [{ codeHash: "0x9f9f9f9f…9f9f", cells: 1 }],
    otherSigners: 0, details: { inputs: [], outputs: [] }, transactionHash: `0x${"ab".repeat(32)}`,
  };
}

test("the confirmation email never drops what a transaction does to the account's assets", () => {
  const lines = previewSummaryLines(preview(11));
  const email = createConfirmationEmailTemplate("Acme Pay", "123456", "Confirm a transaction", lines);
  for (const body of [email.plaintext, email.html]) {
    assert.ok(body.includes(`Token -1000 of token 0x${"55".repeat(32)} (xUDT 0x${"55".repeat(32)})`));
    assert.match(body, /Unrecognized script 0x9f9f9f9f…9f9f/);
    // Whatever doesn't fit is said to be missing, not silently left out.
    assert.match(body, /and \d+ more/);
  }
  const short = createConfirmationEmailTemplate("Acme Pay", "123456", "Confirm a transaction", previewSummaryLines(preview(1)));
  assert.doesNotMatch(short.plaintext, /more/);
});

test("the confirmation email shows each recipient's whole address", () => {
  const near = [address(1), address(2)];
  // Two addresses with the same lock differ only in the middle and the checksum at the end.
  assert.equal(near[0].slice(0, 12), near[1].slice(0, 12));
  const lines = previewSummaryLines(preview(2));
  const email = createConfirmationEmailTemplate("Acme Pay", "123456", "Confirm a transaction", lines);
  for (const full of near) {
    assert.ok(lines.some((line) => line.includes(full)), full);
    assert.ok(email.plaintext.includes(full) && email.html.includes(full), full);
  }
});

test("a recipient line too long for the email keeps its amount and is marked as cut", () => {
  const long = ccc.Address.fromScript(ccc.Script.from({
    codeHash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", hashType: "type", args: `0x${"cd".repeat(200)}`,
  }), client).toString();
  const base = preview(1);
  const lines = previewSummaryLines({ ...base, recipients: [{ ...base.recipients[0], address: long, ckb: "4321" }] });
  const email = createConfirmationEmailTemplate("Acme Pay", "123456", "Confirm a transaction", lines);
  const shown = email.plaintext.split("\n").find((line) => line.includes(long.slice(0, 40)));
  assert.ok(shown, "the recipient line is in the email");
  assert.match(shown, /4321 CKB/);
  assert.ok(shown.endsWith("…") && shown.length === 240, shown);
  assert.ok(email.html.includes(shown));
  // A line that fits is left as it is.
  const short = createConfirmationEmailTemplate("Acme Pay", "123456", "Confirm a transaction", previewSummaryLines(preview(1)));
  assert.doesNotMatch(short.plaintext, /…$/m);
});

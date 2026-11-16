import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { confirmationEmailFits, createConfirmationEmailTemplate, createOtpEmailTemplate, createRecoveryNoticeEmailTemplate } from "../src/server/email-template";
import { previewSummaryLines, type TransactionPreview } from "../src/server/transaction-policy.ts";
import { recoveryLines } from "../src/server/recovery.ts";

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
    nfts: [], dao: [], cellsSpent: [],
    recipients: Array.from({ length: recipients }, (_, index) => ({ address: address(index + 1), kind: "wallet" as const, walletType: "standard", ckb: "100", tokens: [], nfts: [], cells: [] })),
    unrecognized: [{ codeHash: `0x${"9f".repeat(32)}`, hashType: "type", cells: 1 }],
    otherSigners: 0, details: { inputs: [], outputs: [] }, transactionHash: `0x${"ab".repeat(32)}`,
  };
}

test("the confirmation email never drops an asset or a recipient, however they're ordered", () => {
  // Junk tokens first, as an attacker ordering the outputs would put them, then thirteen recipients.
  const base = preview(13);
  const junk = Array.from({ length: 12 }, (_, index) => {
    const asset = `0x${(index + 0x30).toString(16).repeat(32)}`;
    return { id: "", asset, standard: "xUDT" as const, amount: "-1", amountText: `-1 of token ${asset}` };
  });
  const lines = previewSummaryLines({ ...base, tokens: [...junk, ...base.tokens] });
  const email = createConfirmationEmailTemplate("Acme Pay", "123456", "Confirm a transaction", lines);
  for (const body of [email.plaintext, email.html]) {
    for (const token of [...junk, ...base.tokens]) assert.ok(body.includes(token.asset), token.asset);
    for (const recipient of base.recipients) assert.ok(body.includes(`100 CKB to ${recipient.address}`), recipient.address);
    assert.ok(body.includes(`Unrecognized script 0x${"9f".repeat(32)} (type, 1 cells)`));
    assert.doesNotMatch(body, /more not shown/);
  }
  for (const line of lines) assert.ok(email.plaintext.includes(`${line}\n`), line);
});

test("a summary too long for one email gets no code, rather than a code for what the email doesn't show", () => {
  const lines = previewSummaryLines(preview(400));
  assert.equal(confirmationEmailFits("Acme Pay", "Confirm a transaction", lines), false);
  assert.throws(() => createConfirmationEmailTemplate("Acme Pay", "123456", "Confirm a transaction", lines), /too much to show in one confirmation email/);
  assert.equal(confirmationEmailFits("Acme Pay", "Confirm a transaction", previewSummaryLines(preview(13))), true);
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

test("a recipient with an unusually long address is shown whole, never cut", () => {
  const long = ccc.Address.fromScript(ccc.Script.from({
    codeHash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", hashType: "type", args: `0x${"cd".repeat(200)}`,
  }), client).toString();
  const base = preview(1);
  const lines = previewSummaryLines({ ...base, recipients: [{ ...base.recipients[0], address: long, ckb: "4321" }] });
  const email = createConfirmationEmailTemplate("Acme Pay", "123456", "Confirm a transaction", lines);
  assert.ok(email.plaintext.includes(`4321 CKB to ${long} (wallet)\n`));
  assert.ok(email.html.includes(`4321 CKB to ${long} (wallet)`));
  assert.doesNotMatch(email.plaintext, /…/);
});

test("turning recovery on with all 8 backups emails every backup and every amount", () => {
  const backups = Array.from({ length: 8 }, (_, index) => ({ kind: "evm" as const, address: `0x${(index + 1).toString(16).padStart(2, "0").repeat(20)}`, label: `EVM wallet 0x${(index + 1).toString(16).padStart(2, "0").repeat(20)}` }));
  const lines = recoveryLines({
    network: "CKB testnet", newAddress: address(9), legacyAddress: address(10), backups,
    adminListCkb: "165", minimumCellCkb: "95", tokenCellsExtraCkb: "0", lockedCkb: "165", feeCkb: "0.00000981", movedCkb: "9802.99999019",
    tokens: [], cellsLeft: 0, transactionHash: `0x${"12".repeat(32)}`,
  });
  const email = createConfirmationEmailTemplate("Acme Pay", "123456", "Turn on account recovery", lines);
  for (const line of lines) assert.ok(email.plaintext.includes(`${line}\n`), line);
  assert.doesNotMatch(email.plaintext, /more not shown/);
});

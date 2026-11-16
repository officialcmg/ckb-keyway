import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { formatDuration, KeyWayPeerModal, KeyWayTransactionModal, settingText } from "../src/sdk/react/signing-modals.tsx";
import type { TransactionPreview } from "../src/sdk/browser/keyway-signer.ts";

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

test("the transaction dialog shows each recipient's whole address, not just its start and checksum", () => {
  const address = "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqgpqyqszqgpqyqszqgpqyqszqgpqyqszqg4pq2v9";
  const preview = {
    network: "CKB testnet", sendingCkb: "100", receivingCkb: "0", feeCkb: "0.00001", tokens: [], nfts: [], dao: [], cellChanges: [],
    recipients: [{ address, kind: "wallet", walletType: "standard", ckb: "100", tokens: [], nfts: [], cells: [] }],
    unrecognized: [], otherSigners: 0, details: { inputs: [], outputs: [] }, transactionHash: `0x${"ab".repeat(32)}`, requiresEmailCode: false,
  } as unknown as TransactionPreview;
  const html = renderToStaticMarkup(createElement(KeyWayTransactionModal, { theme: "light", appName: "Acme Pay", preview, answer: () => undefined }));
  // The main rows, before the collapsed details.
  const rows = html.slice(0, html.indexOf("<details"));
  assert.ok(rows.includes(address));
});

test("the transaction dialog names NFTs, tokens and other cells KeyWay can't name by their whole ID", () => {
  const twinA = "0xbdb681eee837511ca24e81fff9e2476fbcb402d5ef264a31c4fa30ef01da72b5";
  const twinB = "0xbdb68117fdbb5becaaeaaa710e97c5e02cf34fa8eac6abafea610c90224472b5";
  const sporeId = `0x${"5e".repeat(14)}${"00".repeat(4)}${"5e".repeat(14)}`;
  const typeHash = `0x${"7e".repeat(32)}`;
  const spent = `0x${"8f".repeat(32)}`;
  const changedType = `0x${"9e".repeat(32)}`;
  const gotType = `0x${"ad".repeat(32)}`;
  const address = "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqgpqyqszqgpqyqszqgpqyqszqgpqyqszqg4pq2v9";
  const preview = {
    network: "CKB testnet", sendingCkb: "0", receivingCkb: "0", feeCkb: "0.00001", dao: [], cellChanges: [{ typeHash: spent, given: 1, changed: 0, received: 0 }, { typeHash: changedType, given: 0, changed: 2, received: 0 }, { typeHash: gotType, given: 0, changed: 0, received: 1 }],
    tokens: [{ id: "0xbdb681…72b5", asset: twinA, standard: "xUDT", amount: "-1000" }, { id: "0xbdb681…72b5", asset: twinB, standard: "xUDT", amount: "-7" }],
    nfts: [{ kind: "Spore", id: sporeId, change: "sent" }],
    recipients: [{ address, kind: "wallet", walletType: "standard", ckb: "600", tokens: [{ id: "0xbdb681…72b5", asset: twinA, amount: "1000" }, { id: "0xbdb681…72b5", asset: twinB, amount: "7" }], nfts: [`Spore ${sporeId}`], cells: [{ typeHash, cells: 2 }] }],
    unrecognized: [], otherSigners: 0, details: { inputs: [], outputs: [] }, transactionHash: `0x${"ab".repeat(32)}`, requiresEmailCode: false,
  } as unknown as TransactionPreview;
  const html = renderToStaticMarkup(createElement(KeyWayTransactionModal, { theme: "light", appName: "Acme Pay", preview, answer: () => undefined }));
  const rows = html.slice(0, html.indexOf("<details"));
  for (const id of [twinA, twinB, sporeId, spent, changedType, gotType]) assert.ok(rows.includes(id), id);
  for (const label of ["You give up 1 cell of type", "You change the data of 2 cells of type", "You get 1 cell of type"]) assert.ok(rows.includes(label), label);
  // Every typed cell the recipient gets, by its whole type script hash.
  assert.ok(rows.includes(`1000 of token ${twinA} · 7 of token ${twinB} · Spore ${sporeId} · 2 cells of type ${typeHash}`), rows);
  assert.doesNotMatch(rows, /…/);
});

test("the peer dialog shows the whole node ID", () => {
  const pubkey = `0x03${"4c".repeat(16)}${"00".repeat(16)}`;
  const html = renderToStaticMarkup(createElement(KeyWayPeerModal, { theme: "light", appName: "Acme Pay", preview: { action: "connect", pubkey, openChannels: 0 }, answer: () => undefined }));
  assert.ok(html.includes(pubkey), html);
  assert.doesNotMatch(html, /…/);
});

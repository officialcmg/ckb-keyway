import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { formatDuration, KeyWayTransactionModal, settingText } from "../src/sdk/react/signing-modals.tsx";
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
    network: "CKB testnet", sendingCkb: "100", receivingCkb: "0", feeCkb: "0.00001", tokens: [], nfts: [], dao: [],
    recipients: [{ address, kind: "wallet", walletType: "standard", ckb: "100", tokens: [], nfts: [] }],
    unrecognized: [], otherSigners: 0, details: { inputs: [], outputs: [] }, transactionHash: `0x${"ab".repeat(32)}`, requiresEmailCode: false,
  } as unknown as TransactionPreview;
  const html = renderToStaticMarkup(createElement(KeyWayTransactionModal, { theme: "light", appName: "Acme Pay", preview, answer: () => undefined }));
  // The main rows, before the collapsed details.
  const rows = html.slice(0, html.indexOf("<details"));
  assert.ok(rows.includes(address));
});

test("the transaction dialog names NFTs and tokens KeyWay can't name by their whole ID", () => {
  const twinA = "0xbdb681eee837511ca24e81fff9e2476fbcb402d5ef264a31c4fa30ef01da72b5";
  const twinB = "0xbdb68117fdbb5becaaeaaa710e97c5e02cf34fa8eac6abafea610c90224472b5";
  const sporeId = `0x${"5e".repeat(14)}${"00".repeat(4)}${"5e".repeat(14)}`;
  const address = "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqgpqyqszqgpqyqszqgpqyqszqgpqyqszqg4pq2v9";
  const preview = {
    network: "CKB testnet", sendingCkb: "0", receivingCkb: "0", feeCkb: "0.00001", dao: [],
    tokens: [{ id: "0xbdb681…72b5", asset: twinA, standard: "xUDT", amount: "-1000" }, { id: "0xbdb681…72b5", asset: twinB, standard: "xUDT", amount: "-7" }],
    nfts: [{ kind: "Spore", id: sporeId, change: "sent" }],
    recipients: [{ address, kind: "wallet", walletType: "standard", ckb: "600", tokens: [{ id: "0xbdb681…72b5", asset: twinA, amount: "1000" }, { id: "0xbdb681…72b5", asset: twinB, amount: "7" }], nfts: [`Spore ${sporeId}`] }],
    unrecognized: [], otherSigners: 0, details: { inputs: [], outputs: [] }, transactionHash: `0x${"ab".repeat(32)}`, requiresEmailCode: false,
  } as unknown as TransactionPreview;
  const html = renderToStaticMarkup(createElement(KeyWayTransactionModal, { theme: "light", appName: "Acme Pay", preview, answer: () => undefined }));
  const rows = html.slice(0, html.indexOf("<details"));
  for (const id of [twinA, twinB, sporeId]) assert.ok(rows.includes(id), id);
  assert.ok(rows.includes(`1000 of token ${twinA} · 7 of token ${twinB} · Spore ${sporeId}`), rows);
  assert.doesNotMatch(rows, /…/);
});

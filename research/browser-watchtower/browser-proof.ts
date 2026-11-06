// Live proof that a real browser node (fiber-wasm in headless Chromium) registers its channel with KeyWay's
// watchtower through the SDK's bridge, store and remote queue, and that the watchtower keeps following the
// channel after the tab is closed. See README.md in this folder.
//
//   (relay-and-watch.ts running; peer node P listening on ws://127.0.0.1:8258)
//   PROOF=… node --import tsx research/browser-watchtower/browser-proof.ts step
//
// Steps: start | pay | close-tab. The page's state lives in a persistent Chromium profile under $PROOF/chrome.
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import * as ccc from "@ckb-ccc/core";
import { deriveSettlementKey } from "../../src/sdk/browser/settlement-key.ts";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const { build } = require("esbuild");
const repo = new URL("../..", import.meta.url).pathname;
const PROOF = process.env.PROOF!;
const evidence = `${PROOF}/evidence`;
const log = (line: string) => {
  const stamped = `${new Date().toISOString().replace("T", " ").slice(0, 19)} ${line}`;
  console.log(stamped);
  appendFileSync(`${evidence}/browser.log`, stamped + "\n");
};
const P_RPC = "http://127.0.0.1:8257";
const rpc = async (method: string, params: unknown[] = []) => {
  const body = await (await fetch(P_RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id: 1, jsonrpc: "2.0", method, params }) })).json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
};

const keyFile = `${PROOF}/browser-fiber-key`;
if (!existsSync(keyFile)) writeFileSync(keyFile, randomBytes(32).toString("hex"), { mode: 0o600 });
const fiberKey = `0x${readFileSync(keyFile, "utf8").trim()}`;
const client = new ccc.ClientPublicTestnet();
const nodeSigner = new ccc.SignerCkbPrivateKey(client, ccc.hexFrom(await deriveSettlementKey(ccc.bytesFrom(fiberKey))));
const nodeAddress = await nodeSigner.getRecommendedAddress();

const step = process.argv[2];
if (step === "fund") {
  const keys = JSON.parse(readFileSync(`${PROOF}/keys.json`, "utf8"));
  const from = new ccc.SignerCkbPrivateKey(client, `0x${keys.V}`);
  const tx = ccc.Transaction.from({ outputs: [{ capacity: ccc.fixedPointFrom(800), lock: (await nodeSigner.getRecommendedAddressObj()).script }], outputsData: ["0x"] });
  await tx.completeInputsByCapacity(from);
  await tx.completeFeeBy(from, 1000);
  log(`funded the browser node's CKB key ${nodeAddress}: ${await from.sendTransaction(tx)}`);
  process.exit(0);
}

// Serve the page from localhost (a secure context) with the isolation headers fiber-wasm needs.
const bundle = await build({
  entryPoints: [`${repo}/research/browser-watchtower/browser-page.ts`], absWorkingDir: repo, bundle: true, write: false,
  platform: "browser", format: "iife", define: { "process.env.KEYWAY_API_TARGET": '"production"', "process.env.NODE_ENV": '"production"' },
});
const isolation = { "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp" };
const server = createServer((request, response) => {
  if (request.url === "/page.js") return void response.writeHead(200, { ...isolation, "content-type": "text/javascript" }).end(Buffer.from(bundle.outputFiles[0].contents));
  response.writeHead(200, { ...isolation, "content-type": "text/html" }).end('<!doctype html><title>proof</title><script src="/page.js"></script>');
});
await new Promise<void>((resolve) => server.listen(18310, "127.0.0.1", resolve));
const proxy = process.env.HTTPS_PROXY ? { server: process.env.HTTPS_PROXY, bypass: "127.0.0.1,localhost" } : undefined;
const context = await chromium.launchPersistentContext(`${PROOF}/chrome`, { headless: true, ignoreHTTPSErrors: true, ...(proxy ? { proxy } : {}) });
const page = context.pages()[0] ?? await context.newPage();
const consoleLog = `${evidence}/browser-console.log`;
const stamp = (source: string, text: string) => appendFileSync(consoleLog, `${new Date().toISOString()} [${source}] ${text.replace(/\x1b\[[0-9;]*m/g, "")}\n`);
page.on("console", (m: { type(): string; text(): string }) => stamp(`page:${m.type()}`, m.text()));
page.on("pageerror", (e: Error) => stamp("pageerror", String(e?.stack ?? e)));
page.on("worker", (w: { on(e: string, f: (m: { type(): string; text(): string }) => void): void }) => w.on("console", (m) => stamp(`worker:${m.type()}`, m.text())));
await page.goto("http://localhost:18310/");
const info = await page.evaluate(([key, relay]: string[]) => (window as any).proof.start(key, relay), [fiberKey, "http://127.0.0.1:18300/sdk"]);
log(`browser node running: ${info.pubkey ?? info.node_id}; CKB key ${nodeAddress}`);
const browserPubkey = info.pubkey ?? info.node_id;
const call = (method: string, params?: unknown) => page.evaluate(async ([m, p]: [string, unknown]) => {
  const node = (window as any).node;
  const result = await node[m](p);
  return JSON.parse(JSON.stringify(result ?? null, (_k, v) => typeof v === "bigint" ? `0x${v.toString(16)}` : v));
}, [method, params]);
const pInfo = await rpc("node_info");
await call("connectPeer", { address: "/ip4/127.0.0.1/tcp/8258/ws" });
await new Promise((r) => setTimeout(r, 3000));

const channels = async () => (await call("listChannels", {}))?.channels ?? [];
async function waitReady() {
  for (let i = 0; i < 120; i++) {
    // The peer's view: the browser node's own list can lag while it is busy with gossip.
    const peers = (await rpc("list_channels", [{}])).channels as any[];
    const ready = peers.find((c) => c.state?.state_name === "ChannelReady" && c.pubkey === browserPubkey);
    if (ready) return ready;
    await new Promise((r) => setTimeout(r, 5000));
  }
  throw new Error("channel not ready");
}

if (step === "start") {
  if ((await channels()).length === 0) {
    const opened = await call("openChannel", { pubkey: pInfo.pubkey, funding_amount: "0xba43b7400", public: false });
    log(`browser node opened a 500 CKB channel to the peer: ${JSON.stringify(opened)}`);
  }
  const ready = await waitReady();
  log(`channel ${ready.channel_id} ready (funding ${ready.channel_outpoint})`);
}
if (step === "pay") {
  const ready = await waitReady();
  const invoice = await rpc("new_invoice", [{ amount: "0x2540be400", currency: "Fibt", description: "browser watchtower proof", expiry: "0xe10", hash_algorithm: "sha256" }]);
  const payment = await call("sendPayment", { invoice: invoice.invoice_address });
  log(`browser node paid the peer 100 CKB: ${payment?.payment_hash} on channel ${ready.channel_id}`);
  for (let i = 0; i < 30; i++) {
    const pending = await page.evaluate(() => (window as any).remote.pending());
    if (pending === 0) break;
    await new Promise((r) => setTimeout(r, 2000));
  }
  await new Promise((r) => setTimeout(r, 5000));
  log(`remote watchtower queue after the payment: ${await page.evaluate(() => (window as any).remote.pending())} channel(s) pending`);
}
if (step === "close-tab") {
  log(`closing the tab (pending updates: ${await page.evaluate(() => (window as any).remote.pending())})`);
}
await page.close();
await context.close();
server.close();
log(`tab closed (step ${step})`);
void browserPubkey;
process.exit(0);

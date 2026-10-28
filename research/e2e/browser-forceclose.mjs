// Force-close settlement proof, live on testnet against the production API: the new SDK (local build, served
// as the www origin) exposes `useFiber().node` with the shared method table in both node modes.
import { createHash, randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import { mkdirSync } from "node:fs";
import { DEMO_APP_ID, EVIDENCE, json, launch, markSeen, newMailbox, nextCode } from "./lib.mjs";

const repo = new URL("../..", import.meta.url).pathname.replace(/\/$/, "");
mkdirSync(EVIDENCE, { recursive: true, mode: 0o700 });
const { build } = createRequire(`${repo}/`)("esbuild");
const origin = "https://www.ckbkeyway.dev";
const appId = DEMO_APP_ID;
const log = (...args) => console.log(new Date().toISOString().slice(11, 19), ...args);
const CKB = 100_000_000n;
const hex = (value) => `0x${BigInt(value).toString(16)}`;
const evidence = [];
const record = (line) => { evidence.push(line); log("PASS", line); };

const bundle = await build({
  entryPoints: [`${repo}/tests/fixtures/react-sdk.tsx`], absWorkingDir: repo, bundle: true, write: false, platform: "browser",
  format: "iife", jsx: "automatic", define: { "process.env.KEYWAY_API_TARGET": '"production"', "process.env.NODE_ENV": '"production"' },
});
const browser = await launch();
const problems = [];

async function user(label, mode) {
  const mailbox = await newMailbox(`forceclose4-${label}`);
  writeFileSync(`${EVIDENCE}/forceclose4-${label}.json`, JSON.stringify({ email: mailbox.email, password: mailbox.password }), { mode: 0o600 });
  const context = await browser.newContext();
  const isolation = { "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp" };
  await context.route(`${origin}/__forceclose4*`, (route) => route.fulfill({ contentType: "text/html", headers: isolation, body: '<div id="root"></div><script src="/__forceclose4-fixture.js"></script>' }));
  await context.route(`${origin}/__forceclose4-fixture.js`, (route) => route.fulfill({ contentType: "text/javascript", headers: isolation, body: Buffer.from(bundle.outputFiles[0].contents) }));
  const page = await context.newPage();
  page.on("pageerror", (error) => problems.push(`${label}: ${String(error).slice(0, 200)}`));
  const keep = (text) => { if (/clos|send tx|commitment|watchtower|settle|sweep|ERROR/.test(text) && !/favicon|gossip/i.test(text)) log("NODE", text.replace(/\x1b\[[0-9;]*m/g, "").slice(0, 600)); };
  page.on("console", (m) => keep(m.text()));
  page.on("worker", (w) => w.on?.("console", (m) => keep(m.text())));
  await page.goto(`${origin}/__forceclose4?app=${encodeURIComponent(appId)}${mode === "browser" ? "&browser" : ""}`);
  await page.waitForFunction(() => window.probe?.auth.ready);
  await markSeen(mailbox);
  await page.evaluate(() => window.probe.auth.login());
  await page.locator('input[type="email"]').fill(mailbox.email);
  await page.locator('input[type="email"]').press("Enter");
  const { code } = await nextCode(mailbox);
  await page.locator('input[autocomplete="one-time-code"]').fill(code);
  await page.waitForFunction(() => window.probe.account.status === "ready", undefined, { timeout: 180_000 });
  const address = await page.evaluate(() => window.probe.account.address);
  log(label, mode, "signed in", address.slice(0, 16) + "…");
  return { label, mode, page, mailbox, address };
}

async function fund(u, ckb) {
  await json("https://faucet-api.nervos.org/claim_events", { claim_event: { address_hash: u.address, amount: String(ckb) } });
  for (let i = 0; i < 60; i++) {
    const balance = BigInt(await u.page.evaluate(async () => (await window.probe.account.refreshBalance()).toString()));
    if (balance >= BigInt(ckb) * CKB / 2n) return balance;
    await new Promise((r) => setTimeout(r, 5000));
  }
  throw new Error(`${u.label} was not funded`);
}

async function start(u) {
  await u.page.evaluate(() => window.probe.fiber.start());
  await u.page.waitForFunction(() => window.probe.fiber.status === "running" && window.probe.fiber.node, undefined, { timeout: 240_000 });
}

async function openChannel(u, ckb) {
  await u.page.evaluate((amount) => { window.opening = window.probe.fiber.openChannel({ fundingAmount: BigInt(amount), public: true }); }, String(BigInt(ckb) * CKB));
  await u.page.getByRole("button", { name: "Confirm activation", exact: true }).click({ timeout: 240_000 });
  const result = await u.page.evaluate(async () => { const r = await window.opening; return { channelId: r.channelId, txHash: r.fundingTxHash ?? r.txHash ?? null }; });
  const channels = await u.page.evaluate(async () => (await window.probe.fiber.refreshChannels()).map((c) => ({ id: c.id, status: c.status, capacity: c.capacity.toString(), canSend: c.canSend.toString(), asset: c.asset.kind })));
  return { ...result, channels };
}

const node = (u, method, params) => u.page.evaluate(async ([method, params]) => {
  try { return { ok: true, value: JSON.parse(JSON.stringify(await window.probe.fiber.node[method](params), (_k, v) => typeof v === "bigint" ? v.toString() : v)) }; }
  catch (error) { return { ok: false, error: `${error.code ?? ""} ${error.message}` }; }
}, [method, params]);

async function waitRoutable(sender, invoice) {
  for (let i = 0; i < 40; i++) {
    const estimate = await sender.page.evaluate(async (invoice) => (await window.probe.fiber.estimatePayment({ invoice, max_fee_amount: "0x5f5e100" })).routable, invoice);
    if (estimate) return;
    await new Promise((r) => setTimeout(r, 6000));
  }
  throw new Error("no route");
}


const EXPLORER = "https://testnet-api.explorer.nervos.org/api/v1";
async function explorerTx(hash) {
  const response = await fetch(`${EXPLORER}/transactions/${hash}`, { headers: { Accept: "application/vnd.api+json", "Content-Type": "application/vnd.api+json" } });
  if (!response.ok) return undefined;
  return (await response.json()).data?.attributes;
}
function outpoint(value) {
  if (typeof value === "string" && /^0x[0-9a-f]{72}$/i.test(value)) return { txHash: `0x${value.slice(2, 66)}`, index: Number.parseInt(value.slice(66).match(/../g).reverse().join(""), 16) };
  if (value && typeof value === "object") return { txHash: value.tx_hash, index: Number(value.index) };
  return undefined;
}
/** Follows a cell to the transaction that spent it. */
async function spentBy(txHash, index) {
  const tx = await explorerTx(txHash);
  const output = tx?.display_outputs?.[index];
  return output?.consumed_tx_hash || undefined;
}

try {
  const b = await user("browser", "browser");
  await fund(b, 10000);
  await start(b);
  const opened = await openChannel(b, 500);
  const raw = await b.page.evaluate(async (id) => (await window.probe.fiber.node.listChannels({})).channels.find((c) => c.channel_id === id), opened.channelId);
  const funding = outpoint(raw.channel_outpoint);
  record(`browser channel ${opened.channelId} ready; funding ${funding.txHash}:${funding.index}`);
  await b.page.evaluate((id) => { window.closing = window.probe.fiber.node.shutdownChannel({ channel_id: id, force: true }).then(() => "ok", (e) => e.message); }, opened.channelId);
  const dialog = b.page.getByRole("dialog");
  await dialog.waitFor({ timeout: 60_000 });
  await dialog.getByRole("button", { name: "Force close", exact: true }).click();
  record(`force close requested: ${await b.page.evaluate(() => window.closing)}`);
  // Keep the node running: after the commitment delay the peer claims its share, then the node's own
  // watchtower claims the user's share using the fee reserve on its settlement key, and the SDK sweeps that
  // key to the user's address. Follow every spend from the commitment until an output pays the user.
  let commitment;
  const seen = new Set();
  let swept = false;
  const deadline = Date.now() + 12 * 60 * 60 * 1000;
  const describe = (tx) => (tx?.display_outputs ?? []).map((o) => `${o.address_hash === b.address ? "USER ADDRESS" : o.address_hash.slice(0, 18) + "…"} ${Number(o.capacity) / 1e8} CKB`).join("; ");
  while (Date.now() < deadline && !swept) {
    if (!commitment) {
      commitment = await spentBy(funding.txHash, funding.index);
      if (commitment) record(`commitment on-chain: ${commitment}`);
    } else {
      // Breadth-first over spends, at most five steps from the commitment.
      let frontier = [commitment];
      for (let depth = 0; depth < 5 && frontier.length && !swept; depth++) {
        const next = [];
        for (const hash of frontier) {
          const tx = await explorerTx(hash);
          for (const output of tx?.display_outputs ?? []) {
            const spender = output.consumed_tx_hash;
            if (!spender) continue;
            next.push(spender);
            if (seen.has(spender)) continue;
            seen.add(spender);
            const spent = await explorerTx(spender);
            record(`step ${depth + 1}: ${hash.slice(0, 12)}… spent by ${spender}: ${describe(spent)}`);
            if (depth > 0 && (spent?.display_outputs ?? []).some((o) => o.address_hash === b.address)) swept = true;
          }
        }
        frontier = [...new Set(next)];
      }
    }
    if (!swept) {
      log("waiting; fiber", await b.page.evaluate(() => window.probe.fiber.status).catch(() => "page gone"));
      await new Promise((r) => setTimeout(r, 5 * 60_000));
    }
  }
  log(swept ? "DONE: the force-closed funds reached the user's address" : "TIMEOUT: no sweep to the user's address seen");
  await b.page.evaluate(() => window.probe.fiber.stop()).catch(() => undefined);
} catch (error) {
  log("FAILED", error.message.split("\n")[0]);
  process.exitCode = 1;
} finally {
  log("page errors:", problems.length ? problems : "none");
  writeFileSync(`${EVIDENCE}/browser-forceclose-evidence.txt`, evidence.join("\n") + "\n");
  await browser.close();
}

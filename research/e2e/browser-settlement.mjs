// Live testnet proof that a browser-mode KeyWay node claims the user's share after a force close and the SDK
// sweeps it to the user's own address. Runs the local SDK build in headless Chromium under the production origin
// against the production API, with a disposable account, and keeps the node running for the whole delay.
//
//   npm install --no-save playwright   (if it isn't installed; the repo doesn't depend on it)
//   node research/e2e/browser-settlement.mjs
//
// Everything the page and Fiber's workers print goes to .evidence/settlement-console.log (nothing is filtered).
// Chain facts come from CKB RPC (block timestamps), not the explorer. While it runs:
//   touch .evidence/reload        rebuilds the SDK bundle, reloads the page and restarts the node
//   .evidence/eval.js             is evaluated in the page once (then renamed) and its result logged
import { createRequire } from "node:module";
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { DEMO_APP_ID, EVIDENCE, json, launchPersistent, markSeen, newMailbox, nextCode, openMailbox } from "./lib.mjs";
import { forAccount, forChannel, loadSettlementState, startupPlan } from "./settlement-state.mjs";

const repo = new URL("../..", import.meta.url).pathname.replace(/\/$/, "");
mkdirSync(EVIDENCE, { recursive: true, mode: 0o700 });
const { build } = createRequire(`${repo}/`)("esbuild");
const origin = "https://www.ckbkeyway.dev";
const RPC = process.env.CKB_RPC ?? "https://testnet.ckb.dev/";
const CKB = 100_000_000n;
const CONSOLE = `${EVIDENCE}/settlement-console.log`;
const now = () => new Date().toISOString().slice(0, 19).replace("T", " ");
const log = (...args) => { const line = `${now()} ${args.join(" ")}`; console.log(line); appendFileSync(`${EVIDENCE}/settlement-run.log`, line + "\n"); };
const record = (line) => { log("PASS", line); appendFileSync(`${EVIDENCE}/settlement-evidence.txt`, `${now()} ${line}\n`); };

async function bundle() {
  const result = await build({
    entryPoints: [`${repo}/tests/fixtures/react-sdk.tsx`], absWorkingDir: repo, bundle: true, write: false, platform: "browser",
    format: "iife", jsx: "automatic", define: { "process.env.KEYWAY_API_TARGET": '"production"', "process.env.NODE_ENV": '"production"' },
  });
  return Buffer.from(result.outputFiles[0].contents);
}

async function rpc(method, params) {
  for (let attempt = 0; ; attempt++) {
    try {
      const response = await fetch(RPC, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: 1, jsonrpc: "2.0", method, params }), signal: AbortSignal.timeout(30_000) });
      const body = await response.json();
      if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
      return body.result;
    } catch (error) {
      if (attempt >= 4) throw error;
      await new Promise((r) => setTimeout(r, 3000 * (attempt + 1)));
    }
  }
}
const blockTime = async (blockHash) => new Date(Number(BigInt((await rpc("get_header", [blockHash])).timestamp))).toISOString().replace("T", " ").slice(0, 19) + " UTC";
async function confirmed(txHash) {
  const tx = await rpc("get_transaction", [txHash]);
  if (tx?.tx_status?.status !== "committed") return undefined;
  return { tx: tx.transaction, block: BigInt(tx.tx_status.block_number), time: await blockTime(tx.tx_status.block_hash) };
}
/** The transaction that spent `txHash:index`, found through the indexer by the cell's lock. */
async function spender(txHash, index) {
  const live = await rpc("get_live_cell", [{ tx_hash: txHash, index: `0x${index.toString(16)}` }, false]);
  if (live.status === "live") return undefined;
  const source = (await rpc("get_transaction", [txHash])).transaction;
  const lock = source.outputs[index].lock;
  let cursor = null;
  for (let page = 0; page < 20; page++) {
    const result = await rpc("get_transactions", [{ script: lock, script_type: "lock", script_search_mode: "exact" }, "desc", "0x64", cursor]);
    for (const item of result.objects) {
      if (item.io_type !== "input") continue;
      const tx = (await rpc("get_transaction", [item.tx_hash])).transaction;
      if (tx.inputs.some((input) => input.previous_output.tx_hash === txHash && Number(input.previous_output.index) === index)) return item.tx_hash;
    }
    if (result.objects.length < 100) break;
    cursor = result.last_cursor;
  }
  return "unknown";
}

const statePath = `${EVIDENCE}/settlement-state.json`;
// Kept across restarts so an unfinished run resumes on its account and channel; a finished run's state is never reused.
const state = loadSettlementState(existsSync(statePath) ? readFileSync(statePath, "utf8") : undefined);
const save = () => writeFileSync(statePath, JSON.stringify(state, null, 2), { mode: 0o600 });
// A restart of an unfinished run signs in to the same account and carries on with the same channel.
const plan = startupPlan(state);
const resuming = plan.resume;

// The browser profile is kept with the run: a resumed run needs this device's ID, its session and the node's channel
// databases, or the node can't come back to claim the settlement. A fresh run starts from an empty profile.
const profile = `${EVIDENCE}/settlement-profile`;
if (!plan.keepProfile) rmSync(profile, { recursive: true, force: true });
const context = await launchPersistent(profile);
let currentBundle = await bundle();
const isolation = { "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp" };
await context.route(`${origin}/__settlement*`, (route) => route.request().url().includes("fixture.js")
  ? route.fulfill({ contentType: "text/javascript", headers: isolation, body: currentBundle })
  : route.fulfill({ contentType: "text/html", headers: isolation, body: '<div id="root"></div><script src="/__settlement-fixture.js"></script>' }));
const page = context.pages()[0] ?? await context.newPage();
const stamp = (source, text) => appendFileSync(CONSOLE, `${now()} [${source}] ${text.replace(/\x1b\[[0-9;]*m/g, "")}\n`);
page.on("console", (m) => stamp(`page:${m.type()}`, m.text()));
page.on("pageerror", (error) => stamp("pageerror", String(error?.stack ?? error)));
page.on("worker", (worker) => { stamp("worker", `started ${worker.url().slice(0, 60)}`); worker.on?.("console", (m) => stamp(`worker:${m.type()}`, m.text())); });
page.on("crash", () => stamp("page", "CRASHED"));
const url = `${origin}/__settlement?app=${encodeURIComponent(DEMO_APP_ID)}&browser`;

async function startNode() {
  await page.evaluate(() => window.probe.fiber.start());
  await page.waitForFunction(() => window.probe.fiber.status === "running" && window.probe.fiber.node, undefined, { timeout: 300_000 });
}
async function watchtowerData() {
  return page.evaluate(async () => {
    const name = (await indexedDB.databases()).map((d) => d.name).find((n) => n?.endsWith("-keyway-watchtower"));
    if (!name) return null;
    const db = await new Promise((resolve, reject) => { const r = indexedDB.open(name); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
    const rows = await new Promise((resolve) => { const r = db.transaction("channels").objectStore("channels").getAll(); r.onsuccess = () => resolve(r.result); });
    db.close();
    return rows;
  });
}
const redact = (rows) => JSON.stringify(rows, (key, value) => key === "localSettlementKey" || key === "local_key" ? "<redacted>" : value);


try {
  const mailbox = resuming ? await openMailbox(state.email, state.password) : await newMailbox("st");
  if (resuming) log(`resuming the run for ${state.address}, channel ${state.channelId}, force-closed at ${state.forceCloseAt ?? "(not yet)"}`);
  await page.goto(url);
  await page.waitForFunction(() => window.probe?.auth.ready);
  // A resumed run's profile may still hold its session.
  if (!await page.evaluate(() => window.probe.auth.authenticated)) {
    await markSeen(mailbox);
    await page.evaluate(() => window.probe.auth.login());
    await page.locator('input[type="email"]').fill(mailbox.email);
    await page.locator('input[type="email"]').press("Enter");
    await page.locator('input[autocomplete="one-time-code"]').fill((await nextCode(mailbox)).code);
  }
  await page.waitForFunction(() => window.probe.account.status === "ready", undefined, { timeout: 180_000 });
  const address = await page.evaluate(() => window.probe.account.address);
  if (resuming && address !== state.address) throw new Error(`resumed account signed in as ${address}, not ${state.address}`);
  forAccount(state, address);
  state.email = mailbox.email; state.password = mailbox.password; save();
  record(`user address ${state.address}`);

  if (!plan.setUp) {
    // The kept profile brings the node back with its channels; if it doesn't start now, the loop below retries.
    await startNode().then(() => record("browser node running again"), (error) => log("WARN the browser node did not start yet", error.message));
  } else {
    await json("https://faucet-api.nervos.org/claim_events", { claim_event: { address_hash: state.address, amount: "10000" } });
    for (let i = 0; ; i++) {
      const balance = BigInt(await page.evaluate(async () => (await window.probe.account.refreshBalance()).toString()));
      if (balance >= 5000n * CKB) { record(`funded from the faucet: ${balance / CKB} CKB`); break; }
      if (i > 120) throw new Error("not funded");
      await new Promise((r) => setTimeout(r, 5000));
    }

    await startNode();
    record("browser node running");
    await page.evaluate(() => { window.opening = window.probe.fiber.openChannel({ fundingAmount: 500n * 100_000_000n, public: true }); });
    await page.getByRole("button", { name: "Activate", exact: true }).click({ timeout: 300_000 });
    const opened = await page.evaluate(async () => { const r = await window.opening; return JSON.parse(JSON.stringify(r, (_k, v) => typeof v === "bigint" ? v.toString() : v)); });
    log("open result", JSON.stringify(opened));
    const raw = await page.evaluate(async (id) => (await window.probe.fiber.node.listChannels({})).channels.find((c) => c.channel_id === id), opened.channelId);
    const op = raw.channel_outpoint;
    forChannel(state, opened.channelId);
    state.funding = { txHash: `0x${op.slice(2, 66)}`, index: Number.parseInt(op.slice(66).match(/../g).reverse().join(""), 16) };
    state.feeReserveTxHash = opened.feeReserveTxHash ?? null; save();
    record(`channel ${state.channelId} ready; funding ${state.funding.txHash}:${state.funding.index}; fee reserve tx ${state.feeReserveTxHash}`);

    for (let i = 0; i < 30; i++) {
      const rows = await watchtowerData();
      if (rows?.some((row) => row.channelId === state.channelId)) {
        writeFileSync(`${EVIDENCE}/settlement-watchtower.json`, JSON.stringify(rows, null, 2), { mode: 0o600 });
        record(`in-page watchtower holds the channel: ${redact(rows.filter((row) => row.channelId === state.channelId)).slice(0, 700)}`);
        break;
      }
      if (i === 29) log("WARN the in-page watchtower has no data for the channel");
      await new Promise((r) => setTimeout(r, 2000));
    }
  }

  if (plan.forceClose) {
    // A run stopped while (or just after) asking for the force close may find the funding already spent.
    const closedBy = resuming ? await spender(state.funding.txHash, state.funding.index) : undefined;
    if (closedBy) {
      state.forceCloseAt = now(); save();
      record(`funding already spent by ${closedBy}; following it`);
    } else {
      if (resuming) await startNode();
      await page.evaluate((id) => { window.closing = window.probe.fiber.node.shutdownChannel({ channel_id: id, force: true }).then(() => "ok", (e) => e.message); }, state.channelId);
      const dialog = page.getByRole("dialog");
      await dialog.waitFor({ timeout: 60_000 });
      await dialog.getByRole("button", { name: "Force close", exact: true }).click();
      state.forceCloseAt = now(); save();
      record(`force close requested: ${await page.evaluate(() => window.closing)}`);
    }
  }

  const seen = new Set();
  // A resumed run already found its commitment: follow on from it.
  const frontier = state.commitment ? [state.commitment] : [];
  const deadline = Date.now() + 7.5 * 60 * 60 * 1000;
  let done = false;
  let nextStartAttempt = 0;
  while (Date.now() < deadline && !done) {
    if (existsSync(`${EVIDENCE}/reload`)) {
      rmSync(`${EVIDENCE}/reload`);
      try {
        currentBundle = await bundle();
        log("reloading the page with a rebuilt SDK");
        await page.reload();
        await page.waitForFunction(() => window.probe?.account.status === "ready", undefined, { timeout: 180_000 });
        await startNode();
        record("page reloaded with the rebuilt SDK; node running again");
      } catch (error) { log("reload failed", error.message); }
    }
    if (existsSync(`${EVIDENCE}/eval.js`)) {
      const code = readFileSync(`${EVIDENCE}/eval.js`, "utf8");
      renameSync(`${EVIDENCE}/eval.js`, `${EVIDENCE}/eval.done.js`);
      try { log("eval:", JSON.stringify(await page.evaluate(code), (_k, v) => typeof v === "bigint" ? v.toString() : v).slice(0, 4000)); } catch (error) { log("eval failed", error.message); }
    }
    try {
      if (!state.commitment) {
        const by = await spender(state.funding.txHash, state.funding.index);
        if (by && by !== "unknown") {
          const c = await confirmed(by);
          if (c) { state.commitment = by; save(); record(`commitment ${by} committed in block ${c.block} at ${c.time}`); frontier.push(by); }
        }
      }
      for (const hash of [...frontier]) {
        const tx = (await rpc("get_transaction", [hash])).transaction;
        for (let index = 0; index < tx.outputs.length; index++) {
          const key = `${hash}:${index}`;
          if (seen.has(key)) continue;
          const by = await spender(hash, index);
          if (!by) continue;
          seen.add(key);
          if (by === "unknown") { log(`${key} spent, spender not found yet`); seen.delete(key); continue; }
          const c = await confirmed(by);
          if (!c) { seen.delete(key); continue; }
          const outs = c.tx.outputs.map((o) => `${o.lock.code_hash.slice(0, 10)}…/${o.lock.args.slice(0, 12)}… ${Number(BigInt(o.capacity)) / 1e8} CKB`).join("; ");
          record(`${key} spent by ${by} (block ${c.block}, ${c.time}): ${outs}`);
          if (!frontier.includes(by)) frontier.push(by);
        }
      }
      // Done once a transaction downstream of the commitment pays the user's own lock.
      state.userScript ??= await page.evaluate(async (address) => { const a = await window.ccc.Address.fromString(address, new window.ccc.ClientPublicTestnet()); return { code_hash: a.script.codeHash, args: a.script.args }; }, state.address);
      const script = state.userScript;
      for (const hash of frontier.slice(1)) {
        const tx = (await rpc("get_transaction", [hash])).transaction;
        if (tx.outputs.some((o) => o.lock.code_hash === script.code_hash && o.lock.args === script.args)) { record(`DONE: ${hash} pays the user's own address`); done = true; }
      }
    } catch (error) { log("follow error", error.message); }
    if (!done) {
      const status = await page.evaluate(() => window.probe.fiber.status).catch(() => "page gone");
      log(`waiting; fiber ${status}`);
      // The node claims and sweeps the settlement, so a stopped node is started again while the chain is followed.
      if (status !== "running" && status !== "page gone" && Date.now() >= nextStartAttempt) {
        nextStartAttempt = Date.now() + 5 * 60_000;
        await startNode().then(() => record("browser node running again"), (error) => log("WARN the browser node did not start", error.message));
      }
      await new Promise((r) => setTimeout(r, 60_000));
    }
  }
  if (done) { state.finished = true; save(); }
  log(done ? "DONE" : "TIMEOUT");
} catch (error) {
  log("FAILED", error.stack?.split("\n").slice(0, 3).join(" | ") ?? error);
  process.exitCode = 1;
} finally {
  writeFileSync(`${EVIDENCE}/settlement-watchtower-final.json`, JSON.stringify(await watchtowerData().catch(() => null), null, 2), { mode: 0o600 });
  await context.close();
}

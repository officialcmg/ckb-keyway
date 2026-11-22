// Live testnet proof that a force-closed channel ends with the user's money at the user's own address, with the node
// in the user's browser (the default) or with a hosted node (FIBER_MODE=hosted). Runs the local SDK build in headless
// Chromium under the production origin against the production API, with a disposable account, and keeps the page
// signed in and the node in use for the whole delay.
//
//   npm install --no-save playwright   (if it isn't installed; the repo doesn't depend on it)
//   node research/e2e/browser-settlement.mjs
//   FIBER_MODE=hosted KEYWAY_EVIDENCE=research/e2e/.evidence-hosted node research/e2e/browser-settlement.mjs
//
// KEYWAY_EVIDENCE   the run's folder (default research/e2e/.evidence): give each of two simultaneous runs its own.
// KEYWAY_PAY_WITH   the folder of another run going on at the same time: before the force closes the two accounts pay
//                   each other 1 CKB over their channels, so each channel is closed from a state after a payment.
//                   Given up after KEYWAY_PAY_MINUTES (default 15); the force close then goes ahead without it.
// KEYWAY_RESERVE_MINUTES  how long the page stays open after the user's address is paid, to see the fee reserve
//                   come back from the node's key as well (default 30; 0 ends the run at the payment).
//
// Everything the page and Fiber's workers print goes to <folder>/settlement-console.log (nothing is filtered).
// Chain facts come from CKB RPC (block timestamps), not the explorer. While it runs:
//   touch <folder>/reload        rebuilds the SDK bundle, reloads the page and restarts the node
//   <folder>/eval.js             is evaluated in the page once (then renamed) and its result logged
import { createRequire } from "node:module";
import { resolve } from "node:path";
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
const hosted = process.env.FIBER_MODE === "hosted";
const mode = hosted ? "hosted" : "browser";
const partner = process.env.KEYWAY_PAY_WITH ? resolve(process.env.KEYWAY_PAY_WITH) : undefined;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const plain = (value) => JSON.stringify(value, (_k, v) => typeof v === "bigint" ? v.toString() : v);
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
const url = `${origin}/__settlement?app=${encodeURIComponent(DEMO_APP_ID)}${hosted ? "" : "&browser"}`;

async function startNode() {
  await page.evaluate(() => window.probe.fiber.start());
  await page.waitForFunction(() => window.probe.fiber.status === "running" && window.probe.fiber.node, undefined, { timeout: 300_000 });
}
let mailbox;
/** The run's mailbox, opened when a code is first needed (a resumed run may still be signed in). */
async function inbox() {
  mailbox ??= state.email ? await openMailbox(state.email, state.password) : await newMailbox(hosted ? "hs" : "st");
  if (!state.email) { state.email = mailbox.email; state.password = mailbox.password; save(); }
  return mailbox;
}
async function signIn() {
  const box = await inbox();
  await markSeen(box);
  await page.evaluate(() => { window.probe.auth.login(); });
  await page.locator('input[type="email"]').fill(box.email);
  for (let attempt = 0; ; attempt++) {
    const sent = page.waitForResponse((response) => response.url().endsWith("/auth/send-code") && response.request().method() === "POST");
    await page.locator('input[type="email"]').press("Enter");
    const response = await sent;
    if (response.ok()) break;
    if (response.status() !== 429 || attempt >= 4) throw new Error(`sign-in code request failed: HTTP ${response.status()}`);
    const seconds = Number(String((await response.json().catch(() => ({}))).error ?? "").match(/(?:in|wait) (\d+) seconds/i)?.[1] ?? 60);
    log(`sign-in cooldown: waiting ${seconds + 1} s`);
    await sleep((seconds + 1) * 1000);
  }
  await page.locator('input[autocomplete="one-time-code"]').fill((await nextCode(box)).code);
}
/**
 * Starts an SDK operation in the page and answers its dialogs as the user would: presses the named buttons and types
 * the emailed confirmation code when one is asked for. Returns what the operation returned.
 */
async function approved(operation, argument, buttons, timeoutMs = 600_000) {
  const box = await inbox();
  await markSeen(box);
  await page.evaluate(({ source, argument }) => {
    window.liveOperation = { done: false };
    Promise.resolve().then(() => (0, eval)(`(${source})`)(argument)).then(
      (value) => { window.liveOperation = { done: true, value: JSON.parse(JSON.stringify(value ?? null, (_k, v) => typeof v === "bigint" ? v.toString() : v)) }; },
      (error) => { window.liveOperation = { done: true, error: String(error?.message ?? error) }; },
    );
  }, { source: operation.toString(), argument });
  const deadline = Date.now() + timeoutMs;
  let nextProgress = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const current = await page.evaluate(() => window.liveOperation);
    if (current.done) {
      if (current.error) throw new Error(current.error);
      return current.value;
    }
    const dialog = page.getByRole("dialog");
    if (await page.getByRole("heading", { name: "Couldn't confirm", exact: true }).isVisible()) {
      const error = (await page.getByRole("alert").allTextContents()).join("; ");
      await dialog.getByRole("button", { name: "Close", exact: true }).click();
      await page.waitForFunction(() => window.liveOperation.done);
      throw new Error(error);
    }
    if (Date.now() >= nextProgress) {
      log("waiting for the operation; dialog:", plain(await dialog.getByRole("heading").allTextContents()));
      nextProgress = Date.now() + 30_000;
    }
    const code = page.locator('input[autocomplete="one-time-code"]');
    if (await code.isVisible() && await code.isEnabled() && !(await code.inputValue())) {
      const digits = Number(await code.getAttribute("maxlength")) || 8;
      await code.fill((await nextCode(box, digits)).code);
    } else {
      for (const name of buttons) {
        const button = dialog.getByRole("button", { name, exact: true });
        if (await button.isVisible() && await button.isEnabled()) { await button.click(); break; }
      }
    }
    await sleep(500);
  }
  throw new Error(`the operation timed out; dialog: ${(await page.getByRole("dialog").getByRole("heading").allTextContents()).join(", ")}`);
}
/** The channel as the node reports it (Fiber's own fields), closed channels included. */
const rawChannel = () => page.evaluate(async (id) => (await window.probe.fiber.node.listChannels({ include_closed: true })).channels.find((c) => c.channel_id === id), state.channelId);
const describeChannel = (c) => c ? `state ${plain(c.state)}, local ${Number(BigInt(c.local_balance)) / 1e8} CKB, remote ${Number(BigInt(c.remote_balance)) / 1e8} CKB, pending TLCs ${c.pending_tlcs?.length ?? "?"}` : "not listed";

/**
 * The two runs pay each other 1 CKB over their new channels, each through the public network. Either side gives up at
 * the deadline; a payment that is still in flight then is waited for, so that no channel is closed with one pending.
 */
async function exchangePayments() {
  const deadline = Date.now() + Number(process.env.KEYWAY_PAY_MINUTES ?? 15) * 60_000;
  const mine = await page.evaluate(() => window.probe.fiber.createInvoice({ amount: "0x5f5e100", currency: "Fibt", description: "KeyWay force-close run", expiry: "0xe10" }));
  const myHash = plain(mine).match(/"payment_hash":"(0x[0-9a-f]{64})"/)?.[1];
  writeFileSync(`${EVIDENCE}/invoice.json`, JSON.stringify({ invoice: mine.invoice_address, paymentHash: myHash }), { mode: 0o600 });
  log(`payment: invoice for 1 CKB written, payment hash ${myHash}`);
  let sent, received = false;
  try {
    while (!existsSync(`${partner}/invoice.json`)) { if (Date.now() > deadline) throw new Error("the other run made no invoice in time"); await sleep(5000); }
    const theirs = JSON.parse(readFileSync(`${partner}/invoice.json`, "utf8"));
    for (let attempt = 0; ; attempt++) {
      const estimate = await page.evaluate(async (invoice) => { const r = await window.probe.fiber.estimatePayment({ invoice, max_fee_amount: "0x5f5e100" }); return { routable: r.routable, error: r.error?.message }; }, theirs.invoice);
      if (estimate.routable) break;
      if (attempt % 6 === 0) log("payment: no route yet", plain(estimate));
      if (Date.now() > deadline) throw new Error(`no route to the other run's node: ${estimate.error}`);
      await sleep(10_000);
    }
    sent = await approved((invoice) => window.probe.fiber.payInvoice(invoice, { max_fee_amount: "0x5f5e100" }), theirs.invoice, ["Approve", "Continue"], 300_000);
    record(`payment sent: 1 CKB to the other run, payment hash ${sent.payment_hash}, status ${sent.status}, fee ${sent.fee ?? "?"}`);
  } catch (error) { log("WARN payment not sent:", error.message); }
  // Whatever happened to ours, the other run may be paying this one: wait for it (or for the other run to give up).
  while (!received) {
    const status = (await page.evaluate((hash) => window.probe.fiber.getInvoice({ payment_hash: hash }), myHash).catch(() => undefined))?.status;
    if (status === "Paid") { received = true; record(`payment received: 1 CKB from the other run, payment hash ${myHash}`); break; }
    if (existsSync(`${partner}/payment-over`) && status !== "Received") break;
    if (Date.now() > deadline + 5 * 60_000) break;
    await sleep(5000);
  }
  if (!received) log("WARN no payment was received from the other run");
  writeFileSync(`${EVIDENCE}/payment-over`, JSON.stringify({ sent: sent?.status ?? null, received }));
  state.payment = { sent: sent ? { paymentHash: sent.payment_hash, status: sent.status } : null, received: received ? myHash : null }; save();
}

async function watchtowerData() {
  if (hosted) return null;
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
  if (resuming) log(`resuming the run for ${state.address}, channel ${state.channelId}, force-closed at ${state.forceCloseAt ?? "(not yet)"}`);
  await page.goto(url);
  await page.waitForFunction(() => window.probe?.auth.ready);
  // A resumed run's profile may still hold its session: the mailbox is only opened when sign-in needs a code.
  if (!await page.evaluate(() => window.probe.auth.authenticated)) await signIn();
  await page.waitForFunction(() => window.probe.account.status === "ready", undefined, { timeout: 180_000 });
  const address = await page.evaluate(() => window.probe.account.address);
  if (resuming && address !== state.address) throw new Error(`resumed account signed in as ${address}, not ${state.address}`);
  const account = { email: state.email, password: state.password };
  forAccount(state, address);
  Object.assign(state, account);
  save();
  record(`${mode} mode; user address ${state.address}`);

  if (!plan.setUp) {
    // The kept profile brings the node back with its channels; if it doesn't start now, the loop below retries.
    await startNode().then(() => record(`${mode} node running again`), (error) => log(`WARN the ${mode} node did not start yet`, error.message));
  } else {
    await json("https://faucet-api.nervos.org/claim_events", { claim_event: { address_hash: state.address, amount: "10000" } });
    for (let i = 0; ; i++) {
      const balance = BigInt(await page.evaluate(async () => (await window.probe.account.refreshBalance()).toString()));
      if (balance >= 5000n * CKB) { record(`funded from the faucet: ${balance / CKB} CKB`); break; }
      if (i > 120) throw new Error("not funded");
      await new Promise((r) => setTimeout(r, 5000));
    }

    await startNode();
    record(`${mode} node running, node ${await page.evaluate(async () => (await window.probe.fiber.node.nodeInfo()).pubkey)}`);
    const opened = await approved(() => window.probe.fiber.openChannel({ fundingAmount: 500n * 100_000_000n, public: true }), undefined, ["Activate", "Continue"]);
    log("open result", JSON.stringify(opened));
    forChannel(state, opened.channelId);
    let raw;
    for (let i = 0; ; i++) {
      raw = await rawChannel();
      // CHANNEL_READY exactly: AWAITING_CHANNEL_READY can already have its funding outpoint and is not ready yet.
      if (raw?.channel_outpoint && String(raw.state?.state_name ?? "").replaceAll("_", "").toLowerCase() === "channelready") break;
      if (i > 120) throw new Error(`the channel did not become ready: ${describeChannel(raw)}`);
      await sleep(5000);
    }
    const op = raw.channel_outpoint;
    state.funding = { txHash: `0x${op.slice(2, 66)}`, index: Number.parseInt(op.slice(66).match(/../g).reverse().join(""), 16) };
    state.feeReserveTxHash = opened.feeReserveTxHash ?? null; state.peer = raw.pubkey ?? raw.peer_id ?? null; save();
    record(`channel ${state.channelId} ready with peer ${state.peer}; funding ${state.funding.txHash}:${state.funding.index}; fee reserve tx ${state.feeReserveTxHash}; ${describeChannel(raw)}`);

    if (!hosted) for (let i = 0; i < 30; i++) {
      const rows = await watchtowerData();
      if (rows?.some((row) => row.channelId === state.channelId)) {
        writeFileSync(`${EVIDENCE}/settlement-watchtower.json`, JSON.stringify(rows, null, 2), { mode: 0o600 });
        record(`in-page watchtower holds the channel: ${redact(rows.filter((row) => row.channelId === state.channelId)).slice(0, 700)}`);
        break;
      }
      if (i === 29) log("WARN the in-page watchtower has no data for the channel");
      await new Promise((r) => setTimeout(r, 2000));
    }
    if (partner) await exchangePayments().catch((error) => log("WARN the payment exchange failed:", error.message));
  }

  if (plan.forceClose) {
    // A run stopped while (or just after) asking for the force close may find the funding already spent. "unknown"
    // (spent, but the spender isn't found yet, or the cell is in flux after a reorganization) proves nothing: wait
    // until the cell is live again or its spender is known, and never record a close on it.
    let closedBy = resuming ? await spender(state.funding.txHash, state.funding.index) : undefined;
    for (let tries = 0; closedBy === "unknown"; tries++) {
      if (tries >= 30) throw new Error("the funding cell is spent but its spender can't be found yet; run again later");
      log("funding spent, spender not found yet; checking again in a minute");
      await new Promise((r) => setTimeout(r, 60_000));
      closedBy = await spender(state.funding.txHash, state.funding.index);
    }
    if (closedBy) {
      state.forceCloseAt = now(); save();
      record(`funding already spent by ${closedBy}; following it`);
    } else {
      if (resuming) await startNode();
      // Never close with a payment in flight: the claim of a channel with pending payments is another case.
      let before;
      for (let i = 0; ; i++) {
        before = await rawChannel();
        if (!before?.pending_tlcs?.length) break;
        if (i > 60) throw new Error(`payments are still pending on the channel: ${describeChannel(before)}`);
        await sleep(5000);
      }
      record(`before the force close: ${describeChannel(before)}`);
      // Approving isn't submitting: only a force close the node accepted is recorded. Otherwise the run stays
      // resumable without it, and the next start tries the force close again.
      await approved((id) => window.probe.fiber.node.shutdownChannel({ channel_id: id, force: true }), state.channelId, ["Force close", "Continue"]);
      state.forceCloseAt = now(); save();
      record("force close requested through the SDK and accepted by the node");
    }
  }

  /** What the node's key (the lock the fee reserve was paid to) holds now; undefined when it can't be told. */
  async function atNodeKey() {
    if (!state.feeReserveTxHash) return undefined;
    state.nodeKeyLock ??= (await rpc("get_transaction", [state.feeReserveTxHash])).transaction.outputs.find((o) => BigInt(o.capacity) === 62n * 100_000_000n)?.lock;
    if (!state.nodeKeyLock) return undefined;
    const held = await rpc("get_cells_capacity", [{ script: state.nodeKeyLock, script_type: "lock", script_search_mode: "exact" }]);
    return BigInt(held?.capacity ?? 0);
  }

  const seen = new Set();
  // A resumed run already found its commitment: follow on from it.
  const frontier = state.commitment ? [state.commitment] : [];
  const deadline = Date.now() + Number(process.env.KEYWAY_FOLLOW_HOURS ?? 7.5) * 60 * 60 * 1000;
  let done = false;
  // A run restarted after the payment only watches for the fee reserve.
  let paid = Boolean(state.paid);
  const reserveMs = Number(process.env.KEYWAY_RESERVE_MINUTES ?? 30) * 60_000;
  let reserveDeadline = paid ? Date.now() + reserveMs : 0;
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
        if (!paid && tx.outputs.some((o) => o.lock.code_hash === script.code_hash && o.lock.args === script.args)) {
          record(`DONE: ${hash} pays the user's own address`);
          paid = true; state.paid = true; save();
          reserveDeadline = Date.now() + reserveMs;
        }
      }
      // The payment can leave the fee reserve at the node's key (it stays while a channel may still need settling):
      // the page stays open a while longer to see whether that comes back to the user too.
      if (paid) {
        const left = await atNodeKey();
        if (left === 0n) { record("nothing is left at the node's key"); done = true; }
        else if (Date.now() >= reserveDeadline) { record(`${left === undefined ? "an unknown amount" : `${Number(left) / 1e8} CKB`} is still at the node's key ${Math.round(reserveMs / 60_000)} minutes after the payment`); done = true; }
      }
    } catch (error) { log("follow error", error.message); }
    if (!done) {
      const status = await page.evaluate(() => window.probe.fiber.status).catch(() => "page gone");
      // Listing the channels is also what keeps a hosted node "in use": the API moves what the node's key holds to
      // the user's address only while the signed-in page keeps asking for the node.
      const channel = status === "running" ? await rawChannel().then(describeChannel, (error) => `not listed: ${error.message.slice(0, 120)}`) : "";
      if (!await page.evaluate(() => window.probe.auth.authenticated).catch(() => true)) await signIn().then(() => record("signed in again"), (error) => log("WARN signing in again failed", error.message));
      log(`waiting; fiber ${status}; ${channel}`);
      // The node claims and sweeps the settlement, so a stopped node is started again while the chain is followed.
      if (status !== "running" && status !== "page gone" && Date.now() >= nextStartAttempt) {
        nextStartAttempt = Date.now() + 5 * 60_000;
        await startNode().then(() => record(`${mode} node running again`), (error) => log(`WARN the ${mode} node did not start`, error.message));
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

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, writeFile, readFile, appendFile } from "node:fs/promises";
import { build } from "esbuild";

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ?? "playwright");
const api = "https://keyway-api-production.up.railway.app/api/v1/keyway";
const origin = "https://www.ckbkeyway.dev";
const browserMode = process.env.FIBER_MODE === "browser";
const productionUi = process.env.PRODUCTION_UI === "1";
const verifyPayments = process.env.VERIFY_PAYMENTS === "1";
const verifyChannels = verifyPayments && process.env.ONLY_CKB_SEND !== "1";
let verifyWrongCode = process.env.VERIFY_WRONG_CONFIRMATION_CODE === "1";
const appId = process.env.KEYWAY_TEST_APP_ID;
if (!appId) throw new Error("KEYWAY_TEST_APP_ID must identify a registered disposable-test application");
const bundle = await build({ entryPoints: ["tests/fixtures/react-sdk.tsx"], bundle: true, write: false, platform: "browser", format: "iife", jsx: "automatic", define: { "process.env.KEYWAY_API_TARGET": '"production"', "process.env.NODE_ENV": '"development"' } });
async function json(url, body, token, headers = {}) {
  let response;
  for (let attempt = 0; attempt < 4; attempt++) {
    response = await fetch(url, { method: body ? "POST" : "GET", headers: { "Content-Type": "application/json", ...(url.startsWith(api) ? { Origin: origin, "X-KeyWay-App-Id": appId } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers }, ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(30_000) });
    if (response.status !== 429 || attempt === 3) break;
    await new Promise(resolve => setTimeout(resolve, 20_000));
  }
  if (!response.ok) throw new Error(`Verification request failed: ${response.status} ${new URL(url).pathname}`);
  if (response.status === 204) return;
  return response.json();
}
async function markSeen(mailbox) {
  for (const message of (await json("https://api.mail.tm/messages", undefined, mailbox.token))["hydra:member"]) mailbox.seen.add(message.id);
}
async function nextCode(mailbox, digits = 6) {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    for (const message of (await json("https://api.mail.tm/messages", undefined, mailbox.token))["hydra:member"]) {
      if (mailbox.seen.has(message.id)) continue;
      const full = await json(`https://api.mail.tm/messages/${message.id}`, undefined, mailbox.token);
      // Funding emails contain eight decimal places before the code. Match its label, never an arbitrary number.
      const code = `${full.text ?? ""}`.match(new RegExp(`(?:Your confirmation code is|Your code is)\\s+(\\d{${digits}})\\b`, "i"))?.[1];
      if (code) { mailbox.seen.add(message.id); return code; }
    }
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  throw new Error(`Disposable ${digits}-digit email did not arrive within two minutes`);
}
// Drive the actual dialogs; never log mailbox addresses, codes, sessions or browser storage.
async function signIn(page, mailbox, live = false) {
  await markSeen(mailbox);
  if (live) await page.getByRole("button", { name: "Sign in with email", exact: true }).click();
  else {
    await page.waitForFunction(() => window.probe?.auth.ready);
    await page.evaluate(() => { window.probe.auth.login(); });
  }
  await page.locator('input[type="email"]').fill(mailbox.email);
  for (let attempt = 0; attempt < 5; attempt++) {
    const sent = page.waitForResponse(response => response.url().endsWith("/auth/send-code") && response.request().method() === "POST");
    await page.locator('input[type="email"]').press("Enter");
    const response = await sent;
    if (response.ok()) break;
    if (response.status() !== 429 || attempt === 4) throw new Error(`UI sign-in request failed: HTTP ${response.status()}`);
    const body = await response.json();
    const seconds = Number(String(body.error ?? "").match(/(?:in|wait) (\d+) seconds/i)?.[1] ?? 60);
    console.log(`Sign-in cooldown: waiting ${seconds + 1}s before retry`);
    await page.waitForTimeout((seconds + 1) * 1000);
  }
  await page.locator('input[autocomplete="one-time-code"]').fill(await nextCode(mailbox));
}
async function record(event, details = {}) {
  const row = { at: new Date().toISOString(), event, ...details };
  await appendFile(`${evidenceDirectory}/results.jsonl`, `${JSON.stringify(row)}\n`, { mode: 0o600 });
  console.log(event, JSON.stringify(details));
}
// Start operations without blocking Playwright while the SDK waits for a user dialog.
async function approved(page, mailbox, operation, argument, buttons, validate) {
  await markSeen(mailbox);
  await page.evaluate(({ source, argument }) => {
    window.liveOperation = { done: false };
    Promise.resolve().then(() => (0, eval)(`(${source})`)(argument)).then(
      value => { window.liveOperation = { done: true, value: JSON.parse(JSON.stringify(value ?? null, (_k, v) => typeof v === "bigint" ? v.toString() : v)) }; },
      error => { window.liveOperation = { done: true, error: error.message }; },
    );
  }, { source: operation.toString(), argument });
  const deadline = Date.now() + 360_000;
  let nextProgress = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const state = await page.evaluate(() => window.liveOperation);
    if (state.done) {
      if (state.error) throw new Error(state.error);
      return state.value;
    }
    if (await page.getByRole("heading", { name: "Couldn't confirm", exact: true }).isVisible()) {
      const error = (await page.getByRole("alert").allTextContents()).join("; ");
      await page.getByRole("dialog").getByRole("button", { name: "Close", exact: true }).click();
      await page.waitForFunction(() => window.liveOperation.done);
      throw new Error(error);
    }
    if (Date.now() >= nextProgress) {
      console.log("Waiting for operation", JSON.stringify({ headings: await page.getByRole("dialog").getByRole("heading").allTextContents(), alerts: (await page.getByRole("alert").allTextContents()).map(text => text.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[disposable email]")) }));
      nextProgress = Date.now() + 30_000;
    }
    const code = page.locator('input[autocomplete="one-time-code"]');
    if (await code.isVisible() && await code.isEnabled() && !(await code.inputValue())) {
      const digits = Number(await code.getAttribute("maxlength")) || 8;
      const value = await nextCode(mailbox, digits);
      if (verifyWrongCode && digits === 8) {
        verifyWrongCode = false;
        await code.fill(value === "00000000" ? "11111111" : "00000000");
        await page.getByRole("alert").filter({ hasText: "That email code isn't right" }).waitFor({ timeout: 60_000 });
        await record("PASS incorrect confirmation code remains retryable");
      }
      await code.fill(value);
    } else {
      for (const name of buttons) {
        const button = page.getByRole("dialog").getByRole("button", { name, exact: true });
        if (await button.isVisible() && await button.isEnabled()) {
          if (validate) await validate(name, await page.getByRole("dialog").innerText());
          await button.click();
          break;
        }
      }
    }
    await page.waitForTimeout(500);
  }
  throw new Error(`Operation timed out; visible dialog: ${(await page.getByRole("dialog").getByRole("heading").allTextContents()).join(", ")}`);
}
async function rpc(method, params) {
  const result = await json("https://testnet.ckb.dev/", { id: 1, jsonrpc: "2.0", method, params });
  if (result.error) throw new Error(`CKB ${method}: ${result.error.message}`);
  return result.result;
}
async function committed(hash) {
  for (let attempt = 0; attempt < 90; attempt++) {
    const result = await rpc("get_transaction", [hash]);
    if (result?.tx_status.status === "committed") return result;
    if (result?.tx_status.status === "rejected") throw new Error(`CKB transaction rejected: ${hash}`);
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  throw new Error(`CKB transaction not committed within three minutes: ${hash}`);
}
async function fixture(page) {
  const isolation = { "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp" };
  await page.route(`${origin}/__sdk-verification*`, route => route.fulfill({ contentType: "text/html", headers: isolation, body: '<div id="root"></div><script src="/__sdk-fixture.js"></script>' }));
  await page.route(`${origin}/__sdk-fixture.js`, route => route.fulfill({ contentType: "text/javascript", headers: isolation, body: Buffer.from(bundle.outputFiles[0].contents) }));
  await page.goto(`${origin}/__sdk-verification?app=${encodeURIComponent(appId)}${browserMode ? "&browser" : ""}`, { waitUntil: "domcontentloaded", timeout: 120_000 });
}
function observeRuntime(page) {
  page.on("pageerror", error => console.log("Browser runtime error:", error.message.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[disposable email]")));
  page.on("console", message => { if (/panicked at|Uncaught RuntimeError/.test(message.text())) console.log("WASM diagnostic:", message.text().slice(0, 2000)); });
}
async function restoreFunded(entry, index) {
  const before = await entry.page.evaluate(async () => ({
    address: window.probe.account.address,
    node: (await window.probe.fiber.node.nodeInfo()).pubkey,
    channels: (await window.probe.fiber.refreshChannels()).filter(channel => channel.status === "ready").map(channel => channel.id).sort(),
  }));
  assert.ok(before.channels.length, "Handoff must include a funded channel");
  await entry.page.evaluate(() => window.probe.auth.logout());
  await entry.page.waitForFunction(() => !window.probe.auth.authenticated);
  await entry.context.close();
  const context = browserMode
    ? await chromium.launchPersistentContext(`${evidenceDirectory}/funded-handoff-${index}`, { headless: true, channel: "chrome" })
    : await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(120_000);
  observeRuntime(page);
  Object.assign(entry, { page, context });
  allPages.push({ ...entry });
  await fixture(page);
  await signIn(page, entry.mailbox);
  await page.waitForFunction(() => window.probe?.account.status === "ready", undefined, { timeout: 180_000 });
  await page.evaluate(() => window.probe.fiber.start());
  await page.waitForFunction(() => window.probe.fiber.status === "running" && window.probe.fiber.node, undefined, { timeout: 180_000 });
  const after = await page.evaluate(async () => ({
    address: window.probe.account.address,
    node: (await window.probe.fiber.node.nodeInfo()).pubkey,
    channels: (await window.probe.fiber.refreshChannels()).filter(channel => channel.status === "ready").map(channel => channel.id).sort(),
  }));
  assert.deepEqual(after, before, "A new device must recover the same wallet, node, and funded channels");
  await record("PASS funded channel handoff to new profile", { mode: browserMode ? "browser" : "hosted", ...after });
}
async function closeTransaction(page, outpoint) {
  assert.match(outpoint, /^0x[0-9a-f]{72}$/i);
  const hash = `0x${outpoint.slice(2, 66)}`;
  const index = Number.parseInt(outpoint.slice(66).match(/../g).reverse().join(""), 16);
  const funding = await committed(hash);
  for (let attempt = 0; attempt < 45; attempt++) {
    const history = await rpc("get_transactions", [{ script: funding.transaction.outputs[index].lock, script_type: "lock", script_search_mode: "exact" }, "desc", "0x64"]);
    for (const item of history.objects) {
      if (item.io_type !== "input") continue;
      const closed = await committed(item.tx_hash);
      if (!closed.transaction.inputs.some(input => input.previous_output.tx_hash === hash && Number(input.previous_output.index) === index)) continue;
      const returned = await page.evaluate(outputs => {
        const signer = window.probe.account.signer;
        return outputs.filter(output => window.ccc.Address.fromScript({ codeHash: output.lock.code_hash, hashType: output.lock.hash_type, args: output.lock.args }, signer.client).toString() === window.probe.account.address).reduce((total, output) => total + BigInt(output.capacity), 0n).toString();
      }, closed.transaction.outputs);
      assert.ok(BigInt(returned) > 0n, "Cooperative close must return funds to the disposable wallet");
      return { closingTransactionHash: item.tx_hash, returnedShannons: returned };
    }
    await page.waitForTimeout(2000);
  }
  throw new Error("Cooperative close not yet found on chain");
}
async function closeChannels(entry) {
  const { page, mailbox } = entry;
  const channels = await page.evaluate(() => window.probe.fiber.refreshChannels().then(channels => channels.map(({ id, status }) => ({ id, status }))));
  for (const channel of channels) {
    if (channel.status === "closed") continue;
    if (channel.status !== "closing") await approved(page, mailbox, id => window.probe.fiber.closeChannel(id), channel.id, ["Close channel"]);
    const deadline = Date.now() + 240_000;
    let closed;
    while (Date.now() < deadline) {
      closed = await page.evaluate(async id => (await window.probe.fiber.node.listChannels({ include_closed: true })).channels.find(channel => channel.channel_id === id), channel.id);
      if (closed?.state.state_name?.toLowerCase() === "closed") break;
      await page.waitForTimeout(3000);
    }
    assert.equal(closed?.state.state_name?.toLowerCase(), "closed", `Disposable channel did not close: ${channel.id}`);
    await record("PASS cooperative channel close", { channelId: channel.id, state: closed.state, fundingOutpoint: closed.channel_outpoint, ...await closeTransaction(page, closed.channel_outpoint) });
  }
}
const domain = (await json("https://api.mail.tm/domains"))["hydra:member"][0].domain;
const browser = await chromium.launch({ headless: true, channel: "chrome" });
const activePages = [];
const allPages = [];
const evidenceDirectory = process.env.REUSE_ACCOUNTS_DIRECTORY ?? await mkdtemp("/private/tmp/keyway-010-live-");
console.log(`Private disposable-account evidence: ${evidenceDirectory}`);
try {
  for (let index = 0; index < (productionUi ? 1 : 2); index++) {
    const accountNumber = index + 1 + Number(process.env.ACCOUNT_OFFSET ?? 0);
    const saved = await readFile(`${evidenceDirectory}/account-${accountNumber}.json`, "utf8").then(JSON.parse).catch(() => undefined);
    const email = saved?.email ?? `keyway-sdk-${randomBytes(8).toString("hex")}@${domain}`;
    const password = saved?.password ?? randomBytes(24).toString("base64url");
    if (!saved) await json("https://api.mail.tm/accounts", { address: email, password });
    const mailbox = { email, token: (await json("https://api.mail.tm/token", { address: email, password })).token, seen: new Set() };
    await writeFile(`${evidenceDirectory}/account-${accountNumber}.json`, JSON.stringify({ ...saved, email, password }), { mode: 0o600 });
    let expectedAddress = saved?.address, expectedNode = saved?.[browserMode ? "browserNode" : "hostedNode"];
    for (let device = process.env.SKIP_DEVICE_SMOKE === "1" ? 1 : 0; device < 2; device++) {
      // Keep browser-mode IndexedDB on disk until logout is verified; a failed backup must remain recoverable.
      const context = browserMode
        ? await chromium.launchPersistentContext(process.env.RESUME_HANDOFF_PROFILES === "1" ? `${evidenceDirectory}/funded-handoff-${index}` : `${evidenceDirectory}/browser-${accountNumber}-device-${device + 1}`, { headless: true, channel: "chrome" })
        : await browser.newContext();
      const page = await context.newPage();
      page.setDefaultTimeout(120_000);
      if (process.env.KEYWAY_TEST_SIGNING_PROXY) {
        await page.route(`${api}/sign-transaction`, async route => {
          const response = await route.fetch({ url: `${process.env.KEYWAY_TEST_SIGNING_PROXY}/api/v1/keyway/sign-transaction` });
          await route.fulfill({ response });
        });
      }
      observeRuntime(page);
      allPages.push({ page, context, mailbox });
      const calls = [];
      page.on("request", request => { if (request.url().endsWith("/managed-node") && request.method() === "POST") calls.push(request.postDataJSON()); });
      page.on("response", async response => {
        if (response.url().startsWith(api) && response.status() >= 400) {
          const body = await response.json().catch(() => ({}));
          const message = typeof body.error === "string" ? body.error : body.error?.message ?? body.message;
          console.log(`API failure: ${new URL(response.url()).pathname} HTTP ${response.status()}`, String(message ?? "").replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[disposable email]"));
        }
      });
      if (productionUi) {
        page.on("response", response => {
          if (response.url().includes("/api/v1/keyway/")) console.log(`Production API ${new URL(response.url()).pathname}: ${response.status()}`);
        });
        await page.goto(`${origin}/app${browserMode ? "?mode=browser" : ""}`, { waitUntil: "domcontentloaded", timeout: 60_000 });
        if (!await page.getByRole("button", { name: "Sign out", exact: true }).isVisible()) await signIn(page, mailbox, true);
        await page.getByRole("button", { name: "Start Fiber", exact: true }).waitFor({ timeout: 180_000 });
        const address = await page.locator(".copy-well__value").first().innerText();
        assert.ok(address.startsWith("ckt1"), "The live UI must show a testnet address");
        if (expectedAddress) assert.equal(address, expectedAddress); else expectedAddress = address;
        assert.equal(calls.length, 0, "Production login must not start Fiber");
        await page.getByRole("button", { name: "Start Fiber", exact: true }).click();
        await page.getByText(browserMode ? "Running · in-browser node" : "Running · hosted node", { exact: true }).waitFor({ timeout: 180_000 });
        await page.getByRole("button", { name: "Sign out", exact: true }).click();
        await page.getByRole("button", { name: "Sign in with email", exact: true }).waitFor({ timeout: 120_000 });
        await context.close();
        await record("PASS production UI", { mode: browserMode ? "browser" : "hosted", device: device + 1, checks: "UI email sign-in, account-only login, explicit connection, channel/setup display, logout" });
        continue;
      }
      await fixture(page);
      await page.waitForFunction(() => window.probe?.auth.ready);
      if (!await page.evaluate(() => window.probe.auth.authenticated)) await signIn(page, mailbox);
      await page.waitForFunction(() => ["ready", "error"].includes(window.probe?.account.status), undefined, { timeout: 180_000 });
      assert.equal(await page.evaluate(() => window.probe.account.status), "ready", "Real account recovery failed");
      assert.equal(calls.length, 0, "Login must not start managed Fiber");
      const address = await page.evaluate(() => window.probe.account.address);
      if (expectedAddress) assert.equal(address, expectedAddress); else expectedAddress = address;
      await page.waitForFunction(() => window.probe.account.balance !== undefined, undefined, { timeout: 60_000 });
      await page.evaluate(() => window.probe.fiber.start());
      // useFiber gives the node once the page has re-rendered as running; its public key comes from Fiber's node_info.
      await page.waitForFunction(() => window.probe.fiber.status === "running" && window.probe.fiber.node, undefined, { timeout: 180_000 });
      const node = await page.evaluate(async () => (await window.probe.fiber.node.nodeInfo()).pubkey);
      assert.equal(typeof node, "string");
      assert.ok(node.length > 60);
      if (expectedNode) assert.equal(node, expectedNode); else expectedNode = node;
      await writeFile(`${evidenceDirectory}/account-${accountNumber}.json`, JSON.stringify({ ...saved, email, password, address, [browserMode ? "browserNode" : "hostedNode"]: node }), { mode: 0o600 });
      await record("PASS stable wallet and node identity", { account: accountNumber, device: device + 1, mode: browserMode ? "browser" : "hosted", address, node });
      for (let restart = 0; restart < Number(process.env.VERIFY_RESTARTS ?? 0); restart++) {
        await page.evaluate(() => window.probe.fiber.stop());
        await page.waitForFunction(() => window.probe.fiber.status === "stopped");
        await page.evaluate(() => window.probe.fiber.start());
        await page.waitForFunction(() => window.probe.fiber.status === "running" && window.probe.fiber.node);
        assert.equal(await page.evaluate(async () => (await window.probe.fiber.node.nodeInfo()).pubkey), node);
        await record("PASS repeated node stop/start", { account: accountNumber, restart: restart + 1 });
      }
      if (verifyPayments && device === 1) {
        activePages.push({ page, context, mailbox });
        console.log(`PASS disposable account ${index + 1}: retained only for funded test`);
        continue;
      }
      await page.evaluate(() => window.probe.auth.logout());
      await page.waitForFunction(() => !window.probe.auth.authenticated);
      await context.close();
      console.log(`PASS disposable account ${index + 1}, device ${device + 1}: real OTP, wallet-only login, balance, explicit ${browserMode ? "browser" : "hosted"} connection, logout`);
    }
  }
  if (verifyPayments) {
    for (const entry of activePages) {
      const { page, mailbox } = entry;
      const address = await page.evaluate(() => window.probe.account.address);
      const balance = await page.evaluate(() => window.probe.account.balance.toString());
      if (BigInt(balance) < 100_000_000_000n) {
        await json("https://faucet-api.nervos.org/claim_events", { claim_event: { address_hash: address, amount: "10000" } });
        for (let attempt = 0; attempt < 90; attempt++) {
          const amount = await page.evaluate(async () => (await window.probe.account.refreshBalance()).toString());
          if (BigInt(amount) >= 100_000_000_000n) break;
          await new Promise(resolve => setTimeout(resolve, 3000));
        }
      }
      assert.ok(BigInt(await page.evaluate(async () => (await window.probe.account.refreshBalance()).toString())) >= 100_000_000_000n, "Faucet funding did not arrive");
      await record("PASS faucet funded disposable wallet", { address });
      if (!verifyChannels) continue;
      if (process.env.VERIFY_CANCELLED_OPENING === "1" && entry === activePages[0]) {
        await assert.rejects(
          () => approved(page, mailbox, () => window.probe.fiber.openChannel({ fundingAmount: 100_000_000_000n, public: true }), undefined, ["Cancel"]),
          /not approved/,
        );
        const unfinished = await page.evaluate(async () => (await window.probe.fiber.refreshChannels()).filter(channel => channel.status !== "closed"));
        assert.equal(unfinished.length, 0, "Declining funding must release the unsigned opening");
        await record("PASS declined funding releases unsigned opening");
      }
      const channels = await page.evaluate(() => window.probe.fiber.refreshChannels());
      if (!channels.some(channel => channel.status === "ready")) {
        const opened = await approved(page, mailbox, () => window.probe.fiber.openChannel({ fundingAmount: 100_000_000_000n, public: true }), undefined, ["Activate", "Continue"]);
        assert.ok(opened.fundingTxHash, "Channel funding must return its transaction hash");
        await committed(opened.fundingTxHash);
        await record("PASS disposable channel funding committed", { channelId: opened.channelId, fundingTxHash: opened.fundingTxHash, feeReserveTxHash: opened.feeReserveTxHash });
      }
      const ready = await page.evaluate(async () => (await window.probe.fiber.refreshChannels()).filter(channel => channel.status === "ready").map(channel => ({ id: channel.id, outpoint: channel.raw.channel_outpoint })));
      assert.ok(ready.length, "Channel must reach READY");
      await record("PASS disposable channel READY", { channels: ready });
    }
    async function verifyRoutedPayments() {
    for (const [senderEntry, receiverEntry] of verifyChannels ? [[activePages[0], activePages[1]], [activePages[1], activePages[0]]] : []) {
      const sender = senderEntry.page, receiver = receiverEntry.page;
      const invoice = await receiver.evaluate(async () => (await window.probe.fiber.createInvoice({ amount: "0x5f5e100", currency: "Fibt", description: "KeyWay disposable verification", expiry: "0xe10" })).invoice_address);
      let routable = false;
      for (let attempt = 0; attempt < 20; attempt++) {
        const estimate = await sender.evaluate(async invoice => {
          const result = await window.probe.fiber.estimatePayment({ invoice, max_fee_amount: "0x5f5e100" });
          return { routable: result.routable, error: result.error?.message };
        }, invoice);
        routable = estimate.routable;
        if (!routable && (attempt === 0 || attempt === 19)) await record("Payment route unavailable", estimate);
        if (routable) break;
        await new Promise(resolve => setTimeout(resolve, 3000));
      }
      assert.equal(routable, true, "No route for disposable 1 CKB payment");
      const payment = await approved(sender, senderEntry.mailbox, invoice => window.probe.fiber.payInvoice(invoice, { max_fee_amount: "0x5f5e100" }), invoice, []);
      assert.equal(payment.status, "Success");
      const received = await receiver.evaluate(hash => window.probe.fiber.getInvoice({ payment_hash: hash }), payment.payment_hash);
      assert.equal(received.status, "Paid");
      await record("PASS real routed 1 CKB payment", { paymentHash: payment.payment_hash, senderStatus: payment.status, receiverStatus: received.status });
    }
    }
    await verifyRoutedPayments();
    if (verifyChannels) for (const [index, entry] of activePages.entries()) await restoreFunded(entry, index);
    await verifyRoutedPayments();
    // A plain CKB transfer exercises the general signer, separate from channel funding.
    const sender = activePages[0], receiver = activePages[1];
    const destination = await receiver.page.evaluate(() => window.probe.account.address);
    const before = BigInt(await receiver.page.evaluate(async () => (await window.probe.account.refreshBalance()).toString()));
    const hash = await approved(sender.page, sender.mailbox, async destination => {
      const signer = window.probe.account.signer;
      const lock = (await window.ccc.Address.fromString(destination, signer.client)).script;
      const tx = window.ccc.Transaction.from({ outputs: [{ lock, capacity: 100n * 100_000_000n }] });
      await tx.completeInputsByCapacity(signer);
      await tx.completeFeeBy(signer, 1_000n);
      return signer.sendTransaction(tx);
    }, destination, ["Continue", "Approve"], async (button, text) => {
      if (button === "Approve") {
        assert.ok(text.includes(destination), "Approval must show the exact disposable recipient");
        assert.ok(text.includes("CKB testnet"), "Approval must identify testnet");
        assert.ok(text.includes("100 CKB"), "Approval must show 100 CKB");
      }
    });
    await committed(hash);
    let after;
    for (let attempt = 0; attempt < 30; attempt++) {
      after = BigInt(await receiver.page.evaluate(async () => (await window.probe.account.refreshBalance()).toString()));
      if (after >= before + 100n * 100_000_000n) break;
      await receiver.page.waitForTimeout(2000);
    }
    assert.ok(after >= before + 100n * 100_000_000n, "Recipient balance must increase by 100 CKB");
    await record("PASS plain 100 CKB transfer committed", { transactionHash: hash, destination, receivedShannons: (after - before).toString() });
    for (const entry of activePages) await closeChannels(entry);
    for (const { page } of activePages) await page.evaluate(() => window.probe.auth.logout());
    await record("PASS full funded flow and transactional logout", { mode: browserMode ? "browser" : "hosted" });
  }
} catch (error) {
  await record("FAIL live verification", { error: String(error.message).replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[disposable email]") });
  for (const { page } of allPages) {
    if (page.isClosed()) continue;
    await record("Failure page state", {
      headings: await page.getByRole("heading").allTextContents().catch(() => []),
      alerts: (await page.getByRole("alert").allTextContents().catch(() => [])).map(text => text.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[disposable email]")),
    });
  }
  throw error;
} finally {
  for (const entry of activePages) {
    if (entry.page.isClosed()) continue;
    if (await entry.page.evaluate(() => window.probe?.fiber.status === "running").catch(() => false)) {
      await closeChannels(entry).catch(async error => { process.exitCode = 1; await record("FAIL disposable channel cleanup; resume this evidence directory", { error: error.message }); });
    }
  }
  for (const { page, context } of allPages) {
    if (page.isClosed()) continue;
    if (!productionUi) await page.evaluate(() => window.probe?.auth.authenticated ? window.probe.auth.logout() : undefined).catch(async error => { process.exitCode = 1; await record("FAIL logout cleanup", { error: error.message }); });
    await context.close();
  }
  await browser.close();
}

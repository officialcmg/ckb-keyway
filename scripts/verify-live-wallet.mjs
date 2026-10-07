import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, writeFile, readFile } from "node:fs/promises";
import { build } from "esbuild";

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ?? "playwright");
const api = "https://keyway-api-production.up.railway.app/api/v1/keyway";
const origin = "https://ckbkeyway.dev";
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
async function login(mailbox) {
  const existing = await json("https://api.mail.tm/messages", undefined, mailbox.token);
  for (const message of existing["hydra:member"]) mailbox.seen.add(message.id);
  const { challengeId } = await json(`${api}/auth/send-code`, { email: mailbox.email });
  for (let attempt = 0; attempt < 30; attempt++) {
    const messages = await json("https://api.mail.tm/messages", undefined, mailbox.token);
    for (const message of messages["hydra:member"]) {
      if (mailbox.seen.has(message.id)) continue;
      const full = await json(`https://api.mail.tm/messages/${message.id}`, undefined, mailbox.token);
      const match = `${full.text ?? ""} ${full.html?.join(" ") ?? ""}`.match(/\b\d{6}\b/);
      if (match) {
        mailbox.seen.add(message.id);
        return json(`${api}/auth/verify-code`, { challengeId, code: match[0] });
      }
    }
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  throw new Error("Disposable OTP email did not arrive within one minute");
}
const domain = (await json("https://api.mail.tm/domains"))["hydra:member"][0].domain;
const browser = await chromium.launch({ headless: true, channel: "chrome" });
const activePages = [];
const evidenceDirectory = process.env.REUSE_ACCOUNTS_DIRECTORY ?? await mkdtemp("/private/tmp/keyway-010-live-");
console.log(`Private disposable-account evidence: ${evidenceDirectory}`);
try {
  for (let index = 0; index < (process.env.PRODUCTION_UI === "1" ? 1 : 2); index++) {
    const accountNumber = index + 1 + Number(process.env.ACCOUNT_OFFSET ?? 0);
    const saved = await readFile(`${evidenceDirectory}/account-${accountNumber}.json`, "utf8").then(JSON.parse).catch(() => undefined);
    const email = saved?.email ?? `keyway-sdk-${randomBytes(8).toString("hex")}@${domain}`;
    const password = saved?.password ?? randomBytes(24).toString("base64url");
    if (!saved) await json("https://api.mail.tm/accounts", { address: email, password });
    const mailbox = { email, token: (await json("https://api.mail.tm/token", { address: email, password })).token, seen: new Set() };
    await writeFile(`${evidenceDirectory}/account-${accountNumber}.json`, JSON.stringify({ email, password }), { mode: 0o600 });
    let expectedAddress, expectedNode;
    for (let device = 0; device < (process.env.PRODUCTION_UI === "1" ? 1 : 2); device++) {
      const session = await login(mailbox);
      const context = await browser.newContext();
      await context.addInitScript(({ session, appId }) => localStorage.setItem(`ckb-keyway.session.v2:${appId}`, JSON.stringify({ authToken: session.sessionToken, user: session.user, expiresAt: session.expiresAt, appId })), { session, appId });
      const page = await context.newPage();
      const calls = [];
      page.on("request", request => { if (request.url().endsWith("/managed-node")) calls.push(request.postDataJSON()); });
      if (process.env.PRODUCTION_UI === "1") {
        page.on("response", response => {
          if (response.url().includes("/api/v1/keyway/")) console.log(`Production API ${new URL(response.url()).pathname}: ${response.status()}`);
        });
        await page.goto(`${origin}/app`, { waitUntil: "domcontentloaded", timeout: 60_000 });
        await page.waitForTimeout(8000);
        console.log(JSON.stringify({ headings: await page.getByRole("heading").allTextContents(), buttons: await page.getByRole("button").allTextContents() }));
        await page.getByRole("heading", { name: "Your account. Fiber when you need it." }).waitFor({ timeout: 120_000 });
        assert.equal(calls.length, 0, "Production login must not start Fiber");
        await page.getByRole("button", { name: "Connect Fiber", exact: true }).click();
        await page.getByRole("heading", { name: /^(Your channels|Activate instant payments)$/ }).first().waitFor({ timeout: 120_000 });
        await page.getByRole("button", { name: "Log out", exact: true }).click();
        await page.getByRole("button", { name: "Log in with email", exact: true }).waitFor({ timeout: 30_000 });
        await context.close();
        console.log("PASS production UI: account-only login, explicit connection, channel/setup display, logout");
        continue;
      }
      await page.route(`${origin}/__sdk-verification*`, route => route.fulfill({ contentType: "text/html", body: '<div id="root"></div><script src="/__sdk-fixture.js"></script>' }));
      await page.route(`${origin}/__sdk-fixture.js`, route => route.fulfill({ contentType: "text/javascript", body: Buffer.from(bundle.outputFiles[0].contents) }));
      await page.goto(`${origin}/__sdk-verification?app=${encodeURIComponent(appId)}`, { waitUntil: "domcontentloaded", timeout: 120_000 });
      await page.waitForFunction(() => ["ready", "error"].includes(window.probe?.account.status), undefined, { timeout: 180_000 });
      assert.equal(await page.evaluate(() => window.probe.account.status), "ready", "Real account recovery failed");
      assert.equal(calls.length, 0, "Login must not start managed Fiber");
      const address = await page.evaluate(() => window.probe.account.address);
      if (expectedAddress) assert.equal(address, expectedAddress); else expectedAddress = address;
      await page.waitForFunction(() => window.probe.account.balance !== undefined, undefined, { timeout: 60_000 });
      await page.evaluate(() => window.probe.fiber.connect());
      const node = await page.evaluate(() => window.probe.fiber.connection.node.pubkey);
      assert.equal(typeof node, "string");
      assert.ok(node.length > 60);
      if (expectedNode) assert.equal(node, expectedNode); else expectedNode = node;
      if (process.env.VERIFY_PAYMENTS === "1" && device === 1) {
        activePages.push({ page, context });
        console.log(`PASS disposable account ${index + 1}: retained only for funded test`);
        continue;
      }
      await page.evaluate(() => window.probe.auth.logout());
      assert.equal(await page.evaluate(() => window.probe.auth.authenticated), false);
      await context.close();
      console.log(`PASS disposable account ${index + 1}, device ${device + 1}: real OTP, wallet-only login, balance, explicit managed connection, logout`);
    }
  }
  if (process.env.VERIFY_PAYMENTS === "1") {
    for (const { page } of activePages) {
      const address = await page.evaluate(() => window.probe.account.address);
      const balance = await page.evaluate(() => window.probe.account.balance.toString());
      if (BigInt(balance) < 100_000_000_000n) {
        await json("https://faucet-api.nervos.org/claim_events", { claim_event: { address_hash: address, amount: "10000" } });
        for (let attempt = 0; attempt < 30; attempt++) {
          const amount = await page.evaluate(async () => (await window.probe.account.refreshBalance()).toString());
          if (BigInt(amount) >= 100_000_000_000n) break;
          await new Promise(resolve => setTimeout(resolve, 3000));
        }
      }
      const channels = await page.evaluate(() => window.probe.fiber.refreshChannels());
      if (!channels.some(channel => channel.status === "ready")) {
        await page.evaluate(() => { window.opening = window.probe.fiber.openChannel({ fundingAmount: 100_000_000_000n, public: true }); });
        await page.getByRole("button", { name: "Confirm activation", exact: true }).click({ timeout: 120_000 });
        await page.evaluate(() => window.opening);
      }
      console.log("PASS disposable channel funded and ready");
    }
    for (const [sender, receiver] of [[activePages[0].page, activePages[1].page], [activePages[1].page, activePages[0].page]]) {
      const invoice = await receiver.evaluate(async () => (await window.probe.fiber.createInvoice({ amount: "0x5f5e100", currency: "Fibt", description: "KeyWay disposable verification", expiry: "0x36ee80" })).invoice_address);
      let routable = false;
      for (let attempt = 0; attempt < 20; attempt++) {
        routable = await sender.evaluate(async invoice => (await window.probe.fiber.preflightPayment({ invoice, max_fee_amount: "0x5f5e100" })).routable, invoice);
        if (routable) break;
        await new Promise(resolve => setTimeout(resolve, 3000));
      }
      assert.equal(routable, true, "No route for disposable 1 CKB payment");
      const payment = await sender.evaluate(invoice => window.probe.fiber.payInvoice(invoice, { max_fee_amount: "0x5f5e100" }), invoice);
      assert.equal(payment.status, "Success");
      const received = await receiver.evaluate(hash => window.probe.fiber.getInvoice({ payment_hash: hash }), payment.payment_hash);
      assert.equal(received.status, "Paid");
      console.log(`PASS real routed 1 CKB payment: ${payment.payment_hash}`);
    }
    for (const { page } of activePages) await page.evaluate(() => window.probe.auth.logout());
  }
} finally {
  for (const { page } of activePages) await page.evaluate(() => window.probe.auth.logout()).catch(() => undefined);
  await browser.close();
}

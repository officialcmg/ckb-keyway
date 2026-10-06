import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, writeFile, readFile } from "node:fs/promises";
import { build } from "esbuild";

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ?? "playwright");
const api = "https://keyway-api-production.up.railway.app/api/v1/keyway";
const origin = "https://ckbkeyway.dev";
const bundle = await build({ entryPoints: ["tests/fixtures/react-sdk.tsx"], bundle: true, write: false, platform: "browser", format: "iife", jsx: "automatic", define: { "process.env.KEYWAY_API_TARGET": '"production"', "process.env.NODE_ENV": '"development"' } });
async function json(url, body, token, headers = {}) {
  let response;
  for (let attempt = 0; attempt < 4; attempt++) {
    response = await fetch(url, { method: body ? "POST" : "GET", headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers }, ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(30_000) });
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
  const { methodId } = await json(`${api}/auth/send-code`, { email: mailbox.email }, undefined, { Origin: origin });
  for (let attempt = 0; attempt < 30; attempt++) {
    const messages = await json("https://api.mail.tm/messages", undefined, mailbox.token);
    for (const message of messages["hydra:member"]) {
      if (mailbox.seen.has(message.id)) continue;
      const full = await json(`https://api.mail.tm/messages/${message.id}`, undefined, mailbox.token);
      const match = `${full.text ?? ""} ${full.html?.join(" ") ?? ""}`.match(/\b\d{6}\b/);
      if (match) {
        mailbox.seen.add(message.id);
        return json(`${api}/auth/verify-code`, { methodId, code: match[0] }, undefined, { Origin: origin });
      }
    }
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  throw new Error("Disposable OTP email did not arrive within one minute");
}
const domain = (await json("https://api.mail.tm/domains"))["hydra:member"][0].domain;
const browser = await chromium.launch({ headless: true, channel: "chrome" });
const evidenceDirectory = process.env.REUSE_ACCOUNTS_DIRECTORY ?? await mkdtemp("/private/tmp/keyway-010-live-");
console.log(`Private disposable-account evidence: ${evidenceDirectory}`);
try {
  for (let index = 0; index < 2; index++) {
    const saved = await readFile(`${evidenceDirectory}/account-${index + 1}.json`, "utf8").then(JSON.parse).catch(() => undefined);
    const email = saved?.email ?? `keyway-sdk-${randomBytes(8).toString("hex")}@${domain}`;
    const password = saved?.password ?? randomBytes(24).toString("base64url");
    if (!saved) await json("https://api.mail.tm/accounts", { address: email, password });
    const mailbox = { email, token: (await json("https://api.mail.tm/token", { address: email, password })).token, seen: new Set() };
    await writeFile(`${evidenceDirectory}/account-${index + 1}.json`, JSON.stringify({ email, password }), { mode: 0o600 });
    let expectedAddress, expectedNode;
    for (let device = 0; device < 2; device++) {
      const session = await login(mailbox);
      const context = await browser.newContext();
      await context.addInitScript(session => localStorage.setItem("ckb-keyway.session", JSON.stringify({ authToken: session.sessionToken, user: session.user })), session);
      const page = await context.newPage();
      const calls = [];
      page.on("request", request => { if (request.url().endsWith("/managed-node")) calls.push(request.postDataJSON()); });
      await page.route(`${origin}/__sdk-verification`, route => route.fulfill({ contentType: "text/html", body: '<div id="root"></div><script src="/__sdk-fixture.js"></script>' }));
      await page.route(`${origin}/__sdk-fixture.js`, route => route.fulfill({ contentType: "text/javascript", body: Buffer.from(bundle.outputFiles[0].contents) }));
      await page.goto(`${origin}/__sdk-verification`, { waitUntil: "domcontentloaded", timeout: 120_000 });
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
      await page.evaluate(() => window.probe.auth.logout());
      assert.equal(await page.evaluate(() => window.probe.auth.authenticated), false);
      await context.close();
      console.log(`PASS disposable account ${index + 1}, device ${device + 1}: real OTP, wallet-only login, balance, explicit managed connection, logout`);
    }
  }
} finally { await browser.close(); }

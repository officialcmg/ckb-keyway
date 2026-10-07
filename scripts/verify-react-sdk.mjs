import assert from "node:assert/strict";
import { createServer } from "node:http";
import { build } from "esbuild";

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ?? "playwright");
const bundle = await build({ entryPoints: ["tests/fixtures/react-sdk.tsx"], bundle: true, write: false, platform: "browser", format: "iife", jsx: "automatic", define: { "process.env.KEYWAY_API_TARGET": '"production"', "process.env.NODE_ENV": '"development"' } });
const server = createServer((request, response) => {
  response.setHeader("Content-Type", request.url === "/fixture.js" ? "text/javascript" : "text/html");
  response.end(request.url === "/fixture.js" ? bundle.outputFiles[0].contents : '<div id="root"></div><script src="/fixture.js"></script>');
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const browser = await chromium.launch({ headless: true, channel: "chrome" });
const wallet = { version: 1, status: "ready", litPkpId: "disposable", litPublicKey: "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", ckbAddress: "test-address", primaryDeviceIdHash: "test", hasOpenedChannel: false, createdAt: "test", updatedAt: "test" };
try {
  for (const scenario of ["default", "browser", "auto", "recovery-failure", "balance-failure", "logout-race", "payment-refresh-failure"]) {
    const context = await browser.newContext();
    await context.addInitScript(() => localStorage.setItem("ckb-keyway.session.v2:unregistered", JSON.stringify({ authToken: "mock-disposable-token", user: { id: "test" }, expiresAt: new Date(Date.now() + 86_400_000).toISOString() })));
    const page = await context.newPage();
    const calls = [], errors = [];
    page.on("pageerror", error => errors.push(error.message));
    let release, paid = false;
    const barrier = new Promise(resolve => { release = resolve; });
    await page.route("**/*", async route => {
      const url = route.request().url();
      if (url.includes("/api/v1/keyway/")) {
        const body = route.request().postDataJSON();
        calls.push({ url, body });
        let result = {}, status = 200;
        if (url.endsWith("/auth/session")) result = { user: { id: "test" }, expiresAt: new Date(Date.now() + 86_400_000).toISOString() };
        else if (url.endsWith("/bootstrap")) {
          if (scenario === "logout-race") await barrier;
          if (scenario === "recovery-failure") { status = 400; result = { error: "Recovery rejected" }; }
          else result = { needsFiberKey: false, provisioned: false, restoreRequired: false, wallet };
        } else if (url.endsWith("/managed-node")) {
          if (body.operation === "status") result = { node: { node_id: "test" }, peers: [] };
          else if (body.operation === "list-channels") {
            if (paid) { status = 400; result = { error: "Refresh unavailable" }; }
            else result = { channels: [] };
          } else if (body.operation === "preflight-payment") result = { routable: true, fee: "0x0", confirmationNonce: "test-nonce" };
          else if (body.operation === "send-payment") { paid = true; result = { payment_hash: "0x123", status: "Success" }; }
          else if (body.operation === "get-payment" || body.operation === "wait-for-payment") result = { payment_hash: "0x123", status: "Success" };
          else throw new Error(`Unexpected operation: ${body.operation}`);
        }
        await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(result) }); return;
      }
      if (url.includes("ckbapp.dev") || url.includes("testnet.ckb.dev")) {
        const body = route.request().postDataJSON();
        await route.fulfill({ contentType: "application/json", body: JSON.stringify({ jsonrpc: "2.0", id: body.id, ...(scenario === "balance-failure" ? { error: { code: -32603, message: "Balance unavailable" } } : { result: { objects: [], last_cursor: "0x" } }) }) }); return;
      }
      assert.ok(url.startsWith("http://127.0.0.1:"), "Unexpected external traffic");
      await route.continue();
    });
    await page.goto(`http://127.0.0.1:${server.address().port}/?${scenario === "auto" ? "auto" : scenario === "browser" ? "browser" : ""}`);
    await page.waitForFunction(() => window.probe?.auth.authenticated);
    if (scenario === "logout-race") {
      await page.evaluate(() => window.probe.auth.logout()); release();
      await page.waitForTimeout(100);
      assert.equal(await page.evaluate(() => window.probe.account.wallet), undefined);
    } else if (scenario === "recovery-failure") {
      await page.waitForFunction(() => window.probe.account.error);
      assert.equal(await page.evaluate(() => window.probe.fiber.status), "disconnected");
    } else {
      await page.waitForFunction(() => window.probe.account.wallet);
      if (scenario === "auto") await page.waitForFunction(() => window.probe.fiber.status === "connected");
      else {
        assert.equal(calls.some(call => call.url.endsWith("/managed-node")), false);
        assert.equal(await page.evaluate(() => window.probe.fiber.status), "disconnected");
        if (scenario === "balance-failure") await page.waitForFunction(() => window.probe.account.error);
        else await page.waitForFunction(() => window.probe.account.balance === 0n);
        if (scenario === "default" || scenario === "payment-refresh-failure") {
          await page.evaluate(async () => {
            const fiber = window.probe.fiber;
            await fiber.connect();
            await fiber.refreshChannels();
          });
          assert.equal(await page.evaluate(() => window.probe.fiber.status), "connected");
          if (scenario === "payment-refresh-failure") {
            const result = await page.evaluate(() => window.probe.fiber.payInvoice("mock-invoice"));
            assert.equal(result.status, "Success");
          }
          await page.evaluate(() => window.probe.fiber.disconnect());
          assert.equal(await page.evaluate(() => window.probe.fiber.status), "disconnected");
          assert.equal(await page.evaluate(() => window.probe.account.status), "ready");
        }
      }
    }
    assert.deepEqual(errors, []);
    console.log(`PASS ${scenario}`);
    await context.close();
  }
} finally {
  await browser.close();
  await new Promise(resolve => server.close(resolve));
}

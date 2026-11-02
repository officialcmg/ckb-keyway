/**
 * Proof in headless Chromium: under COOP same-origin + COEP require-corp (+ KeyWay's real CSP from proxy.ts,
 * X-Frame-Options DENY, Referrer-Policy strict-origin-when-cross-origin), a cross-origin popup loses
 * window.opener so its postMessage never arrives, while a top-level navigation round trip to a cross-origin
 * page and back works, keeps sessionStorage, and lands cross-origin isolated again.
 *
 * "wallet" (127.0.0.1:4200) mimics JoyID's two delivery paths exactly as its bundle does them
 * (sendMessageToDapp + the referrer guard), sends JoyID's own headers (no COOP, X-Frame-Options DENY) and uses
 * the real @joyid/common encode/decode. "app" (localhost:4100) uses the real @joyid/common buildJoyIDURL /
 * getRedirectResponse / isRedirectFromJoyID.
 *
 * Run: node --import tsx research/joyid-redirect/proofs/coop-browser.ts
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { contentSecurityPolicy } from "../../../proxy";

// The environment's preinstalled Playwright (global), not a repo dependency.
const { chromium } = createRequire(import.meta.url)("playwright") as typeof import("playwright");
const APP = "http://localhost:4100";
const WALLET = "http://127.0.0.1:4200";
const joyidCommon = readFileSync(new URL("../../../node_modules/@joyid/common/dist/index.js", import.meta.url));
const serverLog: string[] = [];
const referers: Record<string, string | undefined> = {};

function appHeaders(coop: string, coep: string, nonce: string) {
  return {
    "Cross-Origin-Opener-Policy": coop,
    "Cross-Origin-Embedder-Policy": coep,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    // KeyWay's CSP verbatim, except the local http wallet origin is added to connect-src so the Referer probe can
    // run over plain http (production connect-src already allows any https: origin).
    "Content-Security-Policy": contentSecurityPolicy(nonce).replace("connect-src 'self' https: wss:", `connect-src 'self' https: wss: ${WALLET}`),
  };
}

const appPage = (nonce: string) => `<!doctype html><meta charset=utf-8><title>app</title>
<script type="module" nonce="${nonce}">
const { buildJoyIDURL, getRedirectResponse, isRedirectFromJoyID } = await import("/joyid-common.js");
const out = window.__result = { crossOriginIsolated, sab: typeof SharedArrayBuffer };
window.startPopup = () => new Promise((resolve) => {
  const url = buildJoyIDURL({ redirectURL: location.href, joyidAppURL: "${WALLET}", challenge: "hello", isData: false, address: "ckt1x" }, "popup", "/sign-message");
  const popup = window.open(url, "joyid:authorize:popup", "width=400,height=600");
  let got = null;
  addEventListener("message", (e) => { if (e.origin === "${WALLET}") got = e.data; });
  setTimeout(() => resolve({ popupHandleClosed: popup ? popup.closed : "null handle", received: got }), 2500);
});
// Hybrid: a same-origin helper WINDOW runs JoyID's redirect mode and relays the result over BroadcastChannel,
// so this tab (and a browser Fiber node in it) never unloads.
window.startHybrid = () => new Promise((resolve) => {
  const id = crypto.randomUUID();
  const channel = new BroadcastChannel("keyway:joyid");
  const helper = window.open("/joyid-return?start=" + id, "keyway-joyid", "width=420,height=640");
  channel.onmessage = (e) => { if (e.data?.state?.id !== id) return; setTimeout(() => resolve({ received: e.data, helperClosed: helper ? helper.closed : "null handle", stillIsolated: crossOriginIsolated }), 500); };
  setTimeout(() => resolve({ timeout: true }), 10000);
});
window.startRedirect = () => {
  const state = { v: 1, id: crypto.randomUUID() };
  sessionStorage.setItem("keyway:joyid-pending", JSON.stringify({ state, op: "backup", startedAt: Date.now() }));
  localStorage.setItem("probe:local", "kept");
  // Hold a Web Lock forever, as device-lock.ts does while the browser Fiber node runs.
  navigator.locks.request("ckb-keyway:fiber:probe", { ifAvailable: true }, (lock) => lock ? new Promise(() => {}) : undefined);
  location.assign(buildJoyIDURL({ redirectURL: location.href, joyidAppURL: "${WALLET}", challenge: "hello", isData: false, address: "ckt1x", state }, "redirect", "/sign-message"));
};
if (location.pathname === "/joyid-return") {
  const start = new URL(location.href).searchParams.get("start");
  if (start) {
    location.assign(buildJoyIDURL({ redirectURL: location.origin + "/joyid-return", joyidAppURL: "${WALLET}", challenge: "hello", isData: false, address: "ckt1x", state: { v: 1, id: start } }, "redirect", "/sign-message"));
  } else if (isRedirectFromJoyID()) {
    const data = getRedirectResponse();
    history.replaceState(null, "", "/joyid-return");
    new BroadcastChannel("keyway:joyid").postMessage(data);
    window.close();
  }
} else if (isRedirectFromJoyID()) {
  out.returnedURL = location.href;
  out.pending = sessionStorage.getItem("keyway:joyid-pending");
  out.local = localStorage.getItem("probe:local");
  out.data = getRedirectResponse();
  out.historyLengthOnReturn = history.length;
  out.fiberLockReacquired = await navigator.locks.request("ckb-keyway:fiber:probe", { ifAvailable: true }, (lock) => Boolean(lock));
  await fetch("${WALLET}/pixel?probe=cross", { mode: "no-cors" }).catch(() => {});
  await fetch("/pixel?probe=same").catch(() => {});
  history.replaceState(history.state, "", location.pathname);
  out.urlAfterReplace = location.href;
  out.done = true;
}
</script>`;

// The JoyID stand-in: same branches as JoyID's sendMessageToDapp and useGuardRedirectUri / referrer check.
const walletPage = `<!doctype html><meta charset=utf-8><title>wallet</title>
<script type="module">
const { decodeSearch, encodeSearch } = await import("/joyid-common.js");
const params = new URL(location.href).searchParams;
const type = params.get("type"), req = decodeSearch(params.get("_data_"));
const report = (o) => fetch("/report?" + new URLSearchParams({ o: JSON.stringify(o) }));
const msg = { type: "SignMessage", data: { signature: "sig", message: "msg", challenge: req.challenge, alg: -7, pubkey: "00", keyType: "main_key", state: req.state }, state: req.state };
await report({ type, openerIsNull: window.opener === null, referrer: document.referrer });
if (type === "popup") {
  if (window.opener) window.opener.postMessage(msg, new URL(req.redirectURL).origin);
} else {
  if (document.referrer && new URL(req.redirectURL).origin !== new URL(document.referrer).origin) { await report({ guard: "REJECTED" }); }
  else { const u = new URL(req.redirectURL); u.searchParams.set("_data_", encodeSearch(msg)); location.replace(u.href); }
}
</script>`;

const reports: unknown[] = [];
function serve(port: number, handler: (req: IncomingMessage, res: ServerResponse) => void) {
  return new Promise<ReturnType<typeof createServer>>((resolve) => { const s = createServer(handler); s.listen(port, () => resolve(s)); });
}
let appCoop = "same-origin", appCoep = "require-corp";
const app = await serve(4100, (req, res) => {
  serverLog.push(`app  ${req.method} ${req.url}`);
  const url = new URL(req.url!, APP);
  if (url.pathname === "/joyid-common.js") { res.writeHead(200, { "content-type": "text/javascript", "Cross-Origin-Resource-Policy": "same-origin" }); res.end(joyidCommon); return; }
  if (url.pathname === "/pixel") { referers[`same:${appCoop}`] = req.headers.referer; res.writeHead(204, { "Cross-Origin-Resource-Policy": "same-origin" }); res.end(); return; }
  const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("base64");
  res.writeHead(200, { "content-type": "text/html", ...appHeaders(appCoop, appCoep, nonce) });
  res.end(appPage(nonce));
});
const wallet = await serve(4200, (req, res) => {
  serverLog.push(`wallet ${req.method} ${req.url!.slice(0, 160)}${req.url!.length > 160 ? "…" : ""}`);
  const url = new URL(req.url!, WALLET);
  if (url.pathname === "/joyid-common.js") { res.writeHead(200, { "content-type": "text/javascript" }); res.end(joyidCommon); return; }
  if (url.pathname === "/report") { reports.push(JSON.parse(url.searchParams.get("o")!)); res.writeHead(204, { "Access-Control-Allow-Origin": "*" }); res.end(); return; }
  if (url.pathname === "/pixel") { referers[`cross:${appCoop}`] = req.headers.referer; res.writeHead(204, { "Cross-Origin-Resource-Policy": "cross-origin" }); res.end(); return; }
  res.writeHead(200, { "content-type": "text/html", "X-Frame-Options": "DENY", "Strict-Transport-Security": "max-age=63072000" }); // JoyID's headers: no COOP, no COEP
  res.end(walletPage);
});

const browser = await chromium.launch();
const results: Record<string, unknown> = { chromium: browser.version() };
try {
  for (const [coop, coep] of [["same-origin", "require-corp"], ["same-origin-allow-popups", "unsafe-none"]]) {
    appCoop = coop; appCoep = coep; reports.length = 0;
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(`${APP}/wallet`);
    await page.waitForFunction(() => (window as never as { __result?: unknown }).__result);
    const isolated = await page.evaluate(() => (window as never as { __result: unknown }).__result);
    const popupResult = await page.evaluate(() => (window as never as { startPopup: () => Promise<unknown> }).startPopup());
    results[`POPUP  app COOP=${coop} COEP=${coep}`] = { appBefore: isolated, popupResult, walletSaw: reports.slice() };
    await context.close();
  }
  {
    appCoop = "same-origin"; appCoep = "require-corp"; reports.length = 0;
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(`${APP}/wallet`);
    await page.waitForFunction(() => (window as never as { startHybrid?: unknown }).startHybrid);
    const hybrid = await page.evaluate(() => (window as never as { startHybrid: () => Promise<unknown> }).startHybrid());
    results["HYBRID helper window + redirect + BroadcastChannel, app COOP=same-origin COEP=require-corp"] = { hybrid, walletSaw: reports.slice(), openPages: context.pages().map((p) => p.url()) };
    await context.close();
  }
  appCoop = "same-origin"; appCoep = "require-corp"; reports.length = 0;
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`${APP}/wallet?tab=recovery`);
  await page.waitForFunction(() => (window as never as { startRedirect?: unknown }).startRedirect);
  serverLog.length = 0;
  await page.evaluate(() => (window as never as { startRedirect: () => void }).startRedirect());
  await page.waitForFunction(() => (window as never as { __result?: { done?: boolean } }).__result?.done, undefined, { timeout: 15000 });
  const r = await page.evaluate(() => (window as never as { __result: unknown }).__result);
  results["REDIRECT app COOP=same-origin COEP=require-corp"] = { result: r, walletSaw: reports.slice(), referers: { ...referers }, serverLog: serverLog.slice() };
  // Back button after the round trip: what is in session history?
  await page.goBack().catch(() => {});
  results["after history.back()"] = page.url();
  await context.close();
} finally {
  await browser.close(); app.close(); wallet.close();
}
console.log(JSON.stringify(results, null, 2));

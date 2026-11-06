/**
 * End-to-end check of KeyWay's JoyID transports in headless Chromium, against the real demo (`/app`) served by
 * `next start` with the real next.config.ts headers (COOP same-origin, COEP require-corp) and proxy.ts CSP.
 *
 * - The KeyWay API (keyway-api-production…) is faked by request routing. It issues challenge nonces and runs
 *   KeyWay's own `verifyBackupOwnership` on every backup proof it gets, as the real server does.
 * - JoyID (testnet.joyid.dev) is faked by request routing too. Its page does what JoyID's does in redirect mode
 *   (research/joyid-redirect): refuses a redirectURL whose origin isn't the referrer's, signs the request with a
 *   real P-256 passkey (Auth without a challenge; SignMessage over base64url(utf8(challenge))), writes the answer
 *   into the return URL's `_data_` query parameter and calls `location.replace`.
 *
 * Build first: `npm run build:sdk && KEYWAY_LOCAL_SDK=1 npx next build`.
 * Run: NODE_PATH=$(npm root -g) node --import tsx research/joyid-transport/e2e.ts
 * With KEYWAY_E2E_DEV=1 it runs against `next dev` instead (React StrictMode on) and writes e2e-dev.output.txt.
 */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import * as ccc from "@ckb-ccc/core";
import { p256 } from "@noble/curves/nist.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { decodeSearch, encodeSearch } from "@joyid/common";
import { adminListTypeScript, KEYWAY_OMNILOCK, omnilockArgsFor } from "../../src/sdk/browser/account-lock";
import { recoveryAccountAddress } from "../../src/sdk/browser/account-recovery";
import { describeBackup, parseBackups, verifyBackupOwnership } from "../../src/sdk/browser/recovery-backups";

type Browser = import("playwright").Browser;
type BrowserContext = import("playwright").BrowserContext;
type Page = import("playwright").Page;
type Route = import("playwright").Route;
const { chromium } = createRequire(import.meta.url)("playwright") as typeof import("playwright");

const root = new URL("../../", import.meta.url).pathname;
const DEV = process.env.KEYWAY_E2E_DEV === "1";
const PORT = 3100;
const APP = `http://localhost:${PORT}`;
const API = "https://keyway-api-production.up.railway.app";
const JOYID = "https://testnet.joyid.dev";
const client = new ccc.ClientPublicTestnet();
const sha256 = (bytes: Uint8Array) => new Uint8Array(createHash("sha256").update(bytes).digest());
const b64u = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const hex = (bytes: number) => Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("hex");

// --- Identities: the KeyWay account (its Lit key) and a JoyID passkey -----------------------------------------
const litPublicKey = ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true));
const account = await recoveryAccountAddress(litPublicKey, client);
const passkeySecret = p256.utils.randomSecretKey();
const passkeyPublic = p256.getPublicKey(passkeySecret, false).slice(1);
const joyIdScript = await client.getKnownScript(ccc.KnownScript.JoyId);
const joyIdAddress = ccc.Address.fromScript({ codeHash: joyIdScript.codeHash, hashType: joyIdScript.hashType, args: ccc.hexFrom(ccc.bytesConcat([0, 1], ccc.hashCkbShort(passkeyPublic))) }, client).toString();

// --- Fake KeyWay API --------------------------------------------------------------------------------------------
type ApiCall = { path: string; operation?: string; verified?: string; refused?: string };
const apiCalls: ApiCall[] = [];
const issuedNonces = new Set<string>();
const cors = { "access-control-allow-origin": "*", "access-control-allow-headers": "content-type, authorization, idempotency-key, x-keyway-app-id", "access-control-allow-methods": "POST, OPTIONS" };
const ENABLE_TX = `0x${"ab".repeat(32)}`;
let recoveryOn: unknown;

async function fakeApi(route: Route) {
  const request = route.request();
  if (request.method() === "OPTIONS") return route.fulfill({ status: 204, headers: cors });
  const path = new URL(request.url()).pathname.replace("/api/v1/keyway", "");
  const body = (request.postDataJSON() ?? {}) as Record<string, unknown>;
  const call: ApiCall = { path, operation: body.operation as string | undefined };
  apiCalls.push(call);
  const json = (status: number, value: unknown) => route.fulfill({ status, headers: { ...cors, "content-type": "application/json" }, body: JSON.stringify(value) });
  const now = new Date();
  switch (path) {
    case "/auth/legacy-cleanup": return json(200, { epoch: "", prefixes: [] });
    case "/auth/session": return json(200, { user: { id: "user-1" }, expiresAt: new Date(Date.now() + 3600_000).toISOString() });
    case "/bootstrap": return json(200, { provisioned: false, restoreRequired: false, wallet: { version: 1, status: "ready", litPkpId: "pkp", litPublicKey, ckbAddress: account, primaryDeviceIdHash: "00", hasOpenedChannel: false, createdAt: now.toISOString(), updatedAt: now.toISOString() } });
    case "/recovery": {
      if (body.operation === "challenge") {
        const nonce = `${Date.now() + 15 * 60_000}.${hex(16)}.${hex(32)}`;
        issuedNonces.add(nonce);
        return json(200, { challengeNonce: nonce });
      }
      if (body.operation === "status") return json(200, { pending: false, ckbAddress: account, transactionHash: ENABLE_TX, recovery: recoveryOn });
      // preview, request-email-code and enable all re-check the proofs, as the server does.
      try {
        const backups = body.backups as Array<Record<string, unknown>>;
        parseBackups(backups);
        for (const proof of backups) {
          if (!issuedNonces.has(proof.challengeNonce as string)) throw new Error("unknown nonce");
          const backup = await verifyBackupOwnership(client, account, proof);
          call.verified = `${backup.kind}:${backup.address}`;
        }
        if (body.operation === "preview") {
          return json(200, {
            confirmationNonce: "confirm",
            preview: {
              network: "CKB testnet", newAddress: account, legacyAddress: account,
              backups: backups.map((proof) => ({ kind: proof.kind, address: proof.address, label: describeBackup(proof as never) })),
              adminListCkb: "165", minimumCellCkb: "61", tokenCellsExtraCkb: "0", lockedCkb: "165", feeCkb: "0.001", movedCkb: "100", tokens: [], cellsLeft: 0, transactionHash: ENABLE_TX,
            },
          });
        }
        if (body.operation === "request-email-code") return json(200, { sentTo: "you@example.com" });
        if (body.operation === "enable") {
          if (body.emailCode !== "123456") return json(400, { error: "That code isn't right" });
          const adminListTypeArgs = `0x${"cd".repeat(32)}`;
          const adminListTypeHash = adminListTypeScript({ adminListTypeArgs }).hash();
          recoveryOn = {
            omnilockArgs: omnilockArgsFor(litPublicKey, adminListTypeHash), omnilock: KEYWAY_OMNILOCK.testnet, adminListTypeArgs, adminListTypeHash,
            adminListOutPoint: { txHash: ENABLE_TX, index: 0 }, enableTransactionHash: ENABLE_TX, legacyAddress: account, enabledAt: now.toISOString(),
            backups: backups.map(({ kind, address }) => ({ kind, address })),
          };
          return json(200, { transactionHash: ENABLE_TX });
        }
      } catch (error) {
        call.refused = (error as Error).message;
        return json(400, { error: (error as Error).message });
      }
      return json(400, { error: "unexpected" });
    }
    default: return json(404, { error: `not faked: ${path}` });
  }
}

// --- Fake JoyID -------------------------------------------------------------------------------------------------
type JoyIdVisit = { path: string; type: string | null; referer?: string; redirectURL: string; state: unknown; challenge?: unknown; answered: string };
const joyIdVisits: JoyIdVisit[] = [];
let rejectNext = false;

function signMessage(challengeText: string) {
  const challenge = b64u(new TextEncoder().encode(challengeText));
  const authData = ccc.bytesConcat(sha256(new TextEncoder().encode("testnet.joyid.dev")), [0x05], [0, 0, 0, 1]);
  const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge, origin: JOYID, crossOrigin: false }));
  const der = p256.sign(ccc.bytesConcat(authData, sha256(clientDataJSON)), passkeySecret, { prehash: true, format: "der", lowS: false });
  return { signature: b64u(der), message: b64u(ccc.bytesConcat(authData, clientDataJSON)) };
}

async function fakeJoyId(route: Route) {
  const request = route.request();
  if (request.resourceType() !== "document") return route.fulfill({ status: 404, body: "" });
  const url = new URL(request.url());
  const sent = decodeSearch(url.searchParams.get("_data_") ?? "") as Record<string, unknown>;
  const auth = url.pathname === "/auth";
  let message: Record<string, unknown>;
  let answered: string;
  if (rejectNext) {
    rejectNext = false;
    message = { error: "User Rejected", type: auth ? "Auth" : "SignMessage", state: sent.state };
    answered = "rejected";
  } else if (auth) {
    // Auth without a challenge: the account. state comes back only at the top level.
    message = { type: "Auth", data: { address: joyIdAddress, ethAddress: "0x0000000000000000000000000000000000000000", keyType: "main_key", alg: -7, pubkey: Buffer.from(passkeyPublic).toString("hex") }, state: sent.state };
    answered = "auth";
  } else {
    if (sent.address !== joyIdAddress || sent.isData !== false || typeof sent.challenge !== "string") throw new Error("unexpected sign request");
    const signed = signMessage(sent.challenge);
    message = { type: "SignMessage", data: { ...signed, challenge: sent.challenge, alg: -7, pubkey: Buffer.from(passkeyPublic).toString("hex"), keyType: "main_key", state: sent.state }, state: sent.state };
    answered = "signed";
  }
  joyIdVisits.push({ path: url.pathname, type: url.searchParams.get("type"), referer: request.headers().referer, redirectURL: sent.redirectURL as string, state: sent.state, challenge: sent.challenge, answered });
  const back = new URL(sent.redirectURL as string);
  back.searchParams.set("_data_", encodeSearch(message));
  // JoyID's guard: the redirectURL's origin must be the referrer's.
  const page = `<!doctype html><meta charset=utf-8><title>JoyID (stand-in)</title><body>JoyID<script>
const redirectURL = ${JSON.stringify(sent.redirectURL)};
if (document.referrer && new URL(redirectURL).origin !== new URL(document.referrer).origin) document.body.textContent = "REJECTED: referrer";
else setTimeout(() => location.replace(${JSON.stringify(back.href)}), 150);
</script>`;
  return route.fulfill({ status: 200, headers: { "content-type": "text/html", "x-frame-options": "DENY", "strict-transport-security": "max-age=63072000" }, body: page });
}

// Anything else off-site (CKB RPC for the balance) answers empty, so the run doesn't depend on the network.
async function offline(route: Route) {
  return route.fulfill({ status: 200, headers: { ...cors, "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, result: null }) });
}

// --- The app ------------------------------------------------------------------------------------------------------
async function startServer() {
  const server = DEV
    ? spawn("npx", ["next", "dev", "-p", String(PORT)], { cwd: root, stdio: ["ignore", "pipe", "pipe"], detached: true, env: { ...process.env, KEYWAY_LOCAL_SDK: "1" } })
    : spawn("npx", ["next", "start", "-p", String(PORT)], { cwd: root, stdio: ["ignore", "pipe", "pipe"], detached: true, env: { ...process.env, NODE_ENV: "production" } });
  server.stdout.on("data", () => undefined);
  server.stderr.on("data", (chunk) => process.stderr.write(chunk));
  for (let i = 0; i < 400; i++) {
    try { if ((await fetch(`${APP}/app`)).ok) return server; } catch { /* starting */ }
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  throw new Error("next start didn't come up");
}

async function newContext(browser: Browser, options: { blockWindows?: boolean } = {}) {
  const context = await browser.newContext();
  await context.route(`${API}/**`, fakeApi);
  await context.route(`${JOYID}/**`, fakeJoyId);
  await context.route((url) => url.protocol === "https:" && !url.href.startsWith(API) && !url.href.startsWith(JOYID), offline);
  // A signed-in session, as the SDK stores it; and a log of where the page was when each fetch started.
  await context.addInitScript(({ app, blockWindows }) => {
    if (location.origin !== app) return;
    localStorage.setItem("ckb-keyway.session.v2:unregistered", JSON.stringify({ authToken: "token", user: { id: "user-1" }, expiresAt: new Date(Date.now() + 3600_000).toISOString() }));
    const log: Array<{ url: string; href: string }> = [];
    (window as unknown as { __fetches: typeof log }).__fetches = log;
    const original = window.fetch;
    window.fetch = function (input: RequestInfo | URL, init?: RequestInit) {
      log.push({ url: String(input instanceof Request ? input.url : input), href: location.href });
      return original.call(this, input, init);
    } as typeof fetch;
    if (blockWindows) window.open = () => null;
  }, { app: APP, blockWindows: Boolean(options.blockWindows) });
  return context;
}

const pageState = (page: Page) => page.evaluate(() => ({
  url: location.href,
  crossOriginIsolated,
  sharedArrayBuffer: typeof SharedArrayBuffer,
  marker: (window as unknown as { __marker?: number }).__marker ?? null,
  fetches: (window as unknown as { __fetches: Array<{ url: string; href: string }> }).__fetches,
}));

async function approveAndEnterCode(page: Page) {
  try {
    await page.getByRole("button", { name: "Turn on recovery" }).click({ timeout: 90_000 });
    await page.locator('input[autocomplete="one-time-code"]').fill("123456", { timeout: 90_000 });
    await page.getByText("These backups can move everything").waitFor({ timeout: 90_000 });
  } catch (error) {
    await page.screenshot({ path: new URL("./e2e-failure.png", import.meta.url).pathname });
    console.error(JSON.stringify({ apiCalls, joyIdVisits: joyIdVisits.map(({ path, answered }) => ({ path, answered })), url: page.url(), text: (await page.locator("body").innerText()).slice(0, 2000) }, null, 2));
    throw error;
  }
}

const results: Record<string, unknown> = {};
const failures: string[] = [];
const check = (name: string, ok: boolean, detail?: unknown) => {
  if (!ok) failures.push(name);
  (results.checks as Record<string, unknown>)[name] = ok ? "ok" : { failed: detail ?? true };
};
results.checks = {};

const server = await startServer();
const browser = await chromium.launch();
results.chromium = browser.version();
results.server = DEV ? "next dev (React StrictMode)" : "next start (production build)";
try {
  // 1. Window transport, first use (connect, then sign) on the cross-origin isolated demo.
  {
    apiCalls.length = 0; joyIdVisits.length = 0; recoveryOn = undefined;
    const context = await newContext(browser);
    const page = await context.newPage();
    page.on("pageerror", (error) => console.error("pageerror", error.message));
    const responseHeaders = (await page.goto(`${APP}/app`))!.headers();
    await page.getByRole("button", { name: "Turn on with JoyID" }).waitFor();
    await page.evaluate(() => { (window as unknown as { __marker: number }).__marker = 1; });
    const helperUrls: string[] = [];
    const opened = context.waitForEvent("page");
    await page.getByRole("button", { name: "Turn on with JoyID" }).click();
    const helper = await opened;
    helper.on("framenavigated", (frame) => { if (frame === helper.mainFrame()) helperUrls.push(frame.url()); });
    const stageSeen = await page.getByRole("button", { name: /Connecting JoyID…|Waiting for JoyID…/ }).textContent({ timeout: 10_000 }).catch(() => null);
    await approveAndEnterCode(page);
    await helper.waitForEvent("close", { timeout: 30_000 }).catch(() => undefined);
    const state = await pageState(page);
    const verified = apiCalls.filter((call) => call.verified);
    results["1. window transport"] = {
      appHeaders: { coop: responseHeaders["cross-origin-opener-policy"], coep: responseHeaders["cross-origin-embedder-policy"], csp: responseHeaders["content-security-policy"]?.slice(0, 60) + "…" },
      stageSeen,
      joyIdVisits: joyIdVisits.map(({ challenge, ...visit }) => ({ ...visit, challenge: typeof challenge === "string" ? `${challenge.split("\n")[0]}…` : challenge })),
      helperUrls: helperUrls.map((url) => url.replace(/_data_=[^&]+/, "_data_=…")),
      helperClosed: helper.isClosed(),
      main: { url: state.url, crossOriginIsolated: state.crossOriginIsolated, sharedArrayBuffer: state.sharedArrayBuffer, sameDocument: state.marker === 1 },
      apiCalls: apiCalls.filter((call) => call.path === "/recovery"),
    };
    check("window: connect then sign in one helper window", joyIdVisits.map((visit) => `${visit.path}:${visit.type}:${visit.answered}`).join(",") === "/auth:redirect:auth,/sign-message:redirect:signed");
    check("window: JoyID saw the app's origin as referrer", joyIdVisits.every((visit) => visit.referer === `${APP}/`), joyIdVisits.map((visit) => visit.referer));
    check("window: JoyID returns to the helper on the app's origin", joyIdVisits.every((visit) => visit.redirectURL.startsWith(`${APP}/app?keyway-joyid=`) && visit.redirectURL.includes("joyid-redirect=true")));
    check("window: the server verified the JoyID proof", verified.length > 0 && verified.every((call) => call.verified === `joyid:${joyIdAddress}`), apiCalls);
    check("window: recovery turned on after preview and emailed code", apiCalls.some((call) => call.operation === "enable" && !call.refused));
    check("window: main tab never reloaded and stayed cross-origin isolated", state.marker === 1 && state.crossOriginIsolated === true);
    check("window: helper closed itself", helper.isClosed());
    check("window: helper stripped _data_ from its address bar", helperUrls.some((url) => url.includes("_data_")) ? helperUrls.at(-1)?.includes("_data_") === false || helper.isClosed() : true, helperUrls);
    await context.close();
  }

  // 2. Window transport, JoyID already connected, user rejects in JoyID: cancelled, nothing sent.
  {
    apiCalls.length = 0; joyIdVisits.length = 0; rejectNext = true;
    const context = await newContext(browser);
    const page = await context.newPage();
    await page.goto(`${APP}/app`);
    await page.evaluate((address) => localStorage.setItem("ccc-joy-id-signer", JSON.stringify([[{ uri: "https://testnet.joyid.dev", addressType: "ckb" }, { address, publicKey: "0x00", keyType: "main_key" }]])), joyIdAddress);
    const opened = context.waitForEvent("page");
    await page.getByRole("button", { name: "Turn on with JoyID" }).click();
    const helper = await opened;
    await page.getByText("Cancelled. Nothing changed.").waitFor({ timeout: 60_000 });
    await helper.waitForEvent("close", { timeout: 30_000 }).catch(() => undefined);
    const helperLeft = helper.isClosed() ? undefined : { url: helper.url().replace(/_data_=[^&]+/, "_data_=…"), text: (await helper.locator("body").innerText().catch(() => "")).slice(0, 300) };
    results["2. known JoyID, rejected in JoyID"] = { helperLeft, joyIdVisits: joyIdVisits.map(({ path, answered }) => ({ path, answered })), helperClosed: helper.isClosed(), apiCalls: apiCalls.filter((call) => call.path === "/recovery") };
    check("known connection skips connect", joyIdVisits.length === 1 && joyIdVisits[0].path === "/sign-message");
    check("rejection in JoyID is a cancel, nothing previewed", !apiCalls.some((call) => call.operation === "preview"));
    check("helper closed after a rejection", helper.isClosed());
    await context.close();
  }

  // 3. Window blocked: falls back to a full-page redirect, resumes, and continues into the normal flow.
  //    Run in browser-node mode while holding a Web Lock like the browser node's device lock.
  {
    apiCalls.length = 0; joyIdVisits.length = 0; recoveryOn = undefined;
    const context = await newContext(browser, { blockWindows: true });
    const page = await context.newPage();
    const refererLeaks: Array<{ url: string; referer: string; type: string }> = [];
    page.on("request", (request) => {
      const referer = request.headers().referer ?? "";
      if (referer.includes("_data_")) refererLeaks.push({ url: request.url().slice(0, 80), referer: "…_data_=…", type: request.resourceType() });
    });
    await page.goto(`${APP}/app?mode=browser`);
    await page.getByRole("button", { name: "Turn on with JoyID" }).waitFor();
    const before = await page.evaluate(() => ({ crossOriginIsolated, lock: navigator.locks.request("ckb-keyway:fiber:e2e", { ifAvailable: true }, (lock) => lock ? new Promise(() => undefined) : undefined) && true }));
    const navigations: string[] = [];
    page.on("framenavigated", (frame) => { if (frame === page.mainFrame()) navigations.push(frame.url().replace(/_data_=[^&]+/, "_data_=…")); });
    await page.getByRole("button", { name: "Turn on with JoyID" }).click();
    await approveAndEnterCode(page);
    const state = await pageState(page);
    const lockAgain = await page.evaluate(() => navigator.locks.request("ckb-keyway:fiber:e2e", { ifAvailable: true }, (lock) => Boolean(lock)));
    const dataInFetch = state.fetches.filter((fetch) => fetch.href.includes("_data_") || fetch.href.includes("joyid-redirect"));
    results["3. blocked window -> full-page redirect"] = {
      before,
      navigations,
      joyIdVisits: joyIdVisits.map(({ path, type, answered, redirectURL, referer }) => ({ path, type, answered, redirectURL, referer })),
      after: { url: state.url, crossOriginIsolated: state.crossOriginIsolated, sharedArrayBuffer: state.sharedArrayBuffer, fiberLockReacquired: lockAgain },
      firstFetchesAfterReturn: state.fetches.slice(0, 4),
      fetchesWithTheAnswerInTheUrl: dataInFetch,
      requestsWithTheAnswerInReferer: refererLeaks,
      apiCalls: apiCalls.filter((call) => call.path === "/recovery"),
    };
    check("redirect: connect and sign as two full-page round trips", joyIdVisits.map((visit) => `${visit.path}:${visit.type}:${visit.answered}`).join(",") === "/auth:redirect:auth,/sign-message:redirect:signed");
    check("redirect: returns to the same page (browser mode kept)", joyIdVisits.every((visit) => visit.redirectURL === `${APP}/app?mode=browser&joyid-redirect=true`), joyIdVisits.map((visit) => visit.redirectURL));
    check("redirect: no fetch ran while the answer was in the URL", dataInFetch.length === 0, dataInFetch);
    check("redirect: address bar clean after return", !state.url.includes("_data_") && !state.url.includes("joyid-redirect"), state.url);
    check("redirect: no cross-origin request carried the answer in Referer", refererLeaks.every((leak) => leak.url.startsWith(APP)), refererLeaks);
    check("redirect: page cross-origin isolated again after return", state.crossOriginIsolated === true && state.sharedArrayBuffer === "function");
    check("redirect: the Fiber Web Lock is free again after return", lockAgain === true);
    check("redirect: the server verified the JoyID proof and recovery turned on", apiCalls.some((call) => call.verified === `joyid:${joyIdAddress}`) && apiCalls.some((call) => call.operation === "enable" && !call.refused));
    await context.close();
  }

  // 4. A crafted return URL with no matching request in this tab: stripped and refused, nothing sent.
  {
    apiCalls.length = 0;
    const context = await newContext(browser);
    const page = await context.newPage();
    const forged = encodeSearch({ type: "SignMessage", data: { ...signMessage("anything"), challenge: "anything", alg: -7, pubkey: Buffer.from(passkeyPublic).toString("hex"), keyType: "main_key" }, state: { v: 1, id: hex(16) } });
    await page.goto(`${APP}/app?joyid-redirect=true&_data_=${encodeURIComponent(forged)}`);
    await page.getByText("JoyID's answer doesn't match this request").waitFor({ timeout: 60_000 });
    const state = await pageState(page);
    results["4. crafted _data_ URL"] = { url: state.url, fetchesWithTheAnswerInTheUrl: state.fetches.filter((fetch) => fetch.href.includes("_data_")), apiCalls: apiCalls.filter((call) => call.path === "/recovery") };
    check("crafted: refused with a plain message", true);
    check("crafted: URL stripped before any fetch", !state.url.includes("_data_") && state.fetches.every((fetch) => !fetch.href.includes("_data_")));
    check("crafted: nothing reached the recovery API", !apiCalls.some((call) => call.path === "/recovery"));
    await context.close();
  }
} finally {
  await browser.close();
  try { process.kill(-server.pid!, "SIGTERM"); } catch { server.kill(); }
}

results.failures = failures;
const output = JSON.stringify(results, null, 2);
writeFileSync(new URL(DEV ? "./e2e-dev.output.txt" : "./e2e.output.txt", import.meta.url), `${output}\n`);
console.log(output);
if (failures.length) process.exit(1);

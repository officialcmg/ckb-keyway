// Shared helpers for live end-to-end checks: disposable mail.tm inboxes and a headless Chrome.
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { resolve } from "node:path";
const require = createRequire(import.meta.url);
export const { chromium } = require(process.env.PLAYWRIGHT_MODULE ?? "playwright");
/**
 * Where a run keeps its account, browser profile and logs. KEYWAY_EVIDENCE names another folder so that two runs can
 * go on at the same time; keep it under research/e2e with a name that starts with ".evidence" (those are gitignored).
 */
export const EVIDENCE = process.env.KEYWAY_EVIDENCE ? resolve(process.env.KEYWAY_EVIDENCE) : new URL("./.evidence", import.meta.url).pathname;
/** The live demo's app ID. It is public: the demo sends it with every request. */
export const DEMO_APP_ID = process.env.KEYWAY_APP_ID ?? "keyway_H3jyHCLd0tDqJ0qpEot8j3zB";

export async function json(url, body, token) {
  for (let attempt = 0; ; attempt++) {
    try { return await jsonOnce(url, body, token); } catch (error) {
      if (!/^429 /.test(error.message) || attempt >= 6) throw error;
      await new Promise((resolve) => setTimeout(resolve, 10_000 * (attempt + 1)));
    }
  }
}

async function jsonOnce(url, body, token) {
  const response = await fetch(url, { method: body ? "POST" : "GET", headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`${response.status} ${new URL(url).pathname}`);
  return response.status === 204 ? undefined : response.json();
}

export async function newMailbox(label) {
  const domain = (await json("https://api.mail.tm/domains"))["hydra:member"][0].domain;
  const email = `kw-${label}-${randomBytes(4).toString("hex")}@${domain}`;
  const password = randomBytes(24).toString("base64url");
  await json("https://api.mail.tm/accounts", { address: email, password });
  const token = (await json("https://api.mail.tm/token", { address: email, password })).token;
  return { email, password, token, seen: new Set() };
}

/** Signs in to a mailbox newMailbox made earlier (a resumed run), with every message already in it marked seen. */
export async function openMailbox(email, password) {
  const token = (await json("https://api.mail.tm/token", { address: email, password })).token;
  const mailbox = { email, password, token, seen: new Set() };
  await markSeen(mailbox);
  return mailbox;
}

export async function markSeen(mailbox) {
  for (const message of (await json("https://api.mail.tm/messages", undefined, mailbox.token))["hydra:member"]) mailbox.seen.add(message.id);
}

/**
 * Waits for the next unseen email that carries a code of `digits` digits and returns the code and the subject. The
 * code is picked out by its label: a funding email states amounts with eight decimal places before the code.
 */
export async function nextCode(mailbox, digits = 6) {
  const labelled = new RegExp(`(?:Your confirmation code is|Your code is)\\s+(\\d{${digits}})\\b`, "i");
  for (let attempt = 0; attempt < 60; attempt++) {
    for (const message of (await json("https://api.mail.tm/messages", undefined, mailbox.token))["hydra:member"]) {
      if (mailbox.seen.has(message.id)) continue;
      const full = await json(`https://api.mail.tm/messages/${message.id}`, undefined, mailbox.token);
      const code = `${full.text ?? ""}`.match(labelled)?.[1];
      if (code) { mailbox.seen.add(message.id); return { code, subject: full.subject }; }
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  throw new Error(`the ${digits}-digit email code did not arrive within two minutes`);
}

/** How the headless browser reaches the network: through HTTPS_PROXY when the machine has one. */
const proxy = process.env.HTTPS_PROXY ? { proxy: { server: process.env.HTTPS_PROXY } } : {};
const executable = process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {};

/** A browser whose profile (local storage, IndexedDB) lives in `dir`, so a restarted run keeps the page's state. */
export async function launchPersistent(dir) {
  return chromium.launchPersistentContext(dir, { headless: true, ...executable, ...proxy });
}

export async function launch() {
  return chromium.launch({ headless: true, ...executable, ...proxy });
}

export function watchErrors(page, label) {
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(`${label}: ${m.text().slice(0, 200)}`); });
  page.on("pageerror", (e) => errors.push(`${label}: ${String(e).slice(0, 200)}`));
  return errors;
}

/** Serves the local build under a real origin inside the headless browser, so the API's CORS rules apply as in production. */
export async function mapOrigin(context, origin, local) {
  await context.route(`${origin}/**`, async (route) => {
    const url = route.request().url().replace(origin, local);
    const response = await route.fetch({ url });
    await route.fulfill({ response });
  });
}

// Shared helpers for live end-to-end checks: disposable mail.tm inboxes and a headless Chrome.
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
export const { chromium } = require("playwright");
export const EVIDENCE = new URL("./.evidence", import.meta.url).pathname;
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
  const email = `keyway-${label}-${randomBytes(6).toString("hex")}@${domain}`;
  const password = randomBytes(24).toString("base64url");
  await json("https://api.mail.tm/accounts", { address: email, password });
  const token = (await json("https://api.mail.tm/token", { address: email, password })).token;
  return { email, password, token, seen: new Set() };
}

export async function markSeen(mailbox) {
  for (const message of (await json("https://api.mail.tm/messages", undefined, mailbox.token))["hydra:member"]) mailbox.seen.add(message.id);
}

/** Waits for the next unseen email and returns its six-digit code and subject. */
export async function nextCode(mailbox) {
  for (let attempt = 0; attempt < 45; attempt++) {
    for (const message of (await json("https://api.mail.tm/messages", undefined, mailbox.token))["hydra:member"]) {
      if (mailbox.seen.has(message.id)) continue;
      mailbox.seen.add(message.id);
      const full = await json(`https://api.mail.tm/messages/${message.id}`, undefined, mailbox.token);
      const code = `${full.text ?? ""}`.match(/\b\d{6}\b/)?.[0];
      if (code) return { code, subject: full.subject };
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  throw new Error("OTP email did not arrive within 90 s");
}

export async function launch() {
  return chromium.launch({ headless: true, ...(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {}) });
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

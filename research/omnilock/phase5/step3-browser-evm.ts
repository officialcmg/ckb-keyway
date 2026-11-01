// Phase 5, step 3: the rescue page in a real browser (headless Chromium through Playwright) against a local
// `next start` of this repo (`npx next build && npx next start -p 3100`). The page gets an injected EIP-1193
// provider whose personal_sign is answered here by the throwaway EVM backup E1; the key never enters the page.
// Error cases first (no rescue), then the phone layout up to the review, then the rescue itself on desktop.
// Screenshots go to ./screenshots. `npx tsx step3-browser-evm.ts`
import { mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { evmAddressOf, evmPersonalSign, HERE, loadKeys, loadState, saveState, secpAddress, waitCommitted } from "./lib.ts";
import * as ccc from "@ckb-ccc/core";

// Playwright isn't a dependency of this repo; this loads an installed copy (NODE_PATH or `npm i -g playwright`).
// Typed loosely so the repo's typecheck doesn't need Playwright's types.
type Browser = any;
type Page = any;
const { chromium } = createRequire(import.meta.url)("playwright") as { chromium: { launch(): Promise<Browser> } };
const URL = process.env.RESCUE_URL ?? "http://localhost:3100/rescue";
const SHOTS = join(HERE, "screenshots");
mkdirSync(SHOTS, { recursive: true });
const keys = loadKeys();
const state = loadState();
const destination = await secpAddress(keys.D1);
const prompts: string[] = [];

async function open(browser: Browser, walletKey: string | undefined, viewport = { width: 1280, height: 900 }): Promise<Page> {
  const context = await browser.newContext({ viewport, deviceScaleFactor: viewport.width < 600 ? 2 : 1, isMobile: viewport.width < 600, hasTouch: viewport.width < 600 });
  const page = await context.newPage();
  page.on("pageerror", (error: Error) => console.log("page error:", error.message));
  if (walletKey) {
    await page.exposeFunction("__walletAccounts", () => [evmAddressOf(walletKey)]);
    await page.exposeFunction("__walletSign", (hex: string) => {
      const text = new TextDecoder().decode(ccc.bytesFrom(hex));
      prompts.push(text);
      return evmPersonalSign(walletKey, text);
    });
    // A string, so the bundler's helpers don't leak into the page.
    await page.addInitScript(`window.ethereum = {
      request: async ({ method, params }) => {
        if (method === "eth_requestAccounts" || method === "eth_accounts") return window.__walletAccounts();
        if (method === "personal_sign") return window.__walletSign(params[0]);
        throw Object.assign(new Error("Unsupported method " + method), { code: 4200 });
      },
    };`);
  }
  await page.goto(URL, { waitUntil: "networkidle" });
  return page;
}

const shot = (page: Page, name: string) => page.screenshot({ path: join(SHOTS, `${name}.png`), fullPage: true });
const lookUp = async (page: Page, address: string) => {
  await page.getByRole("textbox", { name: "KeyWay address", exact: true }).fill(address);
  await page.getByRole("button", { name: "Look up" }).click();
  await page.waitForSelector(".rescue-account, .field-error", { timeout: 60_000 });
};
const alert = async (page: Page) => (await page.getByRole("alert").first().textContent())?.trim();

const browser = await chromium.launch();
try {
  // Errors, each shown plainly on the page.
  let page = await open(browser, undefined);
  await shot(page, "01-start");
  await lookUp(page, await secpAddress(keys.K));
  console.log("old secp256k1 address:", await alert(page));
  await shot(page, "02-error-recovery-off");
  await lookUp(page, `ckb1${state.newAddress.slice(4)}`);
  console.log("mainnet-style address on testnet:", await alert(page));
  await lookUp(page, `${state.newAddress.slice(0, -6)}qqqqqq`);
  console.log("malformed address:", await alert(page));
  await lookUp(page, state.newAddress);
  await page.getByRole("button", { name: "EVM wallet" }).click();
  await page.waitForSelector(".field-error");
  console.log("no EVM wallet in the browser:", await alert(page));
  await page.close();

  page = await open(browser, keys.X);
  await lookUp(page, state.newAddress);
  await page.getByRole("button", { name: "EVM wallet" }).click();
  await page.waitForSelector(".field-error");
  console.log("EVM wallet that isn't a backup:", await alert(page));
  await shot(page, "03-error-not-a-backup");
  await page.close();

  // Phone: through to the review, then stop.
  page = await open(browser, keys.E1, { width: 390, height: 844 });
  await lookUp(page, state.newAddress);
  await shot(page, "04-phone-account");
  await page.getByRole("button", { name: "EVM wallet" }).click();
  await page.getByText("is on the list").waitFor();
  await page.getByRole("textbox", { name: "Destination address", exact: true }).fill(state.newAddress);
  await page.getByRole("button", { name: "Review" }).click();
  await page.waitForSelector(".field-error");
  console.log("destination is the KeyWay address itself:", await alert(page));
  await page.getByRole("textbox", { name: "Destination address", exact: true }).fill(destination);
  await page.getByRole("button", { name: "Review" }).click();
  await page.getByRole("button", { name: "Sign and send" }).waitFor({ timeout: 60_000 });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  console.log("phone horizontal overflow (px):", overflow);
  if (overflow > 0) throw new Error("the page scrolls sideways on a phone");
  await shot(page, "05-phone-review");
  await page.close();

  // Desktop: the rescue.
  page = await open(browser, keys.E1);
  await lookUp(page, state.newAddress);
  await shot(page, "06-account");
  await page.getByRole("button", { name: "EVM wallet" }).click();
  await page.getByText("is on the list").waitFor();
  await page.getByRole("textbox", { name: "Destination address", exact: true }).fill(destination);
  await page.getByRole("button", { name: "Review" }).click();
  await page.getByRole("button", { name: "Sign and send" }).waitFor({ timeout: 60_000 });
  await shot(page, "07-review");
  console.log("review:", (await page.locator(".rescue-review .detail-list").innerText()).replace(/\n/g, " | "));
  await page.getByRole("button", { name: "Sign and send" }).click();
  await page.getByText("Sent.").waitFor({ timeout: 60_000 });
  const hash = (await page.locator(".copy-well__value").textContent())!.trim();
  console.log("wallet prompts:", prompts.length, JSON.stringify(prompts));
  console.log("rescue tx", hash);
  await shot(page, "08-sent");
  await waitCommitted(hash);
  saveState({ rescueEvm: hash, rescueEvmPrompt: prompts.at(-1) });
  console.log("committed");
} finally {
  await browser.close();
}
process.exit(0);

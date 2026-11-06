/**
 * Screenshots of the demo's account recovery card with both backup options, from the development state previews
 * (`/app?screen=…`), served by `next dev` against the local SDK. Light and dark color schemes, desktop and 360px.
 *
 * Run: npm run build:sdk && NODE_PATH=$(npm root -g) node --import tsx research/joyid-transport/screenshots.ts
 */
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { createRequire } from "node:module";

const { chromium } = createRequire(import.meta.url)("playwright") as typeof import("playwright");
const root = new URL("../../", import.meta.url).pathname;
const out = new URL("./screenshots/", import.meta.url).pathname;
const PORT = 3200;
const APP = `http://localhost:${PORT}`;
mkdirSync(out, { recursive: true });

const server = spawn("npx", ["next", "dev", "-p", String(PORT)], { cwd: root, stdio: "ignore", detached: true, env: { ...process.env, KEYWAY_LOCAL_SDK: "1" } });
for (let i = 0; ; i++) {
  try { if ((await fetch(`${APP}/app?screen=recoveryOff`)).ok) break; } catch { /* starting */ }
  if (i > 200) throw new Error("next dev didn't come up");
  await new Promise((resolve) => setTimeout(resolve, 500));
}

const browser = await chromium.launch();
const shots: string[] = [];
try {
  for (const scheme of ["light", "dark"] as const) {
    for (const [label, viewport] of [["desktop", { width: 1280, height: 900 }], ["360", { width: 360, height: 800 }]] as const) {
      const context = await browser.newContext({ viewport, deviceScaleFactor: 2, colorScheme: scheme });
      const page = await context.newPage();
      const card = () => page.locator("section.card", { has: page.getByText("Account recovery") });
      const shoot = async (name: string) => {
        const file = `${out}${name}-${label}-${scheme}.png`;
        await card().screenshot({ path: file });
        shots.push(file.replace(root, ""));
      };
      await page.goto(`${APP}/app?screen=recoveryOff`, { timeout: 120_000 });
      await page.getByRole("button", { name: "Turn on with JoyID" }).waitFor({ timeout: 120_000 });
      await shoot("recovery-off");
      await page.getByRole("button", { name: "Turn on with JoyID" }).click();
      await page.getByText("Finish in the JoyID window.").waitFor();
      await shoot("recovery-off-waiting-for-joyid");
      await page.getByRole("button", { name: "Cancel" }).click();
      await page.getByText("Cancelled. Nothing changed.").waitFor();
      await shoot("recovery-off-cancelled");
      await page.goto(`${APP}/app?screen=recoveryJoyIdReturn`);
      await page.getByText("Approve the JoyID backup").waitFor({ timeout: 60_000 });
      await shoot("recovery-off-back-from-joyid");
      await page.goto(`${APP}/app?screen=recoveryOn`);
      await page.getByRole("button", { name: "Add JoyID" }).waitFor({ timeout: 60_000 });
      await shoot("recovery-on");
      await context.close();
    }
  }
} finally {
  await browser.close();
  try { process.kill(-server.pid!, "SIGTERM"); } catch { server.kill(); }
}
console.log(shots.join("\n"));

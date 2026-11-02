// Screenshots every scene of the development dialog gallery (`/dev-modals`) in light and dark, at desktop width
// and at 360px. Run `npx next dev -p 3100`, then `node research/ui-audit/capture.mjs <out-dir> [scene ...]`.
import { mkdir } from "node:fs/promises";
import { createRequire } from "node:module";

// Playwright comes with the environment, not this package, so it is resolved the way require finds it.
const { chromium } = createRequire(import.meta.url)("playwright");

const BASE = process.env.GALLERY_URL ?? "http://localhost:3100/dev-modals";
const [out = "research/ui-audit/after", ...only] = process.argv.slice(2);

const typeEmail = async (page) => {
  await page.getByLabel("Email address").fill("ana@acmepay.example");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByText("Check").first().waitFor();
};
const typeCode = (code) => async (page) => { await page.keyboard.type(code, { delay: 30 }); };

// What to do in each scene before the screenshot; scenes without steps are shot as they open.
const STEPS = {
  "code-typed": [typeCode("482913")],
  "code-resend-error": [async (page) => page.getByRole("button", { name: /send a new code/i }).click(), 900],
  "code-resent": [async (page) => page.getByRole("button", { name: /send a new code/i }).click(), 900],
  "code-checking": [typeCode("482913"), 200],
  "code-wrong": [typeCode("000000"), 900],
  "code-expired": [typeCode("482913"), 900],
  "code-success": [typeCode("482913"), 300],
  "busy-transaction": [async (page) => page.getByRole("button", { name: "Approve" }).click(), 200],
  "failed-transaction": [async (page) => page.getByRole("button", { name: "Approve" }).click(), 900],
  "login-code": [typeEmail],
  "login-wrong": [typeEmail, typeCode("000000"), 900],
  "login-slow": [typeEmail, typeCode("482913"), 200],
  "login-success": [typeEmail, typeCode("482913"), 700],
};

const browser = await chromium.launch();
const scenes = only.length ? only : await (async () => {
  const page = await browser.newPage();
  await page.goto(BASE);
  await page.locator("[data-scene]").first().waitFor();
  const names = await page.locator("[data-scene]").evaluateAll((links) => links.map((link) => link.dataset.scene));
  await page.close();
  return names;
})();
await mkdir(out, { recursive: true });
for (const scene of scenes) {
  for (const theme of ["light", "dark"]) {
    for (const [label, viewport] of [["desktop", { width: 1280, height: 860 }], ["360", { width: 360, height: 800 }]]) {
      const page = await browser.newPage({ viewport, colorScheme: theme });
      await page.goto(`${BASE}?scene=${scene}&theme=${theme}`);
      await page.locator("[role=dialog]").first().waitFor();
      await page.waitForTimeout(150);
      for (const step of STEPS[scene] ?? []) {
        if (typeof step === "number") await page.waitForTimeout(step);
        else await step(page);
      }
      await page.screenshot({ path: `${out}/${scene}-${theme}-${label}.jpg`, type: "jpeg", quality: 80 });
      await page.close();
    }
  }
  console.log(scene);
}
await browser.close();

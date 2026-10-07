import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { build } from "esbuild";
import { resolve } from "node:path";
import sharp from "sharp";

async function compareModal(actual, expected, label) {
  const [a, b] = await Promise.all([sharp(actual).raw().toBuffer({ resolveWithObject: true }), sharp(expected).raw().toBuffer({ resolveWithObject: true })]);
  assert.deepEqual(a.info, b.info, `${label} dimensions changed`);
  let changed = 0;
  for (let offset = 0; offset < a.data.length; offset += a.info.channels) {
    if (Array.from({ length: a.info.channels }, (_, channel) => Math.abs(a.data[offset + channel] - b.data[offset + channel])).some((delta) => delta > 2)) changed++;
  }
  const ratio = changed / (a.info.width * a.info.height);
  assert.ok(ratio < 0.001, `${label} changed ${(ratio * 100).toFixed(3)}% of pixels`);
}

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ?? "playwright");
const baseline = execFileSync("git", ["show", "HEAD:src/sdk/react/keyway-provider.tsx"], { encoding: "utf8" });
const source = `import {createRoot} from 'react-dom/client';import {KeyWayProvider,useKeyWay} from './src/sdk/react/keyway-provider';function Button(){const auth=useKeyWay();return <button onClick={auth.login}>Login</button>;}createRoot(document.getElementById('root')).render(<KeyWayProvider theme={new URLSearchParams(location.search).get('theme')}><Button /></KeyWayProvider>);`;
const bundles = {};
for (const version of ["baseline", "current"]) {
  const result = await build({ stdin: { contents: source, loader: "tsx", resolveDir: process.cwd() }, bundle: true, write: false, platform: "browser", format: "iife", jsx: "automatic", define: { "process.env.NODE_ENV": '"development"', "process.env.KEYWAY_API_TARGET": '"production"' },
    plugins: version === "baseline" ? [{ name: "baseline", setup(build) { build.onLoad({ filter: /keyway-provider\.tsx$/ }, () => ({ contents: baseline, loader: "tsx", resolveDir: resolve("src/sdk/react") })); } }] : [],
  });
  bundles[version] = result.outputFiles[0].contents;
}
const server = createServer((request, response) => {
  response.setHeader("Content-Type", request.url.endsWith(".js") ? "text/javascript" : "text/html");
  response.end(request.url.endsWith(".js") ? bundles[request.url.slice(1, -3)] : `<div id="root"></div><script src="/${new URL(request.url, "http://localhost").searchParams.get("version")}.js"></script>`);
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const browser = await chromium.launch({ headless: true, channel: "chrome" });
try {
  for (const theme of ["light", "dark"]) for (const width of [360, 1280]) {
    const screenshots = [];
    for (const version of ["baseline", "current"]) {
      const context = await browser.newContext({ viewport: { width, height: 900 } });
      const page = await context.newPage();
      await page.route("**/api/v1/keyway/**", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ methodId: "test", challengeId: "test", epoch: "", prefixes: [] }) }));
      await page.goto(`http://127.0.0.1:${server.address().port}/?version=${version}&theme=${theme}`);
      await page.getByRole("button", { name: "Login", exact: true }).click();
      await page.addStyleTag({ content: "*{animation:none!important;transition:none!important;caret-color:transparent!important}" });
      await page.waitForTimeout(100);
      const email = await page.getByRole("dialog").screenshot();
      await page.getByPlaceholder("you@example.com").fill("disposable@example.com");
      await page.getByRole("button", { name: "Continue", exact: true }).click();
      await page.getByRole("heading", { name: "Enter confirmation code" }).waitFor();
      screenshots.push([email, await page.getByRole("dialog").screenshot()]);
      await context.close();
    }
    await compareModal(screenshots[1][0], screenshots[0][0], `${theme}/${width} email modal`);
    await compareModal(screenshots[1][1], screenshots[0][1], `${theme}/${width} OTP modal`);
    console.log(`PASS unchanged ${theme} modal at ${width}px`);
  }
} finally { await browser.close(); await new Promise((resolve) => server.close(resolve)); }

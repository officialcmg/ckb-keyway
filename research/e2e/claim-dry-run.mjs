// Hands claim-dry-run.ts to a running browser-settlement.mjs (browser mode, after the commitment is on-chain) through
// its eval.js; the result appears in the run's log as "eval: {...}".
//   node research/e2e/claim-dry-run.mjs <evidence folder>
import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = new URL("../..", import.meta.url).pathname.replace(/\/$/, "");
const folder = resolve(process.argv[2] ?? new URL("./.evidence", import.meta.url).pathname);
const state = JSON.parse(readFileSync(`${folder}/settlement-state.json`, "utf8"));
if (!state.commitment) throw new Error("the run has no commitment on-chain yet");
const { build } = createRequire(`${repo}/`)("esbuild");
const result = await build({ entryPoints: [`${repo}/research/e2e/claim-dry-run.ts`], absWorkingDir: repo, bundle: true, write: false, platform: "browser", format: "iife" });
const script = `${Buffer.from(result.outputFiles[0].contents).toString("utf8")}\nwindow.claimDryRun(${JSON.stringify(state.channelId)}, ${JSON.stringify(state.commitment)}, ${JSON.stringify(state.address)})`;
writeFileSync(`${folder}/eval.js`, script, { mode: 0o600 });
console.log(`written ${folder}/eval.js (${script.length} bytes); the run evaluates it on its next pass`);

// Local page for testing a real JoyID and a real EVM wallet as recovery backups (CKB testnet only):
//   DATABASE_URL=postgres://... npx tsx research/omnilock/backup-test/server.ts   ->  http://localhost:4400
// Step 1 connects the backups, step 2 turns recovery on for a funded throwaway account with them as its backups
// (through src/server/recovery.ts, the real ownership check included), steps 3 and 4 use the real rescue page.
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as ccc from "@ckb-ccc/core";
import { build } from "esbuild";
import { recoverySetup } from "../../../src/server/recovery.ts";
import { recoveryBackupChallenge, type RecoveryBackup } from "../../../src/sdk/browser/recovery-backups.ts";
import { accountContext, accountKey, claimFaucet, client, emailCode, funderKey, loadState, refill, saveState, secpAddress } from "./lib.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
await build({ entryPoints: [join(HERE, "client.ts")], bundle: true, format: "esm", platform: "browser", outfile: join(HERE, "client.js"), logLevel: "warning" });

const legacyAddress = await secpAddress(accountKey());
const funderAddress = await secpAddress(funderKey());
const balance = async (address: string) => ccc.fixedPointToString(await client.getBalance([(await ccc.Address.fromString(address, client)).script]));

async function setup(body: { backups: unknown[] }) {
  const emails: Array<{ subject: string; plaintext: string }> = [];
  const context = await accountContext(emails);
  const backups = body.backups;
  const preview = await recoverySetup(context, { operation: "preview", backups }) as { confirmationNonce: string };
  await recoverySetup(context, { operation: "request-email-code", backups, confirmationNonce: preview.confirmationNonce });
  const result = await recoverySetup(context, { operation: "enable", backups, confirmationNonce: preview.confirmationNonce, emailCode: emailCode(emails) }) as { transactionHash: string; ckbAddress: string };
  // The change takes effect only once the chain commits it; the status operation settles it.
  for (let i = 0; i < 60; i++) {
    const status = await recoverySetup(await accountContext(emails), { operation: "status" }) as { pending: boolean; ckbAddress: string };
    if (!status.pending) {
      if (status.ckbAddress !== result.ckbAddress) throw new Error("The enable transaction was dropped. Try again");
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
  saveState({ enable: result.transactionHash, newAddress: result.ckbAddress, backups: (backups as RecoveryBackup[]).map(({ kind, address }) => ({ kind, address })) });
  return { transactionHash: result.transactionHash, address: result.ckbAddress };
}

const send = (response: import("node:http").ServerResponse, status: number, body: unknown, type = "application/json") => {
  response.writeHead(status, { "content-type": type, "cache-control": "no-store" });
  response.end(type === "application/json" ? JSON.stringify(body) : body as string);
};

const readBody = async (request: import("node:http").IncomingMessage) => {
  let raw = "";
  for await (const chunk of request) raw += chunk;
  return JSON.parse(raw);
};

createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? "/", "http://localhost");
    if (url.pathname === "/") return send(response, 200, readFileSync(join(HERE, "index.html"), "utf8"), "text/html");
    if (url.pathname === "/client.js") return send(response, 200, readFileSync(join(HERE, "client.js"), "utf8"), "text/javascript");
    if (url.pathname === "/api/status") {
      const state = loadState();
      return send(response, 200, {
        funded: await balance(legacyAddress),
        account: state.newAddress ? { address: state.newAddress, transactionHash: state.enable, balance: await balance(state.newAddress), backups: state.backups } : null,
      });
    }
    if (url.pathname === "/api/challenge") {
      // One nonce per backup: KeyWay issues it, the backup signs the text naming it.
      const backup = { kind: url.searchParams.get("kind"), address: url.searchParams.get("address") ?? "" } as RecoveryBackup;
      const { challengeNonce } = await recoverySetup(await accountContext([]), { operation: "challenge" }) as { challengeNonce: string };
      return send(response, 200, { text: recoveryBackupChallenge(legacyAddress, backup, challengeNonce), challengeNonce });
    }
    if (url.pathname === "/api/setup" && request.method === "POST") return send(response, 200, await setup(await readBody(request)));
    if (url.pathname === "/api/refill" && request.method === "POST") {
      const state = loadState();
      if (!state.newAddress) throw new Error("Make the test account first");
      return send(response, 200, { transactionHash: await refill(state.newAddress, "1000") });
    }
    send(response, 404, { error: "Not found" });
  } catch (error) {
    console.error(error);
    send(response, 500, { error: error instanceof Error ? error.message : String(error) });
  }
}).listen(4400, async () => {
  console.log("Backup test page: http://localhost:4400");
  // Testnet faucet for the throwaway keys when they're empty (the account for setup, the funder for refills).
  for (const address of [legacyAddress, funderAddress]) {
    if (!loadState().newAddress && Number(await balance(address)) < 1000) console.log("faucet", address === legacyAddress ? "account" : "funder", await claimFaucet(address));
  }
});

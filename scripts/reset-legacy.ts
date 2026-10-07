import { readFile } from "node:fs/promises";
import postgres from "postgres";

type Account = { userId: string; managedRetired: boolean; browserInspected: boolean; channels: Array<{ fundingHash: string; fundingIndex: string; closingTransaction: string; cooperative: boolean }> };
type ResetReport = { projectId: string; accounts: Account[]; preservedAppIds: string[]; ownerConfirmedNoOpenBrowserChannelsAt?: string };
const reportPath = process.argv[process.argv.indexOf("--report") + 1];
if (!process.argv.includes("--report") || !reportPath) throw new Error("Provide a complete private --report file; no deletion without channel inspection");
const report: ResetReport = JSON.parse(await readFile(reportPath, "utf8"));
const projectId = process.env.STYTCH_PROJECT_ID;
const secret = process.env.STYTCH_SECRET;
if (process.env.STYTCH_ENVIRONMENT !== "test" || report.projectId !== projectId || !secret) throw new Error("Reset report must match the configured Stytch test project");
const authorization = `Basic ${Buffer.from(`${projectId}:${secret}`).toString("base64")}`;
async function stytch(path: string, method: string, body?: unknown) {
  const response = await fetch(`https://test.stytch.com${path}`, { method, headers: { Authorization: authorization, "Content-Type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(15_000) });
  if (!response.ok) throw new Error(`Legacy provider operation failed (${response.status})`);
  return response.json();
}
async function rpc(method: string, params: unknown[]) {
  const response = await fetch(process.env.CKB_NODE_RPC_URL ?? "https://testnet.ckbapp.dev/", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(15_000) });
  const body = await response.json();
  if (!response.ok || body.error) throw new Error("Could not verify on-chain settlement; reset aborted");
  return body.result;
}
const ids: string[] = [];
let cursor: string | undefined;
do {
  const result = await stytch("/v1/users/search", "POST", { limit: 1000, ...(cursor ? { cursor } : {}) });
  ids.push(...result.results.map((user: { user_id: string }) => user.user_id));
  cursor = result.results_metadata?.next_cursor ?? undefined;
} while (cursor);
const sql = postgres(process.env.DATABASE_URL!, { max: 1 });
try {
  const wallets = await sql<Array<{ stytch_user_id: string; wallet: { hasOpenedChannel?: boolean } }>>`select stytch_user_id, wallet from keyway_wallets`;
  const expected = [...new Set([...ids, ...wallets.map((row) => row.stytch_user_id)])].sort();
  const supplied = report.accounts.map((row) => row.userId).sort();
  if (JSON.stringify(expected) !== JSON.stringify(supplied)) throw new Error("Report must cover every legacy test account exactly once, not a selected subset");
  const appIds = (await sql<Array<{ app_id: string }>>`select app_id from keyway_applications`).map((row) => row.app_id).sort();
  if (JSON.stringify(appIds) !== JSON.stringify([...report.preservedAppIds].sort())) throw new Error("Application preservation inventory changed");
  const tip = BigInt(await rpc("get_tip_block_number", []));
  for (const account of report.accounts) {
    const ownerConfirmed = typeof report.ownerConfirmedNoOpenBrowserChannelsAt === "string" && Number.isFinite(Date.parse(report.ownerConfirmedNoOpenBrowserChannelsAt));
    if (!account.managedRetired || (!account.browserInspected && !ownerConfirmed) || !Array.isArray(account.channels)) throw new Error("Active node state or missing browser inspection/owner confirmation blocks the reset");
    if (wallets.find((row) => row.stytch_user_id === account.userId)?.wallet.hasOpenedChannel && !account.channels.length && !ownerConfirmed) throw new Error("A previously funded wallet requires settlement evidence or explicit owner confirmation that no browser channels remain open");
    for (const channel of account.channels) {
      if (!channel.cooperative) throw new Error("Force-close settlement requires separate approval and verification");
      const closing = await rpc("get_transaction", [channel.closingTransaction]);
      if (closing?.tx_status?.status !== "committed" || !closing.transaction?.inputs?.some((input: { previous_output: { tx_hash: string; index: string } }) => input.previous_output.tx_hash === channel.fundingHash && BigInt(input.previous_output.index) === BigInt(channel.fundingIndex))) throw new Error("Closing transaction does not spend the inventoried funding cell");
      const header = await rpc("get_header", [closing.tx_status.block_hash]);
      if (tip - BigInt(header.number) + 1n < 6n) throw new Error("Wait for six closing-transaction confirmations");
    }
  }
  if (!process.argv.includes("--execute")) {
    console.log(JSON.stringify({ ready: true, users: expected.length, preservedApplications: appIds.length, deleted: false }));
  } else {
    if (process.env.KEYWAY_LEGACY_AUTH_DISABLED !== "1") throw new Error("Freeze legacy auth/provisioning and explicitly set KEYWAY_LEGACY_AUTH_DISABLED=1 before execution");
    const [migration] = await sql<Array<{ version: number }>>`select max(version) as version from keyway_schema_migrations`;
    if (migration.version < 10) throw new Error("Apply reviewed replacement migrations before executing the reset");
    // Provider deletion invalidates the old authentication identity. A partial
    // provider outage leaves wallet records intact for a reviewed retry.
    for (const id of ids) await stytch(`/v1/users/${encodeURIComponent(id)}`, "DELETE");
    await sql.begin(async (tx) => {
      for (const table of ["keyway_device_leases", "keyway_signing_confirmations", "keyway_node_backups", "keyway_managed_confirmations", "keyway_idempotency_keys", "keyway_wallets"]) await tx.unsafe(`delete from ${table} where stytch_user_id = any($1::text[])`, [expected]);
      await tx`update keyway_applications set owner_stytch_user_id = null where owner_stytch_user_id = any(${expected}::text[])`;
      await tx`delete from keyway_otp_methods`;
    });
    console.log(JSON.stringify({ deletedUsers: expected.length, preservedApplications: appIds.length, nodeFiles: "Purge retired exact directories separately; never remove whole volumes" }));
  }
} finally { await sql.end(); }

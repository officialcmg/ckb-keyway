import { createHash } from "node:crypto";
import postgres from "postgres";

// Read-only inventory. Never calls migrations, creates a node, or deletes a user.
const projectId = process.env.STYTCH_PROJECT_ID;
const secret = process.env.STYTCH_SECRET;
if (process.env.STYTCH_ENVIRONMENT !== "test" || !projectId || !secret) throw new Error("Legacy test project credentials are required");
const users: Array<{ user_id: string; trusted_metadata?: Record<string, unknown> }> = [];
let cursor: string | undefined;
do {
  const response = await fetch("https://test.stytch.com/v1/users/search", {
    method: "POST", headers: { Authorization: `Basic ${Buffer.from(`${projectId}:${secret}`).toString("base64")}`, "Content-Type": "application/json" },
    body: JSON.stringify({ limit: 1000, ...(cursor ? { cursor } : {}) }), signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`Legacy user inventory failed (${response.status})`);
  const result = await response.json();
  users.push(...result.results);
  cursor = result.results_metadata?.next_cursor ?? undefined;
} while (cursor);
const sql = postgres(process.env.DATABASE_URL!, { max: 1, connect_timeout: 10, idle_timeout: 1 });
try {
  const wallets = await sql<Array<{ stytch_user_id: string; wallet: { litPkpId?: string; hasOpenedChannel?: boolean } }>>`select stytch_user_id, wallet from keyway_wallets`;
  const ids = [...new Set([...users.map((u) => u.user_id), ...wallets.map((w) => w.stytch_user_id)])].sort();
  const rows: Record<string, number> = {};
  for (const table of ["keyway_wallets", "keyway_device_leases", "keyway_signing_confirmations", "keyway_node_backups", "keyway_managed_confirmations", "keyway_idempotency_keys"]) {
    const [row] = await sql.unsafe(`select count(*)::int as count from ${table}`);
    rows[table] = row.count;
  }
  const [applications] = await sql`select count(*)::int as count from keyway_applications`;
  console.log(JSON.stringify({ version: 1, generatedAt: new Date().toISOString(), projectId, environment: "test", stytchUsers: users.length, legacyRows: rows, preservedApplications: applications.count,
    accounts: ids.map((id) => {
      const wallet = wallets.find((row) => row.stytch_user_id === id)?.wallet;
      const metadata = users.find((user) => user.user_id === id)?.trusted_metadata?.keyway as typeof wallet;
      const pkp = wallet?.litPkpId ?? metadata?.litPkpId;
      return { userId: id, managedDirectoryId: createHash("sha256").update(id).digest("hex"), databasePrefix: pkp ? `/wasm-${pkp}` : undefined, hasOpenedChannel: wallet?.hasOpenedChannel ?? metadata?.hasOpenedChannel ?? false, channelInspection: "required-before-deletion" };
    }),
  }, null, 2));
} finally { await sql.end(); }

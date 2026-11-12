import * as ccc from "@ckb-ccc/core";
import { database, type DatabaseSql } from "./database.ts";
import { serializeTransaction } from "./funding-transaction.ts";

/**
 * The transactions KeyWay signed for an account that may still be in the node's pool. Every client signs through
 * this server, so any client can load them before it builds a send: their spent cells are skipped and their change
 * (and the newest send-limit cell) can be used, even by a client that didn't make them.
 */

/** How long a signed transaction the node doesn't know yet stays listed: the signing client may not have sent it yet. */
export const UNSENT_GRACE_MS = 2 * 60_000;
/** A pending transaction older than this is dropped from the list whatever its status. */
const MAX_AGE = "1 day";
const MAX_LISTED = 64;

/** `connection` is a reserved connection the caller holds, if any, so it never waits on the pool while holding one. */
export async function recordPendingTransaction(userId: string, transaction: ccc.Transaction, connection?: DatabaseSql): Promise<void> {
  const sql = connection ?? await database();
  await sql`
    insert into keyway_v2_pending_transactions (user_id, transaction_hash, transaction)
    values (${userId}, ${transaction.hash()}, ${sql.json(serializeTransaction(transaction) as never)})
    on conflict (user_id, transaction_hash) do update set transaction = excluded.transaction
  `;
}

export type TransactionStatus = "pending" | "proposed" | "committed" | "rejected" | "unknown" | string;
export type StatusOf = (hash: string) => Promise<TransactionStatus | undefined>;

/**
 * The node's own status for a transaction. Read raw: CCC's getTransaction returns nothing for "unknown" and
 * "rejected" (the node sends no transaction body then), and those are the statuses that drop an entry.
 */
export function nodeStatus(client: ccc.Client): StatusOf {
  return async (hash) => {
    const known = await client.getTransaction(hash);
    if (known) return known.status;
    const result = await (client as unknown as { requestor: { request: (method: string, params: unknown[]) => Promise<unknown> } }).requestor.request("get_transaction", [hash, "0x1"]) as { tx_status?: { status?: string } } | null;
    return result?.tx_status?.status;
  };
}

/**
 * The account's pending transactions, oldest first, after dropping those the node reports committed or rejected,
 * and those it hasn't known for longer than the grace period (dropped from the pool, or never sent). A status the
 * node can't give right now keeps the entry.
 */
export type PendingTransaction = { transaction: ccc.Transaction; status: TransactionStatus; signedAt: number };

export async function listPendingTransactions(userId: string, statusOf: StatusOf, now = Date.now()): Promise<PendingTransaction[]> {
  const sql = await database();
  await sql`delete from keyway_v2_pending_transactions where user_id = ${userId} and signed_at < now() - ${MAX_AGE}::interval`;
  const rows = await sql<Array<{ transaction_hash: string; transaction: ccc.TransactionLike; signed_at: Date; seen_at: Date | null }>>`
    select transaction_hash, transaction, signed_at, seen_at from keyway_v2_pending_transactions
    where user_id = ${userId} order by seq limit ${MAX_LISTED}
  `;
  const statuses = await Promise.all(rows.map((row) => statusOf(row.transaction_hash).catch(() => undefined)));
  const kept: PendingTransaction[] = [];
  const gone: string[] = [];
  const seen: string[] = [];
  rows.forEach((row, index) => {
    const status = statuses[index];
    if (status === "committed" || status === "rejected") { gone.push(row.transaction_hash); return; }
    if (status === "unknown") {
      const since = (row.seen_at ?? row.signed_at).getTime();
      if (now - since > UNSENT_GRACE_MS) { gone.push(row.transaction_hash); return; }
    } else if (status === "pending" || status === "proposed") seen.push(row.transaction_hash);
    kept.push({ transaction: ccc.Transaction.from(row.transaction), status: status ?? "unknown", signedAt: row.signed_at.getTime() });
  });
  if (gone.length > 0) await sql`delete from keyway_v2_pending_transactions where user_id = ${userId} and transaction_hash in ${sql(gone)}`;
  // A transaction the pool held and then lost is gone once it stays unknown for the grace period from then.
  if (seen.length > 0) await sql`update keyway_v2_pending_transactions set seen_at = now() where user_id = ${userId} and transaction_hash in ${sql(seen)}`;
  return kept;
}

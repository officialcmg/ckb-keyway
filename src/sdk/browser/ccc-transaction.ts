import * as ccc from "@ckb-ccc/core";

export function serializeCccTransaction(transactionLike: unknown): Record<string, unknown> {
  const transaction = ccc.Transaction.from(transactionLike as ccc.TransactionLike);
  return JSON.parse(ccc.stringify(transaction)) as Record<string, unknown>;
}

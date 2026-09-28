import * as ccc from "@ckb-ccc/core";
import { JsonRpcTransformers } from "@ckb-ccc/core/advanced";

export function serializeCccTransaction(transactionLike: unknown): Record<string, unknown> {
  const transaction = ccc.Transaction.from(transactionLike as ccc.TransactionLike);
  return JSON.parse(ccc.stringify(transaction)) as Record<string, unknown>;
}

export function serializeCccTransactionForRpc(transactionLike: unknown) {
  return JsonRpcTransformers.transactionFrom(transactionLike as ccc.TransactionLike);
}

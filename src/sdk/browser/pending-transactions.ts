import * as ccc from "@ckb-ccc/core";
import type { SendLimitHead, SendLimitOffer } from "./send-limits";

export type PendingState = { transactions: ccc.Transaction[]; sendLimit?: SendLimitHead; sendLimitOffer?: SendLimitOffer };
type Load = () => Promise<{ transactions: ccc.TransactionLike[]; sendLimit?: SendLimitHead; sendLimitOffer?: { ckb: string } }>;

/**
 * Keeps CCC's cache in step with the account's transactions that another client (another tab, a reload, another
 * device, an app's backend) had KeyWay sign and that may still be in the pool. Each is marked in the order it was
 * signed, so its inputs are skipped and its outputs (change, and the newest send-limit cell) can be spent, the way
 * CCC already chains sends made in one page. Loading again within `minIntervalMs` reuses the last answer.
 */
export class PendingTransactions {
  private state: PendingState = { transactions: [] };
  private loadedAt = 0;
  private loading?: Promise<PendingState>;

  constructor(private readonly load: Load, private readonly client: ccc.Client, private readonly minIntervalMs = 1_000) {}

  /** The newest known state. A failed load (an older KeyWay server, a network error) keeps the last one. */
  async refresh(force = false): Promise<PendingState> {
    if (this.loading) return this.loading;
    if (!force && Date.now() - this.loadedAt < this.minIntervalMs) return this.state;
    this.loading = (async () => {
      try {
        const answer = await this.load();
        const transactions = (Array.isArray(answer?.transactions) ? answer.transactions : []).map((transaction) => ccc.Transaction.from(transaction));
        // One at a time: a later transaction may spend an earlier one's output, and must mark it spent after.
        for (const transaction of transactions) await this.client.cache.markTransactions(transaction);
        const offer = answer?.sendLimitOffer && /^[0-9]{1,20}$/.test(String(answer.sendLimitOffer.ckb)) ? { ckb: BigInt(answer.sendLimitOffer.ckb) } : undefined;
        this.state = { transactions, ...(answer?.sendLimit ? { sendLimit: answer.sendLimit } : {}), ...(offer && !answer?.sendLimit ? { sendLimitOffer: offer } : {}) };
      } catch {
        // Sending still works without it; only a cell another client spent may be picked.
      }
      // A failure waits as long as a success, so a server without the list isn't asked on every step.
      this.loadedAt = Date.now();
      return this.state;
    })().finally(() => { this.loading = undefined; });
    return this.loading;
  }

  /**
   * Records a transaction this client just had signed: it is marked in the cache (CCC does that again once it is
   * sent), and if it spent the send-limit cell its successor becomes the newest one at once.
   */
  async signed(transaction: ccc.Transaction, secp?: ccc.Script): Promise<void> {
    await this.client.cache.markTransactions(transaction);
    const head = this.state.sendLimit;
    if (!head) return;
    const spent = transaction.inputs.findIndex((input) => input.previousOutput.eq(ccc.OutPoint.from(head.outPoint)));
    if (spent === -1) return;
    const type = ccc.CellOutput.from(head.cellOutput).type;
    const index = transaction.outputs.findIndex((output) => Boolean(type && output.type?.eq(type)) && (!secp || output.lock.eq(secp)));
    if (index === -1) return;
    const record = transaction.getWitnessArgsAt(spent)?.inputType ?? "0x";
    this.state = {
      transactions: [...this.state.transactions, transaction],
      sendLimit: {
        outPoint: { txHash: transaction.hash(), index },
        cellOutput: transaction.outputs[index],
        outputData: ccc.hexFrom(transaction.outputsData[index]),
        recordEntriesBytes: Math.max(0, ccc.bytesFrom(record).length - 6),
      },
    };
    this.loadedAt = Date.now();
  }
}

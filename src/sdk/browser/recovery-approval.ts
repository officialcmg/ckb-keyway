import * as ccc from "@ckb-ccc/core";

/**
 * The readable text a recovery backup signs to approve a rescue, built exactly as KeyWay's on-chain verifiers
 * (contracts/keyway-approval) rebuild it from the transaction, so the wallet shows what moves and where:
 *
 *   KeyWay recovery
 *   Move everything to ckt1…
 *   CKB: 12,345.678
 *   Tokens: 2 token cells
 *   Fee: 0.00001234 CKB
 *   Transaction: 0x<sighash>
 *
 * `CKB` is the outputs' total capacity (everything the destination receives, including the CKB in token
 * cells), `Tokens` counts the outputs with a type script, `Fee` is the inputs less the outputs. The sighash line
 * binds the signature to one transaction. A transaction that isn't a rescue (every output to one lock other than
 * the account's, no data without a type script) has no approval text, and the verifiers refuse it.
 */
export type RescueApproval = {
  destination: ccc.Script;
  /** Shannons in all outputs. */
  ckb: bigint;
  tokenCells: number;
  /** Shannons of inputs less outputs. */
  fee: bigint;
};

/** The verifiers build at most this many bytes; a longer destination address can't be approved. */
export const MAX_APPROVAL_TEXT = 480;

/** The network byte in a backup's signature: it picks the address prefix the verifier writes. */
export function approvalNetworkByte(client: ccc.Client): 0 | 1 {
  return client.addressPrefix === "ckb" ? 1 : 0;
}

/** Shannons as CKB with thousands separators and up to 8 decimals, trailing zeros dropped. */
export function approvalAmount(shannons: bigint): string {
  const whole = (shannons / 100_000_000n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const fraction = (shannons % 100_000_000n).toString().padStart(8, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole;
}

export function recoveryApprovalText(client: ccc.Client, approval: RescueApproval, sighash: ccc.HexLike): string {
  const hash = ccc.bytesFrom(sighash);
  if (hash.length !== 32) throw new Error("A sighash must be 32 bytes");
  const tokens = approval.tokenCells === 0 ? "none" : approval.tokenCells === 1 ? "1 token cell" : `${approval.tokenCells} token cells`;
  const text = [
    "KeyWay recovery",
    `Move everything to ${ccc.Address.fromScript(approval.destination, client).toString()}`,
    `CKB: ${approvalAmount(approval.ckb)}`,
    `Tokens: ${tokens}`,
    `Fee: ${approvalAmount(approval.fee)} CKB`,
    `Transaction: ${ccc.hexFrom(hash)}`,
  ].join("\n");
  if (new TextEncoder().encode(text).length > MAX_APPROVAL_TEXT) throw new Error("The destination address is too long to approve with a backup");
  return text;
}

/**
 * What a transaction moves, read the way the verifiers read it, or a refusal when it isn't a rescue.
 * `inputCapacity` is the inputs' total capacity, from cells checked against their creating transactions.
 */
export function rescueApproval(transaction: ccc.Transaction, account: ccc.ScriptLike, inputCapacity: bigint): RescueApproval {
  const refuse = (reason: string): never => { throw new Error(`This transaction can't be approved by a backup: ${reason}`); };
  const [first] = transaction.outputs;
  if (!first) refuse("it has no outputs");
  const destination = first.lock;
  if (destination.eq(ccc.Script.from(account))) refuse("it sends to the account itself");
  let ckb = 0n;
  let tokenCells = 0;
  transaction.outputs.forEach((output, index) => {
    if (!output.lock.eq(destination)) refuse("its outputs go to more than one address");
    ckb += output.capacity;
    if (output.type) tokenCells += 1;
    else if (ccc.hexFrom(transaction.outputsData[index] ?? "0x") !== "0x") refuse("an output carries data without a type script");
  });
  if (inputCapacity < ckb) refuse("its outputs exceed its inputs");
  return { destination, ckb, tokenCells, fee: inputCapacity - ckb };
}

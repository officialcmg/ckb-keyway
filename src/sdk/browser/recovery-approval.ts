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
 * the account's, no data without a type script, and token cells that are exactly the account's own, moved
 * unchanged) has no approval text, and the verifiers refuse it.
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

/** The most token cells a rescue may move (`keyway_approval::chain::MAX_TOKEN_CELLS`). */
export const MAX_RESCUE_TOKEN_CELLS = 256;

/** An input cell of the transaction, checked against the transaction that created it. */
export type RescueInputCell = { cellOutput: ccc.CellOutputLike; outputData: ccc.HexLike };

/**
 * What a transaction moves, read the way the verifiers read it, or a refusal when it isn't a rescue. `inputCells`
 * are the transaction's input cells in order, checked against the transactions that created them.
 *
 * The text counts token cells rather than naming them, so they must be exactly the account's own, moved
 * unchanged: each output with a type script has the type script and data of a distinct input of the account, and
 * each of the account's inputs with a type script is one of them. A token cell changed, left behind (burned), or
 * made under a type script the account didn't hold is refused.
 */
export function rescueApproval(transaction: ccc.Transaction, account: ccc.ScriptLike, inputCells: readonly RescueInputCell[]): RescueApproval {
  const refuse = (reason: string): never => { throw new Error(`This transaction can't be approved by a backup: ${reason}`); };
  if (inputCells.length !== transaction.inputs.length) throw new Error("The input cells don't match the transaction's inputs");
  const [first] = transaction.outputs;
  if (!first) refuse("it has no outputs");
  const accountLock = ccc.Script.from(account);
  const destination = first.lock;
  if (destination.eq(accountLock)) refuse("it sends to the account itself");
  const tokenKey = (type: ccc.Script, data: ccc.HexLike) => `${type.hash()}:${ccc.hashCkb(data)}`;
  let ckb = 0n;
  const tokens: string[] = [];
  transaction.outputs.forEach((output, index) => {
    if (!output.lock.eq(destination)) refuse("its outputs go to more than one address");
    ckb += output.capacity;
    const data = ccc.hexFrom(transaction.outputsData[index] ?? "0x");
    if (output.type) tokens.push(tokenKey(output.type, data));
    else if (data !== "0x") refuse("an output carries data without a type script");
  });
  if (tokens.length > MAX_RESCUE_TOKEN_CELLS) refuse(`it moves more than ${MAX_RESCUE_TOKEN_CELLS} token cells`);
  const unmoved = [...tokens];
  let inputCapacity = 0n;
  for (const cell of inputCells) {
    const cellOutput = ccc.CellOutput.from(cell.cellOutput);
    inputCapacity += cellOutput.capacity;
    if (!cellOutput.lock.eq(accountLock) || !cellOutput.type) continue;
    const at = unmoved.indexOf(tokenKey(cellOutput.type, cell.outputData));
    if (at < 0) refuse("one of the account's token cells isn't moved unchanged");
    unmoved.splice(at, 1);
  }
  if (unmoved.length > 0) refuse("a token cell it creates isn't one of the account's, moved unchanged");
  if (inputCapacity < ckb) refuse("its outputs exceed its inputs");
  return { destination, ckb, tokenCells: tokens.length, fee: inputCapacity - ckb };
}

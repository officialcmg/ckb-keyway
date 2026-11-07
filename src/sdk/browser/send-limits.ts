import * as ccc from "@ckb-ccc/core";

/**
 * Send limits the policy Action enforces (lit-actions/sign-ckb-transaction.js, research/send-limits/README.md).
 * An account with limits on has one send-limit cell at its key's secp256k1 address, with a Type ID and this data:
 * "KWSL" ‖ 0x01 ‖ email fingerprint (32) ‖ flags (1) ‖ CKB amount (u64 LE) ‖ n (1) ‖ n × (token type hash (32) ‖
 * amount (u128 LE)). Every send spends it and creates its successor, and the witness of that input carries the
 * chain record the Action checks: "KWSR" ‖ 0x01 ‖ count ‖ entries.
 */
export const SEND_LIMIT_MAGIC = "0x4b57534c";
export const SEND_LIMIT_RECORD_MAGIC = "0x4b575352";
export const SEND_LIMIT_UNLIMITED = (1n << 64n) - 1n;
export const MAX_SEND_LIMIT_TOKENS = 8;
/** Bytes of a record entry without tokens, and per token. */
export const RECORD_ENTRY_BYTES = 49;
export const RECORD_TOKEN_BYTES = 48;
/** Spare CKB the server leaves in a new cell, which pays the few hundred bytes each send adds. */
export const SEND_LIMIT_SPARE = 100_000_000n;

/**
 * Send limits are on by default: an account's first send offers to turn them on with this daily amount, which the
 * user can change before confirming.
 */
export const DEFAULT_DAILY_LIMIT_CKB = 100_000n;
export const DEFAULT_DAILY_LIMIT_SHANNONS = DEFAULT_DAILY_LIMIT_CKB * 100_000_000n;
/**
 * Plain CKB at the key's secp256k1 address before limits are offered: the cell itself (173 CKB plus the 1 CKB spare),
 * a change cell (61 CKB) and the fee. Below this the account sends as before until it has enough.
 */
export const SEND_LIMIT_OFFER_MINIMUM = 236n * 100_000_000n;

/** What KeyWay offers when an account without send limits sends: the daily CKB amount to start from, in shannons. */
export type SendLimitOffer = { ckb: bigint };

export type SendLimitSettings = {
  /** The keyed fingerprint of the bound email (32 bytes); never the address. */
  fingerprint: ccc.Hex;
  /** Tokens without an amount of their own: unlimited (limits off) or a code for every transfer. */
  tokensUnlimited: boolean;
  /** CKB a day in shannons; undefined for no limit. */
  ckb?: bigint;
  /** Amounts by token type script hash, in the token's smallest unit. */
  tokens: Map<string, bigint>;
};

export function encodeSendLimitSettings(settings: SendLimitSettings): ccc.Hex {
  const fingerprint = ccc.bytesFrom(settings.fingerprint);
  if (fingerprint.length !== 32) throw new Error("The email fingerprint must be 32 bytes");
  const tokens = [...settings.tokens].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  if (tokens.length > MAX_SEND_LIMIT_TOKENS) throw new Error(`At most ${MAX_SEND_LIMIT_TOKENS} tokens can have their own daily amount`);
  const ckb = settings.ckb ?? SEND_LIMIT_UNLIMITED;
  if (ckb < 0n || ckb > SEND_LIMIT_UNLIMITED) throw new Error("The CKB amount is out of range");
  return ccc.hexFrom(ccc.bytesConcat(
    SEND_LIMIT_MAGIC, [0x01], fingerprint, [settings.tokensUnlimited ? 1 : 0], ccc.numLeToBytes(ckb, 8), [tokens.length],
    ...tokens.map(([asset, amount]) => ccc.bytesConcat(asset, ccc.numLeToBytes(amount, 16))),
  ));
}

export function decodeSendLimitSettings(data: ccc.HexLike): SendLimitSettings {
  const bytes = ccc.bytesFrom(data);
  if (bytes.length < 47 || ccc.hexFrom(bytes.slice(0, 4)) !== SEND_LIMIT_MAGIC || bytes[4] !== 1) throw new Error("Not a send-limit cell");
  const count = bytes[46];
  if (bytes.length !== 47 + count * 48) throw new Error("Not a send-limit cell");
  const tokens = new Map<string, bigint>();
  for (let i = 0; i < count; i++) {
    const at = 47 + i * 48;
    tokens.set(ccc.hexFrom(bytes.slice(at, at + 32)), ccc.numLeFromBytes(bytes.slice(at + 32, at + 48)));
  }
  const ckb = ccc.numLeFromBytes(bytes.slice(38, 46));
  return { fingerprint: ccc.hexFrom(bytes.slice(5, 37)), tokensUnlimited: (bytes[37] & 1) === 1, ...(ckb === SEND_LIMIT_UNLIMITED ? {} : { ckb }), tokens };
}

/**
 * Settings for the server's daily amounts ("ckb" or a token's type script hash, to its amount). No amounts at all
 * means limits off: every asset unlimited, as the server's own rule has it.
 */
export function settingsFromDailyAmounts(amounts: Map<string, bigint>, fingerprint: ccc.HexLike): SendLimitSettings {
  const tokens = new Map([...amounts].filter(([asset]) => asset !== "ckb"));
  return { fingerprint: ccc.hexFrom(fingerprint), tokensUnlimited: amounts.size === 0, ...(amounts.has("ckb") ? { ckb: amounts.get("ckb") } : {}), tokens };
}

export function isSendLimitCell(cellOutput: ccc.CellOutputLike, outputData: ccc.HexLike, secp: ccc.ScriptLike): boolean {
  const output = ccc.CellOutput.from(cellOutput);
  const data = ccc.hexFrom(outputData);
  return output.lock.eq(ccc.Script.from(secp)) && Boolean(output.type && output.type.codeHash === TYPE_ID_CODE_HASH && output.type.hashType === "type") && data.startsWith(SEND_LIMIT_MAGIC);
}

const TYPE_ID_CODE_HASH = "0x00000000000000000000000000000000000000000000000000545950455f4944";

/** The account's current send-limit cell, as the server reports it, and how many record bytes the next send needs. */
export type SendLimitHead = {
  outPoint: { txHash: ccc.Hex; index: number };
  cellOutput: ccc.CellOutputLike;
  outputData: ccc.Hex;
  /** Bytes of the previous record's entries the next record may keep. */
  recordEntriesBytes: number;
};

/** Index of the send-limit input in a transaction, if any. */
export function sendLimitInputIndex(transaction: ccc.Transaction, head: Pick<SendLimitHead, "outPoint">): number {
  const outPoint = ccc.OutPoint.from(head.outPoint);
  return transaction.inputs.findIndex((input) => input.previousOutput.eq(outPoint));
}

/**
 * Bytes to reserve for the record: the previous entries, this transaction's own entry with a token entry for every
 * typed input (more than it can need), and room for two more sends made meanwhile from another client.
 */
export function recordReserve(head: Pick<SendLimitHead, "recordEntriesBytes">, typedInputs: number): number {
  return 6 + head.recordEntriesBytes + RECORD_ENTRY_BYTES + typedInputs * RECORD_TOKEN_BYTES + 2 * RECORD_ENTRY_BYTES;
}

/**
 * Chains a transaction on the send-limit cell: appends the cell as an input and its unchanged copy as an output,
 * with a zero placeholder for the record in that input's witness, which KeyWay's server fills in. Doing it before
 * the fee is computed keeps the fee right; it does nothing if the transaction already spends the cell.
 */
export function chainOnSendLimit(transaction: ccc.Transaction, head: SendLimitHead): void {
  if (sendLimitInputIndex(transaction, head) !== -1) return;
  // Copies: CCC's from() hands back the same object, and the output's capacity may change (the fee).
  const cellOutput = ccc.CellOutput.from(head.cellOutput).clone();
  transaction.inputs.push(ccc.CellInput.from({ previousOutput: head.outPoint, cellOutput, outputData: head.outputData }));
  transaction.outputs.push(cellOutput.clone());
  transaction.outputsData.push(head.outputData);
  const typed = transaction.inputs.filter((input) => input.cellOutput?.type).length;
  setSendLimitRecord(transaction, transaction.inputs.length - 1, new Uint8Array(recordReserve(head, typed)));
}

/** Puts the record (or its placeholder) in the input_type of the send-limit input's witness. */
export function setSendLimitRecord(transaction: ccc.Transaction, index: number, record: ccc.HexLike): void {
  while (transaction.witnesses.length < index) transaction.witnesses.push("0x");
  const witness = transaction.getWitnessArgsAt(index) ?? ccc.WitnessArgs.from({});
  witness.inputType = ccc.hexFrom(record);
  transaction.setWitnessArgsAt(index, witness);
}

/** The record bytes a record's entries take, without its 6-byte header. */
export function recordEntriesBytes(record: ccc.HexLike): number {
  const bytes = ccc.bytesFrom(record);
  return bytes.length >= 6 && ccc.hexFrom(bytes.slice(0, 4)) === SEND_LIMIT_RECORD_MAGIC ? bytes.length - 6 : 0;
}

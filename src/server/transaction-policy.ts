import * as ccc from "@ckb-ccc/core";
import { formatAsset, isXudtByDataHash, isXudtCompatible } from "../sdk/browser/tokens.ts";
import { accountLocks, refuseAdminListSpend, refuseForeignOmnilockOutputs, verifyRecoveryAnchor, type KeyWayRecovery } from "../sdk/browser/account-lock.ts";
import { keptCapacity, signingGroups, withChainInputs, type SigningGroup } from "./funding-transaction.ts";
import type { ReadyWallet } from "./user-wallet.ts";

const SHANNONS_PER_CKB = 100_000_000n;
const MIN_FEE_CAP = SHANNONS_PER_CKB / 100n; // 0.01 CKB
/** How the details label the account's AdminList cell. */
const RECOVERY_LIST = "recovery list";
const TYPE_ID_CODE_HASH = "0x00000000000000000000000000000000000000000000000000545950455f4944";
/** "KWSL", the start of the send-limit settings cell's data. */
const SEND_LIMIT_SETTINGS_MAGIC = "0x4b57534c";
const FIBER_FUNDING_LOCK_CODE_HASH = "0x6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c";

// Spore protocol testnet scripts (sporeprotocol/spore-sdk predefined config).
const SPORE_CODE_HASHES = new Set([
  "0x0b1f412fbae26853ff7d082d422c2bdd9e2ff94ee8aaec11240a5b34cc6e890f",
  "0x685a60219309029d01310311dba953d67029170ca4848a4ff638e57002130a0d",
  "0xbbad126377d45f90a8ee120da988a2d7332c78ba8fd679aab478a19d6c133494",
]);
const CLUSTER_CODE_HASHES = new Set([
  "0x0bbe768b519d8ea7b96d58f1182eb7e6ef96c541fbd9526975077ee09f049058",
  "0x598d793defef36e2eeba54a9b45130e4ca92822e1d193671f490950c3b856080",
]);

/**
 * A token's net change for the account: `amount` is signed raw units, `amountText` is for people ("-25 RUSD"),
 * `id` is a short form of `asset`, the token's type script hash.
 */
export type TokenEffect = { id: string; asset: string; standard: "xUDT" | "sUDT"; amount: string; amountText: string };
export type NftEffect = { kind: "Spore" | "Cluster"; id: string; change: "sent" | "received" | "minted" | "burned" };
export type DaoEffect = { action: "deposit" | "withdrawal request" | "withdrawal"; amountCkb: string };
export type Recipient = {
  address: string;
  kind: "wallet" | "contract" | "Fiber channel";
  walletType?: string;
  ckb: string;
  tokens: Array<{ id: string; amount: string; amountText: string }>;
  nfts: string[];
};
export type CellSummary = { lock: string; type?: string; capacityCkb: string; dataBytes: number };

export type TransactionPreview = {
  network: "CKB testnet";
  /**
   * CKB leaving the user's account as the daily amount counts it, excluding the fee when the user pays all of it. It
   * includes CKB put into the account's own cells under a type script that could keep it (`heldUnderScriptsCkb`).
   */
  sendingCkb: string;
  /** CKB that stays in the user's cells but under a type script that could keep it, counted as sent. */
  heldUnderScriptsCkb?: string;
  /** Plain CKB arriving in the user's account. */
  receivingCkb: string;
  feeCkb: string;
  tokens: TokenEffect[];
  nfts: NftEffect[];
  dao: DaoEffect[];
  recipients: Recipient[];
  unrecognized: Array<{ codeHash: string; cells: number }>;
  otherSigners: number;
  details: { inputs: CellSummary[]; outputs: CellSummary[] };
  transactionHash: string;
};

export type KnownScripts = {
  xudt: ccc.ScriptInfo;
  sudt: ccc.ScriptInfo;
  dao: ccc.ScriptInfo;
  wallets: Array<{ name: string; info: ccc.ScriptInfo }>;
  quiet: ccc.ScriptInfo[];
};

export type ValidatedTransaction = {
  transaction: ccc.Transaction;
  signer: ccc.SignerCkbPublicKey;
  script: ccc.Script;
  /** Every lock group of the account in the transaction, the current lock first. */
  groups: SigningGroup[];
  preview: TransactionPreview;
  /** All CKB leaving the user's account including any fee they pay; compared with the email threshold. */
  outflowShannons: bigint;
  /** True when any token (xUDT or sUDT) leaves the user's account. */
  tokensLeaving: boolean;
  /** Each token leaving the account, by its type script hash, with the amount in the token's smallest unit. */
  tokenOutflows: TokenOutflow[];
};

/**
 * `perCell` marks an asset whose amounts KeyWay can't read, counted one per cell: a cell can hold any balance, so
 * with a daily amount set for it, it always needs the code (as the policy Action rules).
 */
export type TokenOutflow = { asset: string; amount: bigint; perCell?: true };

export async function loadKnownScripts(client: ccc.Client): Promise<KnownScripts> {
  const get = (script: ccc.KnownScript) => client.getKnownScript(script);
  const [xudt, sudt, dao, secp, multisig, multisigV2, joyId, omni, acp, pw, nostr, typeId, unique] = await Promise.all([
    get(ccc.KnownScript.XUdt), get(ccc.KnownScript.SUdt), get(ccc.KnownScript.NervosDao),
    get(ccc.KnownScript.Secp256k1Blake160), get(ccc.KnownScript.Secp256k1Multisig), get(ccc.KnownScript.Secp256k1MultisigV2),
    get(ccc.KnownScript.JoyId), get(ccc.KnownScript.OmniLock), get(ccc.KnownScript.AnyoneCanPay), get(ccc.KnownScript.PWLock),
    get(ccc.KnownScript.NostrLock), get(ccc.KnownScript.TypeId), get(ccc.KnownScript.UniqueType),
  ]);
  return {
    xudt, sudt, dao,
    wallets: [
      { name: "standard", info: secp }, { name: "multisig", info: multisig }, { name: "multisig", info: multisigV2 },
      { name: "JoyID", info: joyId }, { name: "Omnilock", info: omni }, { name: "anyone-can-pay", info: acp },
      { name: "PW", info: pw }, { name: "Nostr", info: nostr },
    ],
    // Recognized type scripts that carry no value of their own (token info cells, type IDs).
    quiet: [typeId, unique],
  };
}

/** Validates a complete transaction for general signing and decodes what it does to the user's account. */
export async function previewGeneralTransaction(
  wallet: ReadyWallet,
  input: unknown,
  client: ccc.Client = new ccc.ClientPublicTestnet(),
): Promise<ValidatedTransaction> {
  if (!input || typeof input !== "object") throw new Error("A complete CKB transaction is required");
  const transaction = withChainInputs(ccc.Transaction.from(input as ccc.TransactionLike));
  if (transaction.version !== 0n) throw new Error("Only CKB transaction version 0 is allowed");
  if (transaction.inputs.length === 0 || transaction.inputs.length > 64) throw new Error("Transaction input count is invalid");
  if (transaction.outputs.length > 64) throw new Error("Transaction output count is invalid");
  if (transaction.headerDeps.length > 8) throw new Error("Transaction has too many header dependencies");

  const signer = new ccc.SignerCkbPublicKey(client, wallet.litPublicKey);
  // The account's address comes from its recovery record, so the record must be one the chain backs.
  if (wallet.recovery) await verifyRecoveryAnchor(client, wallet.litPublicKey, wallet.recovery);
  const locks = await accountLocks(client, wallet.litPublicKey, wallet.recovery);
  const own = locks.map(({ script }) => script);
  const inputCells = await Promise.all(transaction.inputs.map((cellInput) => cellInput.getCell(client)));
  const groups = signingGroups(locks, inputCells);
  if (groups.length === 0) throw new Error("Transaction has no input owned by this KeyWay account");
  refuseAdminListSpend(transaction, inputCells, wallet.recovery);
  refuseForeignOmnilockOutputs(transaction, await client.getKnownScript(ccc.KnownScript.OmniLock), wallet.litPublicKey, wallet.recovery);
  // CCC's own groups for this key are its secp256k1 lock and anyone-can-pay locks; only the first is signed.
  const secp = locks.find(({ kind }) => kind === "secp256k1")!.script;
  const related = await signer.getRelatedScripts(transaction);
  if (related.some(({ script }) => !script.eq(secp))) throw new Error("Transaction has an unexpected signing group");

  const known = await loadKnownScripts(client);
  const described = describeTransaction(transaction, inputCells, own, known, client, feeRateCap(), wallet.recovery);
  return {
    transaction, signer, script: groups[0].script, groups, preview: described.preview,
    outflowShannons: described.outflowShannons, tokensLeaving: described.tokensLeaving, tokenOutflows: described.tokenOutflows,
  };
}

/**
 * Pure decoding of a transaction's effects on one account, which may have more than one lock (its Omnilock
 * and its old secp256k1 lock once recovery is on). Anything it can't explain becomes a visible
 * "unrecognized" entry rather than being left out.
 */
export function describeTransaction(
  transaction: ccc.Transaction,
  inputCells: Array<{ cellOutput: ccc.CellOutput; outputData: ccc.Hex }>,
  own: ccc.Script | ccc.Script[],
  known: KnownScripts,
  client: ccc.Client,
  maxFeeRate = feeRateCap(),
  recovery?: KeyWayRecovery,
): { preview: TransactionPreview; outflowShannons: bigint; tokensLeaving: boolean; tokenOutflows: TokenOutflow[] } {
  const outputs = transaction.outputs.map((cellOutput, index) => ({ cellOutput, outputData: ccc.hexFrom(transaction.outputsData[index] ?? "0x") }));
  const totalIn = sum(inputCells.map(({ cellOutput }) => cellOutput.capacity));
  const totalOut = sum(outputs.map(({ cellOutput }) => cellOutput.capacity));
  const fee = totalIn - totalOut;
  if (fee < 0n) throw new Error("Transaction outputs exceed its inputs");
  const size = BigInt(transaction.toBytes().length + 4);
  const feeCap = maxBig(MIN_FEE_CAP, size * maxFeeRate);
  if (fee > feeCap) throw new Error(`Transaction fee ${formatCkb(fee)} CKB is above the KeyWay limit of ${formatCkb(feeCap)} CKB for this transaction size`);

  const ownLocks = [own].flat();
  const isOwn = (cell: { cellOutput: ccc.CellOutput }) => ownLocks.some((lock) => lock.eq(cell.cellOutput.lock));
  const isRecoveryList = (type: ccc.Script | undefined) => Boolean(recovery && type?.hash() === recovery.adminListTypeHash.toLowerCase());
  const ownInputs = inputCells.filter(isOwn);
  const ownOutputs = outputs.filter(isOwn);
  const otherSigners = inputCells.length - ownInputs.length;
  const matches = (script: ccc.Script | undefined, info: ccc.ScriptInfo) => Boolean(script && script.codeHash === info.codeHash && script.hashType === info.hashType);
  const typeKind = (type: ccc.Script | undefined): "none" | "xUDT" | "sUDT" | "dao" | "Spore" | "Cluster" | "quiet" | "unknown" => {
    if (!type) return "none";
    if (matches(type, known.xudt) || isXudtCompatible(type) || isXudtByDataHash(type)) return "xUDT";
    if (matches(type, known.sudt)) return "sUDT";
    if (matches(type, known.dao)) return "dao";
    if (SPORE_CODE_HASHES.has(type.codeHash)) return "Spore";
    if (CLUSTER_CODE_HASHES.has(type.codeHash)) return "Cluster";
    if (known.quiet.some((info) => matches(type, info))) return "quiet";
    return "unknown";
  };
  // Typed cells that count as an asset, one per cell, as the Lit Action counts them: every type other than a token
  // (counted by amount) and Nervos DAO, except the recovery list and the send-limit settings cell (a Type ID cell
  // under the account's secp256k1 lock whose data starts with "KWSL").
  const standardLock = known.wallets.find(({ name }) => name === "standard")?.info;
  const countsPerCell = (cell: { cellOutput: ccc.CellOutput; outputData: ccc.Hex }) => {
    const type = cell.cellOutput.type;
    const kind = typeKind(type);
    if (kind === "none" || kind === "xUDT" || kind === "sUDT" || kind === "dao" || isRecoveryList(type)) return false;
    const settings = type!.codeHash === TYPE_ID_CODE_HASH && type!.hashType === "type"
      && Boolean(standardLock && matches(cell.cellOutput.lock, standardLock)) && cell.outputData.startsWith(SEND_LIMIT_SETTINGS_MAGIC);
    return !settings;
  };

  // CKB: everything the account puts in versus gets back, across all of its cells.
  const ownIn = sum(ownInputs.map(({ cellOutput }) => cellOutput.capacity));
  const ownOut = sum(ownOutputs.map(({ cellOutput }) => cellOutput.capacity));
  const userPaysFee = otherSigners === 0;
  const outflow = ownIn > ownOut ? ownIn - ownOut : 0n;
  // What the daily amount counts, as the policy Action does: a type script runs whenever its cell is spent, so
  // whoever wrote it could keep the CKB put under it. CKB the account gets back under one that can't stop it
  // (none, Nervos DAO, Type ID, a UDT without extension scripts) is kept; under any other, only as far as the
  // account already held that much under the same script.
  const keepsCkbFree = (type: ccc.Script | undefined) => {
    const kind = typeKind(type);
    return kind === "none" || kind === "dao" || (type!.codeHash === TYPE_ID_CODE_HASH && type!.hashType === "type")
      || ((kind === "xUDT" || kind === "sUDT") && ccc.bytesFrom(type!.args).length === 32);
  };
  const leaving = maxBig(0n, ownIn - keptCapacity(ownInputs, ownOutputs, keepsCkbFree));
  // What the user is told they send is what the daily amount counts, so a code asked for CKB put under a script that
  // could keep it never reads as "Send 0 CKB". That part, still in the account's own cells, is shown on its own.
  const sending = userPaysFee ? maxBig(0n, leaving - fee) : leaving;
  const atRisk = leaving - outflow;
  const receiving = ownOut > ownIn ? ownOut - ownIn : 0n;

  // Tokens: net change per token for this account.
  const tokenTotals = new Map<string, { standard: "xUDT" | "sUDT"; delta: bigint }>();
  // A token cell too short to hold an amount counts as one, per cell, as the policy Action counts it.
  const unreadTokens = new Set<string>();
  const addToken = (cell: { cellOutput: ccc.CellOutput; outputData: ccc.Hex }, sign: 1n | -1n) => {
    const kind = typeKind(cell.cellOutput.type);
    if (kind !== "xUDT" && kind !== "sUDT") return;
    const id = cell.cellOutput.type!.hash();
    const entry = tokenTotals.get(id) ?? { standard: kind, delta: 0n };
    const readable = ccc.bytesFrom(cell.outputData).length >= 16;
    if (!readable) unreadTokens.add(id);
    entry.delta += sign * (readable ? udtAmount(cell.outputData) : 1n);
    tokenTotals.set(id, entry);
  };
  ownInputs.forEach((cell) => addToken(cell, -1n));
  ownOutputs.forEach((cell) => addToken(cell, 1n));
  const tokens = [...tokenTotals].filter(([, { delta }]) => delta !== 0n)
    .map(([id, { standard, delta }]) => ({
      id: shortHash(id), asset: id, standard, amount: `${delta > 0n ? "+" : ""}${delta}`,
      amountText: `${delta > 0n ? "+" : "-"}${formatAsset(delta > 0n ? delta : -delta, id)}`,
    }));

  // NFTs: Spore and Cluster cells identified by their type args.
  const nftKey = (cell: { cellOutput: ccc.CellOutput }) => {
    const kind = typeKind(cell.cellOutput.type);
    return kind === "Spore" || kind === "Cluster" ? { kind, id: cell.cellOutput.type!.args } : undefined;
  };
  const inputNfts = inputCells.map((cell) => ({ key: nftKey(cell), own: isOwn(cell) })).filter((item) => item.key);
  const outputNfts = outputs.map((cell) => ({ key: nftKey(cell), own: isOwn(cell) })).filter((item) => item.key);
  const nfts: NftEffect[] = [];
  for (const { key } of inputNfts.filter((item) => item.own)) {
    const after = outputNfts.find((item) => item.key!.id === key!.id);
    if (!after) nfts.push({ kind: key!.kind, id: shortHash(key!.id), change: "burned" });
    else if (!after.own) nfts.push({ kind: key!.kind, id: shortHash(key!.id), change: "sent" });
  }
  for (const { key } of outputNfts.filter((item) => item.own)) {
    if (inputNfts.some((item) => item.own && item.key!.id === key!.id)) continue;
    const existed = inputNfts.some((item) => item.key!.id === key!.id);
    nfts.push({ kind: key!.kind, id: shortHash(key!.id), change: existed ? "received" : "minted" });
  }

  // Nervos DAO: deposit cells hold 8 zero bytes; withdrawal requests hold the deposit block number.
  const dao: DaoEffect[] = [];
  const isDao = (cell: { cellOutput: ccc.CellOutput }) => typeKind(cell.cellOutput.type) === "dao";
  const zero = (data: ccc.Hex) => /^0x(00)+$/.test(data);
  for (const cell of ownOutputs.filter(isDao)) {
    dao.push({ action: zero(cell.outputData) ? "deposit" : "withdrawal request", amountCkb: formatCkb(cell.cellOutput.capacity) });
  }
  if (ownOutputs.filter(isDao).length === 0) {
    for (const cell of ownInputs.filter(isDao).filter((input) => !zero(input.outputData))) {
      dao.push({ action: "withdrawal", amountCkb: formatCkb(cell.cellOutput.capacity) });
    }
  }

  // Anything carrying a type script we can't explain, on the account's cells or on any output.
  const unrecognizedCounts = new Map<string, number>();
  for (const cell of [...ownInputs, ...outputs]) {
    if (typeKind(cell.cellOutput.type) !== "unknown") continue;
    const codeHash = shortHash(cell.cellOutput.type!.codeHash);
    unrecognizedCounts.set(codeHash, (unrecognizedCounts.get(codeHash) ?? 0) + 1);
  }
  const unrecognized = [...unrecognizedCounts].map(([codeHash, cells]) => ({ codeHash, cells }));

  // Recipients: every other lock that receives an output.
  const recipients = new Map<string, Recipient>();
  for (const cell of outputs.filter((output) => !isOwn(output))) {
    const lock = cell.cellOutput.lock;
    const key = lock.hash();
    const wallet = known.wallets.find(({ info }) => matches(lock, info));
    const recipient = recipients.get(key) ?? {
      address: ccc.Address.fromScript(lock, client).toString(),
      kind: lock.codeHash === FIBER_FUNDING_LOCK_CODE_HASH ? "Fiber channel" : wallet ? "wallet" : "contract",
      ...(wallet ? { walletType: wallet.name } : {}),
      ckb: "0",
      tokens: [],
      nfts: [],
    } satisfies Recipient;
    recipient.ckb = formatCkb(parseCkb(recipient.ckb) + cell.cellOutput.capacity);
    const kind = typeKind(cell.cellOutput.type);
    if (kind === "xUDT" || kind === "sUDT") {
      const asset = cell.cellOutput.type!.hash();
      const id = shortHash(asset);
      const existing = recipient.tokens.find((token) => token.id === id);
      const amount = udtAmount(cell.outputData) + BigInt(existing?.amount ?? 0);
      const entry = { id, amount: amount.toString(), amountText: formatAsset(amount, asset) };
      if (existing) Object.assign(existing, entry);
      else recipient.tokens.push(entry);
    }
    if (kind === "Spore" || kind === "Cluster") recipient.nfts.push(`${kind} ${shortHash(cell.cellOutput.type!.args)}`);
    recipients.set(key, recipient);
  }

  const summarize = (cell: { cellOutput: ccc.CellOutput; outputData: ccc.Hex }): CellSummary => {
    const kind = typeKind(cell.cellOutput.type);
    return {
      lock: isOwn(cell) ? "you" : shortHash(cell.cellOutput.lock.hash()),
      ...(cell.cellOutput.type ? {
        type: isRecoveryList(cell.cellOutput.type) ? RECOVERY_LIST
          : kind === "unknown" || kind === "quiet" ? shortHash(cell.cellOutput.type.codeHash) : kind === "dao" ? "Nervos DAO" : kind,
      } : {}),
      capacityCkb: formatCkb(cell.cellOutput.capacity),
      dataBytes: (cell.outputData.length - 2) / 2,
    };
  };

  return {
    outflowShannons: leaving,
    tokensLeaving: [...tokenTotals.values()].some(({ delta }) => delta < 0n) || cellsLeaving(ownInputs, ownOutputs, countsPerCell).length > 0,
    // Other typed cells (NFTs, Type ID and Unique cells, scripts KeyWay can't read) leave as "tokens" counted per
    // cell (and whenever one doesn't come back unchanged). Like a token, they have no limit unless the user sets an
    // amount for their type script hash, as the Lit Action reads the send-limit cell KeyWay writes.
    tokenOutflows: [
      ...[...tokenTotals].filter(([, { delta }]) => delta < 0n)
        .map(([asset, { delta }]) => ({ asset, amount: -delta, ...(unreadTokens.has(asset) ? { perCell: true as const } : {}) })),
      ...cellsLeaving(ownInputs, ownOutputs, countsPerCell),
    ],
    preview: {
      network: "CKB testnet",
      sendingCkb: formatCkb(sending),
      ...(atRisk > 0n ? { heldUnderScriptsCkb: formatCkb(atRisk) } : {}),
      receivingCkb: formatCkb(receiving),
      feeCkb: formatCkb(fee),
      tokens,
      nfts,
      dao,
      recipients: [...recipients.values()],
      unrecognized,
      otherSigners,
      details: { inputs: inputCells.map(summarize), outputs: outputs.map(summarize) },
      transactionHash: transaction.hash(),
    },
  };
}

/**
 * Lines for the confirmation email, written from the backend's own decoding. What happens to the account's assets
 * comes before the recipients, so a long list of recipients can't push it out of the email. Each recipient is shown
 * by its whole address: the start and the checksum are all two look-alike addresses need to share.
 */
export function previewSummaryLines(preview: TransactionPreview): string[] {
  const lines = [
    `Send ${preview.sendingCkb} CKB`,
    ...(preview.heldUnderScriptsCkb ? [`Of which ${preview.heldUnderScriptsCkb} CKB stays in your account under a type script that could keep it`] : []),
    `Network fee ${preview.feeCkb} CKB`,
    `Network ${preview.network}`,
  ];
  for (const token of preview.tokens) lines.push(`Token ${token.amountText} (${token.standard} ${token.id})`);
  for (const nft of preview.nfts) lines.push(`${nft.kind} ${nft.id}: ${nft.change}`);
  for (const action of preview.dao) lines.push(`Nervos DAO ${action.action}: ${action.amountCkb} CKB`);
  for (const script of preview.unrecognized) lines.push(`Unrecognized script ${script.codeHash} (${script.cells} cells)`);
  if (preview.details.outputs.some(({ type }) => type === RECOVERY_LIST)) lines.push("Writes the account's recovery list");
  // The amount comes before the address, so an address too long for the email's line can't push it out.
  for (const recipient of preview.recipients) lines.push(`${recipient.ckb} CKB to ${recipient.address} (${recipient.kind})`);
  return lines;
}

/** The fee cap, in shannons per byte. Default: 100x CKB's 1,000 shannons/KB minimum fee rate. */
export function feeRateCap(): bigint {
  const configured = Number(process.env.KEYWAY_MAX_FEE_RATE);
  return BigInt(Number.isSafeInteger(configured) && configured > 0 ? configured : 100);
}

export function formatCkb(shannons: bigint): string {
  const whole = shannons / SHANNONS_PER_CKB;
  const fraction = (shannons % SHANNONS_PER_CKB).toString().padStart(8, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

function parseCkb(value: string): bigint {
  const [whole, fraction = ""] = value.split(".");
  return BigInt(whole) * SHANNONS_PER_CKB + BigInt(fraction.padEnd(8, "0") || "0");
}

function udtAmount(data: ccc.Hex): bigint {
  const bytes = ccc.bytesFrom(data);
  return bytes.length >= 16 ? ccc.numLeFromBytes(bytes.slice(0, 16)) : 0n;
}

function shortHash(value: string): string {
  return value.length <= 14 ? value : `${value.slice(0, 8)}…${value.slice(-4)}`;
}

function sum(values: readonly bigint[]): bigint {
  return values.reduce((total, value) => total + value, 0n);
}

function maxBig(a: bigint, b: bigint): bigint {
  return a > b ? a : b;
}

/**
 * Typed cells that count as assets one per cell (see countsPerCell) and leave the account. As in the policy Action,
 * a type counts as leaving whenever one of the account's cells of it doesn't come back with the same data, so a
 * balance can't leave while an empty cell of it stays.
 */
function cellsLeaving(
  ownInputs: Array<{ cellOutput: ccc.CellOutput; outputData: ccc.Hex }>,
  ownOutputs: Array<{ cellOutput: ccc.CellOutput; outputData: ccc.Hex }>,
  countsPerCell: (cell: { cellOutput: ccc.CellOutput; outputData: ccc.Hex }) => boolean,
): TokenOutflow[] {
  const counts = new Map<string, bigint>();
  const byData = new Map<string, Map<string, bigint>>();
  const count = (cell: { cellOutput: ccc.CellOutput; outputData: ccc.Hex }, sign: 1n | -1n) => {
    if (!countsPerCell(cell)) return;
    const asset = cell.cellOutput.type!.hash();
    if (sign < 0n && !counts.has(asset)) return;
    counts.set(asset, (counts.get(asset) ?? 0n) + sign);
    const cells = byData.get(asset) ?? new Map<string, bigint>();
    const data = cell.outputData.toLowerCase();
    cells.set(data, (cells.get(data) ?? 0n) + sign);
    byData.set(asset, cells);
  };
  ownInputs.forEach((cell) => count(cell, 1n));
  ownOutputs.forEach((cell) => count(cell, -1n));
  return [...counts].flatMap(([asset, left]) => {
    if (left > 0n) return [{ asset, amount: left, perCell: true as const }];
    return [...byData.get(asset)!.values()].some((cells) => cells > 0n) ? [{ asset, amount: 1n, perCell: true as const }] : [];
  });
}

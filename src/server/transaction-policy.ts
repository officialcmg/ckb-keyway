import * as ccc from "@ckb-ccc/core";
import { formatAsset, isXudtCompatible } from "../sdk/browser/tokens.ts";
import { accountLocks, refuseAdminListSpend, type KeyWayRecovery } from "../sdk/browser/account-lock.ts";
import { signingGroups, type SigningGroup } from "./funding-transaction.ts";
import type { ReadyWallet } from "./user-wallet.ts";

const SHANNONS_PER_CKB = 100_000_000n;
const MIN_FEE_CAP = SHANNONS_PER_CKB / 100n; // 0.01 CKB
/** How the details label the account's AdminList cell. */
const RECOVERY_LIST = "recovery list";
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

/** A token's net change for the account: `amount` is signed raw units, `amountText` is for people ("-25 RUSD"). */
export type TokenEffect = { id: string; standard: "xUDT" | "sUDT"; amount: string; amountText: string };
export type NftEffect = { kind: "Spore" | "Cluster"; id: string; change: "sent" | "received" | "minted" | "burned" };
export type DaoEffect = { action: "deposit" | "withdrawal request" | "withdrawal"; amountCkb: string };
export type Recipient = {
  address: string;
  kind: "wallet" | "contract" | "Fiber channel";
  walletType?: string;
  ckb: string;
  tokens: Array<{ id: string; amount: string }>;
  nfts: string[];
};
export type CellSummary = { lock: string; type?: string; capacityCkb: string; dataBytes: number };

export type TransactionPreview = {
  network: "CKB testnet";
  /** Plain CKB leaving the user's account, excluding the fee when the user pays all of it. */
  sendingCkb: string;
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

export type TokenOutflow = { asset: string; amount: bigint };

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
  const transaction = ccc.Transaction.from(input as ccc.TransactionLike);
  if (transaction.version !== 0n) throw new Error("Only CKB transaction version 0 is allowed");
  if (transaction.inputs.length === 0 || transaction.inputs.length > 64) throw new Error("Transaction input count is invalid");
  if (transaction.outputs.length > 64) throw new Error("Transaction output count is invalid");
  if (transaction.headerDeps.length > 8) throw new Error("Transaction has too many header dependencies");

  const signer = new ccc.SignerCkbPublicKey(client, wallet.litPublicKey);
  const locks = await accountLocks(client, wallet.litPublicKey, wallet.recovery);
  const own = locks.map(({ script }) => script);
  const inputCells = await Promise.all(transaction.inputs.map((cellInput) => cellInput.getCell(client)));
  const groups = signingGroups(locks, inputCells);
  if (groups.length === 0) throw new Error("Transaction has no input owned by this KeyWay account");
  refuseAdminListSpend(transaction, inputCells, wallet.recovery);
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
    if (matches(type, known.xudt) || isXudtCompatible(type)) return "xUDT";
    if (matches(type, known.sudt)) return "sUDT";
    if (matches(type, known.dao)) return "dao";
    if (SPORE_CODE_HASHES.has(type.codeHash)) return "Spore";
    if (CLUSTER_CODE_HASHES.has(type.codeHash)) return "Cluster";
    if (known.quiet.some((info) => matches(type, info))) return "quiet";
    return "unknown";
  };

  // CKB: everything the account puts in versus gets back, across all of its cells.
  const ownIn = sum(ownInputs.map(({ cellOutput }) => cellOutput.capacity));
  const ownOut = sum(ownOutputs.map(({ cellOutput }) => cellOutput.capacity));
  const userPaysFee = otherSigners === 0;
  const outflow = ownIn > ownOut ? ownIn - ownOut : 0n;
  const sending = userPaysFee ? maxBig(0n, outflow - fee) : outflow;
  const receiving = ownOut > ownIn ? ownOut - ownIn : 0n;

  // Tokens: net change per token for this account.
  const tokenTotals = new Map<string, { standard: "xUDT" | "sUDT"; delta: bigint }>();
  const addToken = (cell: { cellOutput: ccc.CellOutput; outputData: ccc.Hex }, sign: 1n | -1n) => {
    const kind = typeKind(cell.cellOutput.type);
    if (kind !== "xUDT" && kind !== "sUDT") return;
    const id = cell.cellOutput.type!.hash();
    const entry = tokenTotals.get(id) ?? { standard: kind, delta: 0n };
    entry.delta += sign * udtAmount(cell.outputData);
    tokenTotals.set(id, entry);
  };
  ownInputs.forEach((cell) => addToken(cell, -1n));
  ownOutputs.forEach((cell) => addToken(cell, 1n));
  const tokens = [...tokenTotals].filter(([, { delta }]) => delta !== 0n)
    .map(([id, { standard, delta }]) => ({
      id: shortHash(id), standard, amount: `${delta > 0n ? "+" : ""}${delta}`,
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
      const id = shortHash(cell.cellOutput.type!.hash());
      const existing = recipient.tokens.find((token) => token.id === id);
      const amount = udtAmount(cell.outputData);
      if (existing) existing.amount = (BigInt(existing.amount) + amount).toString();
      else recipient.tokens.push({ id, amount: amount.toString() });
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
    outflowShannons: outflow,
    tokensLeaving: [...tokenTotals.values()].some(({ delta }) => delta < 0n) || unrecognizedLeaving(ownInputs, ownOutputs, typeKind).length > 0,
    // Cells with a type script KeyWay can't read leave as "tokens" with no daily amount, counted per cell,
    // so they always need the email code once confirmation is on.
    tokenOutflows: [
      ...[...tokenTotals].filter(([, { delta }]) => delta < 0n).map(([asset, { delta }]) => ({ asset, amount: -delta })),
      ...unrecognizedLeaving(ownInputs, ownOutputs, typeKind),
    ],
    preview: {
      network: "CKB testnet",
      sendingCkb: formatCkb(sending),
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

/** Lines for the confirmation email, written from the backend's own decoding. */
export function previewSummaryLines(preview: TransactionPreview): string[] {
  const lines = [`Send ${preview.sendingCkb} CKB`, `Network fee ${preview.feeCkb} CKB`];
  for (const recipient of preview.recipients) lines.push(`To ${shortAddress(recipient.address)} (${recipient.kind}): ${recipient.ckb} CKB`);
  for (const token of preview.tokens) lines.push(`Token ${token.id} (${token.standard}): ${token.amount}`);
  for (const nft of preview.nfts) lines.push(`${nft.kind} ${nft.id}: ${nft.change}`);
  for (const action of preview.dao) lines.push(`Nervos DAO ${action.action}: ${action.amountCkb} CKB`);
  for (const script of preview.unrecognized) lines.push(`Unrecognized script ${script.codeHash} (${script.cells} cells)`);
  if (preview.details.outputs.some(({ type }) => type === RECOVERY_LIST)) lines.push("Writes the account's recovery list");
  lines.push(`Network ${preview.network}`);
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

function shortAddress(value: string): string {
  return value.length <= 24 ? value : `${value.slice(0, 12)}…${value.slice(-6)}`;
}

function sum(values: readonly bigint[]): bigint {
  return values.reduce((total, value) => total + value, 0n);
}

function maxBig(a: bigint, b: bigint): bigint {
  return a > b ? a : b;
}

function unrecognizedLeaving(
  ownInputs: Array<{ cellOutput: ccc.CellOutput }>,
  ownOutputs: Array<{ cellOutput: ccc.CellOutput }>,
  typeKind: (type: ccc.Script | undefined) => string,
): TokenOutflow[] {
  const counts = new Map<string, bigint>();
  for (const { cellOutput } of ownInputs) {
    if (typeKind(cellOutput.type) === "unknown") counts.set(cellOutput.type!.hash(), (counts.get(cellOutput.type!.hash()) ?? 0n) + 1n);
  }
  for (const { cellOutput } of ownOutputs) {
    if (typeKind(cellOutput.type) === "unknown" && counts.has(cellOutput.type!.hash())) counts.set(cellOutput.type!.hash(), counts.get(cellOutput.type!.hash())! - 1n);
  }
  return [...counts].filter(([, left]) => left > 0n).map(([asset, amount]) => ({ asset, amount }));
}

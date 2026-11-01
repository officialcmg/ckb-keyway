import * as ccc from "@ckb-ccc/core";
import type { User } from "./auth-user.ts";
import { accountLocks, omnilockOwnerWitnessLock, refuseAdminListSpend, refuseForeignOmnilockOutputs, verifyRecoveryAnchor, witnessLockLength, type KeyWayLockKind } from "../sdk/browser/account-lock.ts";
import { isXudtCompatible } from "../sdk/browser/tokens.ts";
import { loadLitAction } from "./lit-actions.ts";
import { signCkbDigest } from "./lit.ts";
import { recoverPkpPublicKey } from "./pkp-identity.ts";
import type { ReadyWallet } from "./user-wallet.ts";

const SHANNONS_PER_CKB = 100_000_000n;
const MAX_FEE = SHANNONS_PER_CKB;
const TESTNET_FUNDING_LOCK_CODE_HASH = "0x6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c";

export type FundingPreview = {
  /** CKB put into the channel: its full size for a CKB channel, or the required reserve for a token channel. */
  amountCkb: string;
  feeCkb: string;
  destination: string;
  transactionHash: string;
  /** For a token channel: the token (by type script hash) and the amount put in, in its smallest unit. */
  token?: { asset: string; amount: string };
};

/** One of the account's lock groups in a transaction, signed with the witness its lock expects. */
export type SigningGroup = { script: ccc.Script; kind: KeyWayLockKind };

type ValidatedFunding = {
  transaction: ccc.Transaction;
  signer: ccc.SignerCkbPublicKey;
  script: ccc.Script;
  /** Every lock group of the account in the transaction, the current lock first. */
  groups: SigningGroup[];
  preview: FundingPreview;
};

export async function previewFundingTransaction(
  wallet: ReadyWallet,
  input: unknown,
  client: ccc.Client = new ccc.ClientPublicTestnet(),
): Promise<ValidatedFunding> {
  if (!input || typeof input !== "object") throw new Error("A complete CKB transaction is required");
  const transaction = ccc.Transaction.from(input as ccc.TransactionLike);
  if (transaction.version !== 0n) throw new Error("Only CKB transaction version 0 is allowed");
  if (transaction.inputs.length === 0 || transaction.inputs.length > 64) throw new Error("Funding input count is invalid");
  if (transaction.outputs.length < 1 || transaction.outputs.length > 64) throw new Error("Funding output count is invalid");
  if (transaction.headerDeps.length !== 0) throw new Error("Funding transactions cannot include header dependencies");

  const signer = new ccc.SignerCkbPublicKey(client, wallet.litPublicKey);
  // The account's address comes from its recovery record, so the record must be one the chain backs.
  if (wallet.recovery) await verifyRecoveryAnchor(client, wallet.litPublicKey, wallet.recovery);
  const locks = await accountLocks(client, wallet.litPublicKey, wallet.recovery);
  const own = locks.map(({ script }) => script);
  const isOwn = (lock: ccc.Script) => own.some((script) => script.eq(lock));
  const inputCells = await Promise.all(transaction.inputs.map((input) => input.getCell(client)));
  refuseAdminListSpend(transaction, inputCells, wallet.recovery);
  const ownedInputs = inputCells.filter(({ cellOutput }) => isOwn(cellOutput.lock));
  if (ownedInputs.length === 0) {
    throw new Error("Funding transaction has no input controlled by this KeyWay wallet");
  }
  refuseForeignOmnilockOutputs(transaction, await client.getKnownScript(ccc.KnownScript.OmniLock), wallet.litPublicKey, wallet.recovery);

  const fundingOutputs = transaction.outputs.filter(({ lock }) => (
    lock.codeHash.toLowerCase() === TESTNET_FUNDING_LOCK_CODE_HASH && lock.hashType === "type"
  ));
  if (fundingOutputs.length !== 1) throw new Error("Funding transaction must contain exactly one channel output");
  const fundingOutput = fundingOutputs[0];
  const token = await checkTokenFunding(client, transaction, inputCells, own, fundingOutput);
  const spend = calculateFundingSpend({
    ownedInputCapacity: sumCapacities(ownedInputs.map(({ cellOutput }) => cellOutput.capacity)),
    ownedChangeCapacity: sumCapacities(transaction.outputs.filter(({ lock }) => isOwn(lock)).map(({ capacity }) => capacity)),
    totalInputCapacity: sumCapacities(inputCells.map(({ cellOutput }) => cellOutput.capacity)),
    totalOutputCapacity: transaction.getOutputsCapacity(),
  });

  const groups = signingGroups(locks, inputCells);
  const related = await signer.getRelatedScripts(transaction);
  // CCC's own groups for this key are its secp256k1 lock and anyone-can-pay locks; only the first is signed.
  const secp = locks.find(({ kind }) => kind === "secp256k1")!.script;
  if (related.some(({ script }) => !script.eq(secp))) {
    throw new Error("Funding transaction has an unexpected signing group");
  }

  return {
    transaction,
    signer,
    script: groups[0].script,
    groups,
    preview: {
      amountCkb: formatCkb(spend.fundingAmount),
      feeCkb: formatCkb(spend.fee),
      destination: `${fundingOutput.lock.codeHash}:${fundingOutput.lock.args}`,
      transactionHash: transaction.hash(),
      ...(token ? { token: { asset: token.asset, amount: token.amount.toString() } } : {}),
    },
  };
}

/**
 * A token channel carries one standard token (xUDT or sUDT) on the channel output. The token may appear only
 * on that output and on the account's own change, so none of it can be sent anywhere else. Plain CKB outputs
 * carry no data. Returns the token put into the channel, or undefined for a CKB channel.
 */
export async function checkTokenFunding(
  client: ccc.Client,
  transaction: ccc.Transaction,
  inputCells: Array<{ cellOutput: ccc.CellOutput; outputData: ccc.Hex }>,
  own: ccc.Script | ccc.Script[],
  fundingOutput: ccc.CellOutput,
): Promise<{ asset: string; amount: bigint } | undefined> {
  const owns = (lock: ccc.Script) => [own].flat().some((script) => script.eq(lock));
  const outputs = transaction.outputs.map((cellOutput, index) => ({ cellOutput, outputData: ccc.hexFrom(transaction.outputsData[index] ?? "0x") }));
  for (const { cellOutput, outputData } of outputs) {
    if (!cellOutput.type && outputData !== "0x") throw new Error("Unexpected funding output data");
  }
  const typed = [...outputs, ...inputCells].filter(({ cellOutput }) => cellOutput.type);
  if (typed.length === 0) return undefined;
  const type = fundingOutput.type;
  if (!type) throw new Error("Only the channel output and your own change may carry a token");
  const [xudt, sudt] = await Promise.all([client.getKnownScript(ccc.KnownScript.XUdt), client.getKnownScript(ccc.KnownScript.SUdt)]);
  const standard = [xudt, sudt].some((known) => known.codeHash === type.codeHash && known.hashType === type.hashType) || isXudtCompatible(type);
  if (!standard) throw new Error("Only standard xUDT or sUDT tokens can fund a channel");
  for (const { cellOutput, outputData } of typed) {
    if (!cellOutput.type!.eq(type)) throw new Error("A channel can hold only one token");
    if ((outputData.length - 2) / 2 < 16) throw new Error("Token cells must hold a 16-byte amount");
  }
  for (const { cellOutput } of outputs.filter(({ cellOutput }) => cellOutput.type)) {
    if (cellOutput !== fundingOutput && !owns(cellOutput.lock)) throw new Error("Only the channel output and your own change may carry a token");
  }
  const tokenAmount = (cells: typeof typed) => cells.reduce((sum, { outputData }) => sum + ccc.numLeFromBytes(ccc.bytesFrom(outputData).slice(0, 16)), 0n);
  const amount = tokenAmount(inputCells.filter((cell) => cell.cellOutput.type && owns(cell.cellOutput.lock)))
    - tokenAmount(outputs.filter((cell) => cell.cellOutput.type && cell.cellOutput !== fundingOutput && owns(cell.cellOutput.lock)));
  if (amount <= 0n) throw new Error("A token channel must take the token from the KeyWay wallet");
  return { asset: type.hash(), amount };
}

export function calculateFundingSpend(capacities: {
  ownedInputCapacity: bigint;
  ownedChangeCapacity: bigint;
  totalInputCapacity: bigint;
  totalOutputCapacity: bigint;
}): { fundingAmount: bigint; fee: bigint } {
  const fee = capacities.totalInputCapacity - capacities.totalOutputCapacity;
  if (fee < 0n || fee > MAX_FEE) throw new Error("Funding transaction fee exceeds the KeyWay limit");

  const ownedDebit = capacities.ownedInputCapacity - capacities.ownedChangeCapacity;
  const fundingAmount = ownedDebit - fee;
  if (fundingAmount <= 0n) throw new Error("Channel funding must spend from the KeyWay wallet");
  return { fundingAmount, fee };
}

export async function signFundingTransaction(
  _user: User,
  wallet: ReadyWallet,
  validated: ValidatedFunding,
): Promise<ccc.Transaction> {
  return signAccountGroups(validated.transaction, validated.groups, validated.signer.client, async (digest) => {
    const signature = await signCkbDigest(digest, wallet.litPkpId, {
      apiKey: requiredEnv("LIT_USAGE_API_KEY"),
      actionCid: requiredEnv("LIT_SIGN_ACTION_CID"),
      actionCode: await loadLitAction("sign-ckb-digest"),
    });
    const recovered = ccc.hexFrom(recoverPkpPublicKey(ccc.bytesFrom(digest), signature));
    if (recovered.toLowerCase() !== wallet.litPublicKey.toLowerCase()) {
      throw new Error("Lit signature does not match the KeyWay wallet");
    }
    return formatCkbSignature(signature);
  }, "Funding transaction has no KeyWay signing group");
}

/** The account's lock groups that have inputs in the transaction, in the order of `locks`. */
export function signingGroups(
  locks: SigningGroup[],
  inputCells: Array<{ cellOutput: ccc.CellOutput }>,
): SigningGroup[] {
  return locks.filter(({ script }) => inputCells.some(({ cellOutput }) => cellOutput.lock.eq(script)));
}

/**
 * Signs each of the account's lock groups over its own digest. The group's first witness lock is reset to
 * zeros at its final length (65 bytes secp256k1, 85 bytes Omnilock) before hashing, then replaced with the
 * signature, bare for secp256k1 or wrapped in OmniLockWitnessLock for Omnilock.
 */
export async function signAccountGroups(
  transaction: ccc.Transaction,
  groups: SigningGroup[],
  client: ccc.Client,
  signDigest: (digest: ccc.Hex) => Promise<ccc.Hex>,
  missingGroup = "Transaction has no KeyWay signing group",
): Promise<ccc.Transaction> {
  if (groups.length === 0) throw new Error(missingGroup);
  for (const { script, kind } of groups) {
    await transaction.prepareSighashAllWitness(script, witnessLockLength(kind), client);
    const info = await transaction.getSignHashInfo(script, client);
    if (!info) throw new Error(missingGroup);
    const signature = await signDigest(info.message);
    const witness = transaction.getWitnessArgsAt(info.position) ?? ccc.WitnessArgs.from({});
    witness.lock = kind === "omnilock" ? omnilockOwnerWitnessLock(signature) : signature;
    transaction.setWitnessArgsAt(info.position, witness);
  }
  return transaction;
}

export function serializeTransaction(transaction: ccc.Transaction): Record<string, unknown> {
  return JSON.parse(ccc.stringify(transaction)) as Record<string, unknown>;
}

export function formatCkbSignature(signature: { r: string; s: string; recoveryParam: 0 | 1 }): ccc.Hex {
  if (!/^0x[0-9a-fA-F]{64}$/.test(signature.r) || !/^0x[0-9a-fA-F]{64}$/.test(signature.s)) {
    throw new Error("Lit returned malformed signature components");
  }
  return ccc.hexFrom(
    `${signature.r}${signature.s.slice(2)}${signature.recoveryParam.toString(16).padStart(2, "0")}`,
  );
}

function formatCkb(shannons: bigint): string {
  const whole = shannons / SHANNONS_PER_CKB;
  const fraction = (shannons % SHANNONS_PER_CKB).toString().padStart(8, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

function sumCapacities(capacities: readonly bigint[]): bigint {
  return capacities.reduce((sum, capacity) => sum + capacity, 0n);
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing server configuration: ${name}`);
  return value;
}

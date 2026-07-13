import * as ccc from "@ckb-ccc/core";
import type { User } from "stytch";
import { loadLitAction } from "./lit-actions.ts";
import { signCkbDigest } from "./lit.ts";
import { recoverPkpPublicKey } from "./pkp-identity.ts";
import type { ReadyWallet } from "./user-wallet.ts";

const SHANNONS_PER_CKB = 100_000_000n;
const MAX_FUNDING = 1_000n * SHANNONS_PER_CKB;
const MAX_FEE = SHANNONS_PER_CKB;
const TESTNET_FUNDING_LOCK_CODE_HASH = "0x6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c";

export type FundingPreview = {
  amountCkb: string;
  feeCkb: string;
  destination: string;
  transactionHash: string;
};

type ValidatedFunding = {
  transaction: ccc.Transaction;
  signer: ccc.SignerCkbPublicKey;
  script: ccc.Script;
  preview: FundingPreview;
};

export async function previewFundingTransaction(wallet: ReadyWallet, input: unknown): Promise<ValidatedFunding> {
  if (!input || typeof input !== "object") throw new Error("A complete CKB transaction is required");
  const transaction = ccc.Transaction.from(input as ccc.TransactionLike);
  if (transaction.version !== 0n) throw new Error("Only CKB transaction version 0 is allowed");
  if (transaction.inputs.length === 0 || transaction.inputs.length > 64) throw new Error("Funding input count is invalid");
  if (transaction.outputs.length < 1 || transaction.outputs.length > 64) throw new Error("Funding output count is invalid");
  if (transaction.headerDeps.length !== 0) throw new Error("Funding transactions cannot include header dependencies");

  const client = new ccc.ClientPublicTestnet();
  const signer = new ccc.SignerCkbPublicKey(client, wallet.litPublicKey);
  const signerScript = (await signer.getRecommendedAddressObj()).script;
  const inputCells = await Promise.all(transaction.inputs.map((input) => input.getCell(client)));
  const ownedInputs = inputCells.filter(({ cellOutput }) => cellOutput.lock.eq(signerScript));
  if (ownedInputs.length === 0) {
    throw new Error("Funding transaction has no input controlled by this KeyWay wallet");
  }

  const fundingOutputs = transaction.outputs.filter(({ lock }) => (
    lock.codeHash.toLowerCase() === TESTNET_FUNDING_LOCK_CODE_HASH && lock.hashType === "type"
  ));
  if (fundingOutputs.length !== 1) throw new Error("Funding transaction must contain exactly one channel output");
  if (transaction.outputs.some((output) => output.type !== undefined)) {
    throw new Error("Only CKB channel funding is allowed");
  }
  if (transaction.outputsData.some((data) => data !== "0x")) {
    throw new Error("Unexpected funding output data");
  }

  const fundingOutput = fundingOutputs[0];
  const spend = calculateFundingSpend({
    ownedInputCapacity: sumCapacities(ownedInputs.map(({ cellOutput }) => cellOutput.capacity)),
    ownedChangeCapacity: sumCapacities(transaction.outputs.filter(({ lock }) => lock.eq(signerScript)).map(({ capacity }) => capacity)),
    totalInputCapacity: sumCapacities(inputCells.map(({ cellOutput }) => cellOutput.capacity)),
    totalOutputCapacity: transaction.getOutputsCapacity(),
  });

  const related = await signer.getRelatedScripts(transaction);
  if (related.length !== 1 || !related[0].script.eq(signerScript)) {
    throw new Error("Funding transaction has an unexpected signing group");
  }

  return {
    transaction,
    signer,
    script: related[0].script,
    preview: {
      amountCkb: formatCkb(spend.fundingAmount),
      feeCkb: formatCkb(spend.fee),
      destination: `${fundingOutput.lock.codeHash}:${fundingOutput.lock.args}`,
      transactionHash: transaction.hash(),
    },
  };
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
  if (fundingAmount <= 0n || fundingAmount > MAX_FUNDING) {
    throw new Error("Channel funding exceeds the KeyWay testnet limit");
  }
  return { fundingAmount, fee };
}

export async function signFundingTransaction(
  _user: User,
  wallet: ReadyWallet,
  validated: ValidatedFunding,
): Promise<ccc.Transaction> {
  const info = await validated.transaction.getSignHashInfo(validated.script, validated.signer.client);
  if (!info) throw new Error("Funding transaction has no KeyWay signing group");

  const signature = await signCkbDigest(info.message, wallet.litPkpId, {
    apiKey: requiredEnv("LIT_USAGE_API_KEY"),
    actionCid: requiredEnv("LIT_SIGN_ACTION_CID"),
    actionCode: await loadLitAction("sign-ckb-digest"),
  });
  const recovered = ccc.hexFrom(recoverPkpPublicKey(ccc.bytesFrom(info.message), signature));
  if (recovered.toLowerCase() !== wallet.litPublicKey.toLowerCase()) {
    throw new Error("Lit signature does not match the KeyWay wallet");
  }

  const witness = validated.transaction.getWitnessArgsAt(info.position) ?? ccc.WitnessArgs.from({});
  witness.lock = formatCkbSignature(signature);
  validated.transaction.setWitnessArgsAt(info.position, witness);
  return validated.transaction;
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

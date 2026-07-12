import * as ccc from "@ckb-ccc/core";
import type { User } from "stytch";
import { loadLitAction } from "./lit-actions.ts";
import { signCkbDigest } from "./lit.ts";
import { recoverPkpPublicKey } from "./pkp-identity.ts";
import type { ReadyWallet } from "./user-wallet.ts";

const SHANNONS_PER_CKB = 100_000_000n;
const MAX_FUNDING = 1_000n * SHANNONS_PER_CKB;
const MAX_FEE = SHANNONS_PER_CKB;

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
  if (inputCells.some(({ cellOutput }) => !cellOutput.lock.eq(signerScript))) {
    throw new Error("Every funding input must be controlled by this KeyWay wallet");
  }

  const externalOutputs = transaction.outputs.filter(({ lock }) => !lock.eq(signerScript));
  if (externalOutputs.length !== 1) throw new Error("Funding transaction must contain exactly one channel output");
  if (transaction.outputs.some((output) => output.type !== undefined)) {
    throw new Error("Only CKB channel funding is allowed");
  }
  if (transaction.outputsData.some((data) => data !== "0x")) {
    throw new Error("Unexpected funding output data");
  }

  const fundingOutput = externalOutputs[0];
  if (fundingOutput.capacity <= 0n || fundingOutput.capacity > MAX_FUNDING) {
    throw new Error("Channel funding exceeds the KeyWay testnet limit");
  }
  const inputCapacity = inputCells.reduce((sum, { cellOutput }) => sum + cellOutput.capacity, 0n);
  const fee = inputCapacity - transaction.getOutputsCapacity();
  if (fee < 0n || fee > MAX_FEE) throw new Error("Funding transaction fee exceeds the KeyWay limit");

  const related = await signer.getRelatedScripts(transaction);
  if (related.length !== 1 || !related[0].script.eq(signerScript)) {
    throw new Error("Funding transaction has an unexpected signing group");
  }

  return {
    transaction,
    signer,
    script: related[0].script,
    preview: {
      amountCkb: formatCkb(fundingOutput.capacity),
      feeCkb: formatCkb(fee),
      destination: `${fundingOutput.lock.codeHash}:${fundingOutput.lock.args}`,
      transactionHash: transaction.hash(),
    },
  };
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

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing server configuration: ${name}`);
  return value;
}

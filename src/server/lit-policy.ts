import * as ccc from "@ckb-ccc/core";
import { omnilockOwnerWitnessLock, witnessLockLength } from "../sdk/browser/account-lock.ts";
import { joyIdLock, joyIdPubkeyHash, normalizeEvmAddress, type RecoveryBackup } from "../sdk/browser/recovery-backups.ts";
import type { SigningGroup } from "./funding-transaction.ts";
import { loadLitAction } from "./lit-actions.ts";
import { LIT_ACTION_CIDS, litSignerMode } from "./lit-config.ts";
import { runLitAction, type LitRuntimeConfig, type LitSignature } from "./lit.ts";
import { recoverPkpPublicKey } from "./pkp-identity.ts";

/**
 * KeyWay's policy signer (`lit-actions/sign-ckb-transaction.js`). Unlike `sign-ckb-digest`, it never signs a
 * digest it is handed: it fetches the transaction's inputs from the chain, computes each sighash itself, enforces
 * the recovery list's rules and checks the code it emailed for every list change. The pinned CID below is the
 * hash of that source (tests/lit-action-packaging.test.ts); the founder registers it in the Lit group.
 */
export const POLICY_ACTION_CID = LIT_ACTION_CIDS["sign-ckb-transaction"];

/** Whether the policy Action signs (`LIT_SIGNER` in lit-config.ts); otherwise the digest signer does. */
export function litPolicyEnabled(): boolean {
  return litSignerMode() === "policy";
}

/**
 * The size of the email binding a transaction turning recovery on carries in witness 0's input_type: "KWEB", a
 * version byte and a 32-byte keyed fingerprint of the account's email. The email itself never goes on chain.
 */
export const EMAIL_BINDING_SIZE = 37;

export type LitEmailCode = { code: string; ticket: string };

async function policyConfig(): Promise<LitRuntimeConfig> {
  const apiKey = process.env.LIT_USAGE_API_KEY;
  if (!apiKey) throw new Error("Missing server configuration: LIT_USAGE_API_KEY");
  return { apiKey, actionCid: POLICY_ACTION_CID, actionCode: await loadLitAction("sign-ckb-transaction") };
}

type WalletKeys = { litPkpId: string; litPublicKey: string };

/** A backup as the policy Action takes it: its kind and 20-byte id, which the Action salts and checks itself. */
export type LitBackupId = { kind: RecoveryBackup["kind"]; id: ccc.Hex };

/**
 * The ids of these backups (the EVM address, or blake160 of the JoyID passkey's public key), without duplicates.
 * The on-chain record holds only salted auths, so the Action is told each backup on the list before and after a
 * change and rebuilds its auth with the account's salt and KeyWay's verifier.
 */
export async function litBackupIds(client: ccc.Client, backups: RecoveryBackup[]): Promise<LitBackupId[]> {
  const ids = await Promise.all(backups.map(async (backup): Promise<LitBackupId> => backup.kind === "evm"
    ? { kind: "evm", id: normalizeEvmAddress(backup.address) }
    : { kind: "joyid", id: ccc.hexFrom(joyIdPubkeyHash(await joyIdLock(client, backup.address))) }));
  return ids.filter((entry, index) => ids.findIndex((other) => other.kind === entry.kind && other.id === entry.id) === index);
}

type Runner = (config: LitRuntimeConfig, params: Record<string, unknown>) => Promise<unknown>;

/** How the policy Action is run; tests replace `run` with the Action under a fake Lit runtime. */
export const litPolicyRunner: { run: Runner } = { run: runLitAction };
const defaultRun: Runner = (config, params) => litPolicyRunner.run(config, params);

function signatureOf(value: unknown): LitSignature {
  const candidate = (value ?? {}) as Partial<LitSignature>;
  if (!/^0x[0-9a-fA-F]{64}$/.test(candidate.r ?? "") || !/^0x[0-9a-fA-F]{64}$/.test(candidate.s ?? "") || (candidate.recoveryParam !== 0 && candidate.recoveryParam !== 1)) {
    throw new Error("Lit Action returned an invalid signature");
  }
  return { r: candidate.r as `0x${string}`, s: candidate.s as `0x${string}`, recoveryParam: candidate.recoveryParam };
}

function formatSignature(signature: LitSignature): ccc.Hex {
  return ccc.hexFrom(`${signature.r}${signature.s.slice(2)}${signature.recoveryParam.toString(16).padStart(2, "0")}`);
}

/** Checks a signature against the digest this server computed itself and the wallet's key, then formats it. */
function checked(digest: ccc.HexLike, signature: LitSignature, publicKey: string): ccc.Hex {
  const recovered = ccc.hexFrom(recoverPkpPublicKey(ccc.bytesFrom(digest), signature));
  if (recovered.toLowerCase() !== publicKey.toLowerCase()) throw new Error("Lit signature does not match the KeyWay wallet");
  return formatSignature(signature);
}

/** The identity signature over KeyWay's fixed identity digest, from which the PKP's public key is recovered. */
export async function policyIdentitySignature(litPkpId: string, run = defaultRun): Promise<LitSignature> {
  return signatureOf(await run(await policyConfig(), { mode: "identity", pkpId: litPkpId }));
}

/** Signs a text message in CKB's "Nervos Message:" format; the Action hashes it itself. */
export async function policySignMessage(wallet: WalletKeys, message: string, run = defaultRun): Promise<ccc.Hex> {
  const signature = signatureOf(await run(await policyConfig(), { mode: "message", pkpId: wallet.litPkpId, message }));
  return checked(ccc.messageHashCkbSecp256k1(message), signature, wallet.litPublicKey);
}

/**
 * Has the policy Action sign every one of the account's lock groups in the transaction at once. Each group's
 * first witness is set to an all-zero lock at its final length first; the Action computes the sighashes from
 * the chain's own input cells, and each signature is checked against the digest computed here before use.
 */
export async function policySignTransaction(
  transaction: ccc.Transaction,
  groups: SigningGroup[],
  client: ccc.Client,
  wallet: WalletKeys,
  options: { enableTransactionHash?: string; email?: string; emailCode?: LitEmailCode; previousListRecord?: ccc.Hex; backups?: RecoveryBackup[] } = {},
  run = defaultRun,
): Promise<ccc.Transaction> {
  if (groups.length === 0) throw new Error("Transaction has no KeyWay signing group");
  for (const { script, kind } of groups) await transaction.prepareSighashAllWitness(script, witnessLockLength(kind), client);
  const expected = await Promise.all(groups.map(async (group) => {
    const info = await transaction.getSignHashInfo(group.script, client);
    if (!info) throw new Error("Transaction has no KeyWay signing group");
    return { ...group, ...info };
  }));
  const response = await run(await policyConfig(), {
    mode: "transaction",
    pkpId: wallet.litPkpId,
    transaction: JSON.parse(ccc.stringify(transaction)),
    ...(options.enableTransactionHash ? { enableTransactionHash: options.enableTransactionHash } : {}),
    ...(options.email ? { email: options.email } : {}),
    ...(options.emailCode ? { emailCode: options.emailCode } : {}),
    ...(options.previousListRecord ? { previousListRecord: options.previousListRecord } : {}),
    ...(options.backups ? { backups: await litBackupIds(client, options.backups) } : {}),
  }) as { transactionHash?: unknown; signatures?: unknown } | undefined;
  if (response?.transactionHash !== transaction.hash()) throw new Error("Lit Action signed a different transaction");
  if (!Array.isArray(response.signatures)) throw new Error("Lit Action returned no signatures");
  const byLock = new Map((response.signatures as Array<Record<string, unknown>>).map((entry) => [String(entry.lockHash).toLowerCase(), entry]));
  for (const { script, kind, message, position } of expected) {
    const entry = byLock.get(script.hash());
    if (!entry || entry.witnessIndex !== position) throw new Error("Lit Action didn't sign one of the account's lock groups");
    const signature = checked(message, signatureOf(entry), wallet.litPublicKey);
    const witness = transaction.getWitnessArgsAt(position) ?? ccc.WitnessArgs.from({});
    witness.lock = kind === "omnilock" ? omnilockOwnerWitnessLock(signature) : signature;
    transaction.setWitnessArgsAt(position, witness);
  }
  return transaction;
}

export type LitCodeSent = { ticket: string; sentTo: string; binding?: ccc.Hex; fingerprint?: ccc.Hex };

/**
 * Has the policy Action email a code for a recovery list change. The Action makes the code and sends it from
 * inside Lit, so this server only gets a ticket back. `email` is the account's address. When turning recovery on,
 * the Action returns the binding the transaction must carry: a keyed fingerprint of that address, not the address.
 * For a later change, the Action sends the code only if the address matches the fingerprint bound on chain.
 */
export async function policySendCode(
  transaction: ccc.Transaction,
  wallet: WalletKeys,
  options: { enableTransactionHash?: string; email?: string; appName: string; backups?: RecoveryBackup[]; client?: ccc.Client },
  run = defaultRun,
): Promise<LitCodeSent> {
  const backups = options.backups ? await litBackupIds(options.client ?? new ccc.ClientPublicTestnet(), options.backups) : undefined;
  // The same Resend key as sign-in email. It must be a sending-only key, so the server can't read the code back.
  const emailApiKey = process.env.RESEND_API_KEY;
  if (!emailApiKey) throw new Error("Missing server configuration: RESEND_API_KEY");
  const response = await run(await policyConfig(), {
    mode: "send-code",
    pkpId: wallet.litPkpId,
    transaction: JSON.parse(ccc.stringify(transaction)),
    emailApiKey,
    appName: options.appName.replace(/[^A-Za-z0-9 .'-]/g, "").slice(0, 40) || "CKB KeyWay",
    ...(options.enableTransactionHash ? { enableTransactionHash: options.enableTransactionHash } : {}),
    ...(options.email ? { email: options.email } : {}),
    ...(backups ? { backups } : {}),
  }) as Record<string, unknown> | undefined;
  if (typeof response?.ticket !== "string" || !/^v2\.\d{13}\.[0-9a-f]{32}\.[0-9a-f]{64}$/.test(response.ticket)) throw new Error("Lit Action returned an invalid code ticket");
  if (response.transactionHash !== transaction.hash()) throw new Error("Lit Action sent a code for a different transaction");
  const binding = response.binding;
  if (binding !== undefined && (typeof binding !== "string" || !/^0x[0-9a-f]*$/.test(binding) || (binding.length - 2) / 2 !== EMAIL_BINDING_SIZE)) {
    throw new Error("Lit Action returned an invalid email binding");
  }
  // Turning send limits on: the keyed fingerprint of the address, which goes into the new cell's data.
  const fingerprint = response.fingerprint;
  if (fingerprint !== undefined && (typeof fingerprint !== "string" || !/^0x[0-9a-f]{64}$/.test(fingerprint))) throw new Error("Lit Action returned an invalid email fingerprint");
  return { ticket: response.ticket, sentTo: String(response.sentTo ?? ""), ...(binding ? { binding: binding as ccc.Hex } : {}), ...(fingerprint ? { fingerprint: fingerprint as ccc.Hex } : {}) };
}

/** Puts an email binding (or, for planning the fee, its zero placeholder) in witness 0's input_type. */
export function setEmailBinding(transaction: ccc.Transaction, binding: ccc.HexLike = new Uint8Array(EMAIL_BINDING_SIZE)): void {
  const bytes = ccc.bytesFrom(binding);
  if (bytes.length !== EMAIL_BINDING_SIZE) throw new Error("The email binding has the wrong size");
  const witness = transaction.getWitnessArgsAt(0) ?? ccc.WitnessArgs.from({});
  witness.inputType = ccc.hexFrom(bytes);
  transaction.setWitnessArgsAt(0, witness);
}

/** A code from the Lit Action: eight digits. */
export function parseLitEmailCode(code: unknown, ticket: unknown): LitEmailCode {
  if (typeof code !== "string" || !/^\d{8}$/.test(code)) throw new Error("Enter the eight-digit code from your email");
  if (typeof ticket !== "string") throw new Error("The email code has expired. Request a new one");
  return { code, ticket };
}

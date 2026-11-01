import * as ccc from "@ckb-ccc/core";
import type { OmnilockDeployment } from "./account-lock";
import type { EthereumProvider } from "./account-recovery";
import { approvalNetworkByte, recoveryApprovalText, rescueApproval } from "./recovery-approval";
import { evmApprovalSignature, EVM_APPROVAL_SIGNATURE_LENGTH, evmPersonalSignAddress, joyIdMainKey, normalizeEvmAddress, omnilockAdminWitnessLock, verifierCellDep } from "./recovery-backups";
import type { RecoveryListEntry } from "./recovery-list";
import { whitelistTree } from "./recovery-smt";
import { MAX_WEBAUTHN_SIGNATURE, parseJoyIdSignature, verifyWebAuthn, webAuthnSignatureBlob, webAuthnSignatureLength } from "./webauthn";

/**
 * Signing an Omnilock administrator-path spend with a backup, without KeyWay: the transaction spends cells of the
 * account's Omnilock `lock`, `list` is the account's backup list (`readRecoveryList`), `entry` the backup that
 * signs. The witness carries the backup's identity and its SMT proof against the list, so the AdminList must be
 * a cell dep (it is added if missing). The backup signs the readable approval (`recoveryApprovalText`), which its
 * verifier rebuilds from the transaction, so the transaction must be a rescue: every output to one address.
 */
export type RecoverySpend = {
  client: ccc.Client;
  lock: ccc.ScriptLike;
  /** The Omnilock the account runs, whose deps are added. */
  omnilock: Pick<OmnilockDeployment, "cellDeps">;
  list: RecoveryListEntry[];
  entry: RecoveryListEntry;
  /** The AdminList cell's out point, added as a cell dep. */
  adminList: ccc.OutPointLike;
  /** The inputs' total capacity, from cells checked against the transactions that created them. */
  inputCapacity: bigint;
};

/** The signature length each kind of backup fills: one passkey prompt always fits Omnilock's 1024 bytes. */
const signatureLength = (entry: RecoveryListEntry) => entry.backup.kind === "evm" ? EVM_APPROVAL_SIGNATURE_LENGTH : MAX_WEBAUTHN_SIGNATURE;

/** The deps and the zeroed admin witness lock at its final length, so the transaction's size and sighash are final. */
export async function prepareRecoveryWitness(transactionLike: ccc.TransactionLike, spend: RecoverySpend): Promise<ccc.Transaction> {
  const transaction = ccc.Transaction.from(transactionLike);
  const { proof, auth, preimage } = entryProof(spend);
  transaction.addCellDeps(spend.omnilock.cellDeps);
  transaction.addCellDeps({ outPoint: spend.adminList, depType: "code" });
  transaction.addCellDeps(verifierCellDep(spend.client, spend.entry.backup.kind));
  const placeholder = omnilockAdminWitnessLock({ signature: new Uint8Array(signatureLength(spend.entry)), auth, proof, preimage });
  await transaction.prepareSighashAllWitness(spend.lock, ccc.bytesFrom(placeholder).length, spend.client);
  return transaction;
}

/**
 * `prepareRecoveryWitness`, then the readable text the backup will sign. What is shown before signing is exactly
 * what the wallet shows and the verifier rebuilds.
 */
export async function prepareRecoverySpend(transactionLike: ccc.TransactionLike, spend: RecoverySpend): Promise<{ transaction: ccc.Transaction; text: string; sighash: ccc.Hex; position: number }> {
  const transaction = await prepareRecoveryWitness(transactionLike, spend);
  const lock = ccc.Script.from(spend.lock);
  const info = await transaction.getSignHashInfo(lock, spend.client);
  if (!info) throw new Error("The transaction spends nothing from this account");
  const text = recoveryApprovalText(spend.client, rescueApproval(transaction, lock, spend.inputCapacity), info.message);
  return { transaction, text, sighash: info.message, position: info.position };
}

/** Signs with an EVM backup: personal_sign of the readable approval, checked against the backup's address. */
export async function signRecoverySpendWithEvm(transaction: ccc.TransactionLike, spend: RecoverySpend, ethereum: EthereumProvider): Promise<ccc.Transaction> {
  if (spend.entry.backup.kind !== "evm") throw new Error("This backup isn't an EVM wallet");
  const address = normalizeEvmAddress(spend.entry.backup.address);
  return signAdmin(transaction, spend, async (text) => {
    const signature = await ethereum.request({ method: "personal_sign", params: [ccc.hexFrom(new TextEncoder().encode(text)), address] });
    if (typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(signature)) throw new Error("The EVM wallet didn't sign");
    if (evmPersonalSignAddress(text, signature) !== address) throw new Error("The EVM wallet signed with another account than the backup on the recovery list");
    return evmApprovalSignature(approvalNetworkByte(spend.client), signature);
  });
}

/**
 * Signs with a JoyID backup through CCC's JoyID signer (`@ckb-ccc/joy-id`): its sign-message page (JoyID's
 * signChallenge) shows the readable approval and the passkey signs it. The assertion is checked locally as the
 * on-chain verifier checks it before it goes in the witness.
 */
export async function signRecoverySpendWithJoyId(transaction: ccc.TransactionLike, spend: RecoverySpend, signer: ccc.Signer): Promise<ccc.Transaction> {
  if (spend.entry.backup.kind !== "joyid") throw new Error("This backup isn't a JoyID passkey");
  if (signer.signType !== ccc.SignerSignType.JoyId) throw new Error("A JoyID backup needs CCC's JoyID signer");
  if (!await signer.isConnected()) await signer.connect();
  const publicKey = joyIdMainKey(await signer.getIdentity());
  if (!publicKey) throw new Error("JoyID didn't share its passkey's public key");
  if (ccc.hexFrom(ccc.hashCkbShort(publicKey)) !== ccc.hexFrom(ccc.bytesFrom(spend.entry.preimage).slice(42))) {
    throw new Error("This JoyID passkey isn't the backup on the recovery list");
  }
  return signAdmin(transaction, spend, async (text) => {
    const assertion = parseJoyIdSignature(await signer.signMessageRaw(text), publicKey);
    if (!verifyWebAuthn(assertion, text)) throw new Error("JoyID's signature doesn't verify");
    if (webAuthnSignatureLength(assertion) > MAX_WEBAUTHN_SIGNATURE) throw new Error("JoyID's signature is longer than Omnilock accepts");
    return ccc.hexFrom(webAuthnSignatureBlob(assertion, MAX_WEBAUTHN_SIGNATURE, approvalNetworkByte(spend.client)));
  });
}

function entryProof(spend: RecoverySpend) {
  const { proofs } = whitelistTree(spend.list.map(({ auth }) => auth));
  const proof = proofs[spend.entry.auth];
  if (!proof) throw new Error("This backup isn't on the recovery list");
  return { proof, auth: spend.entry.auth, preimage: spend.entry.preimage };
}

/** Prepares the spend, has the backup sign its readable approval and writes the admin witness lock. */
async function signAdmin(transactionLike: ccc.TransactionLike, spend: RecoverySpend, sign: (text: string) => Promise<ccc.Hex>): Promise<ccc.Transaction> {
  const { transaction, text, position } = await prepareRecoverySpend(transactionLike, spend);
  const signature = await sign(text);
  if (ccc.bytesFrom(signature).length !== signatureLength(spend.entry)) throw new Error("The signature has the wrong length");
  const { proof, auth, preimage } = entryProof(spend);
  const witness = transaction.getWitnessArgsAt(position) ?? ccc.WitnessArgs.from({});
  witness.lock = omnilockAdminWitnessLock({ signature, auth, proof, preimage });
  transaction.setWitnessArgsAt(position, witness);
  return transaction;
}

import * as ccc from "@ckb-ccc/core";
import type { EthereumProvider } from "./account-recovery";
import { evmOmnilockMessage, evmOmnilockSignature, joyIdMainKey, joyIdOmnilockMessage, joyIdVerifierCellDep, omnilockAdminWitnessLock } from "./recovery-backups";
import type { RecoveryListEntry } from "./recovery-list";
import { whitelistTree } from "./recovery-smt";
import { MAX_WEBAUTHN_SIGNATURE, parseJoyIdSignature, verifyWebAuthn, webAuthnSignatureBlob, webAuthnSignatureLength } from "./webauthn";

/**
 * Signing an Omnilock administrator-path spend with a backup, without KeyWay: the transaction spends cells of the
 * account's Omnilock `lock`, `list` is the account's backup list (`readRecoveryList`), `entry` the backup that
 * signs. The witness carries the backup's identity and its SMT proof against the list, so the AdminList must be
 * a cell dep (it is added if missing).
 */
export type RecoverySpend = {
  client: ccc.Client;
  lock: ccc.ScriptLike;
  list: RecoveryListEntry[];
  entry: RecoveryListEntry;
  /** The AdminList cell's out point, added as a cell dep. */
  adminList: ccc.OutPointLike;
};

/** A passkey signature slot that fits JoyID's assertions with room to spare; 1024 is Omnilock's limit. */
export const JOYID_SIGNATURE_SLOT = 768;
const EVM_SIGNATURE_LENGTH = 65;

/** Signs with an EVM backup: personal_sign of "CKB transaction: 0x<sighash>" (Omnilock flag 0x12). */
export async function signRecoverySpendWithEvm(transaction: ccc.TransactionLike, spend: RecoverySpend, ethereum: EthereumProvider): Promise<ccc.Transaction> {
  if (spend.entry.backup.kind !== "evm") throw new Error("This backup isn't an EVM wallet");
  const address = spend.entry.backup.address;
  return signAdmin(transaction, spend, EVM_SIGNATURE_LENGTH, async (sighash) => {
    const message = ccc.hexFrom(new TextEncoder().encode(evmOmnilockMessage(sighash)));
    const signature = await ethereum.request({ method: "personal_sign", params: [message, address] });
    if (typeof signature !== "string") throw new Error("The EVM wallet didn't sign");
    return evmOmnilockSignature(signature);
  });
}

/**
 * Signs with a JoyID backup through CCC's JoyID signer (`@ckb-ccc/joy-id`): its sign-message page (JoyID's
 * signChallenge) shows "CKB transaction: 0x<sighash>" and the passkey signs it. The assertion is checked
 * locally as the on-chain verifier checks it before it goes in the witness. If it is longer than the reserved
 * slot, the transaction is signed again with the 1024-byte maximum.
 */
export async function signRecoverySpendWithJoyId(transaction: ccc.TransactionLike, spend: RecoverySpend, signer: ccc.Signer): Promise<ccc.Transaction> {
  if (spend.entry.backup.kind !== "joyid" || !spend.entry.preimage) throw new Error("This backup isn't a JoyID passkey");
  if (signer.signType !== ccc.SignerSignType.JoyId) throw new Error("A JoyID backup needs CCC's JoyID signer");
  if (!await signer.isConnected()) await signer.connect();
  const publicKey = joyIdMainKey(await signer.getIdentity());
  if (!publicKey) throw new Error("JoyID didn't share its passkey's public key");
  if (ccc.hexFrom(ccc.hashCkbShort(publicKey)) !== ccc.hexFrom(ccc.bytesFrom(spend.entry.preimage).slice(42))) {
    throw new Error("This JoyID passkey isn't the backup on the recovery list");
  }
  for (const slot of [JOYID_SIGNATURE_SLOT, MAX_WEBAUTHN_SIGNATURE]) {
    let tooLong = false;
    const signed = await signAdmin(transaction, spend, slot, async (sighash) => {
      const message = joyIdOmnilockMessage(sighash);
      const assertion = parseJoyIdSignature(await signer.signMessageRaw(message), publicKey);
      if (!verifyWebAuthn(assertion, message)) throw new Error("JoyID's signature doesn't verify");
      if (webAuthnSignatureLength(assertion) > slot) {
        tooLong = true;
        return ccc.hexFrom(new Uint8Array(slot));
      }
      return ccc.hexFrom(webAuthnSignatureBlob(assertion, slot));
    });
    if (!tooLong) return signed;
  }
  throw new Error("JoyID's signature is longer than Omnilock accepts");
}

/**
 * Writes the admin witness lock zeroed at its final length, takes the sighash, signs it and writes the lock with
 * the signature. The proof comes from the whole list, and the AdminList and the verifier are cell deps.
 */
async function signAdmin(
  transactionLike: ccc.TransactionLike,
  spend: RecoverySpend,
  signatureLength: number,
  sign: (sighash: ccc.Hex) => Promise<ccc.Hex>,
): Promise<ccc.Transaction> {
  const transaction = ccc.Transaction.from(transactionLike);
  const lock = ccc.Script.from(spend.lock);
  const { proofs } = whitelistTree(spend.list.map(({ auth }) => auth));
  const proof = proofs[spend.entry.auth];
  if (!proof) throw new Error("This backup isn't on the recovery list");
  const { auth, preimage } = spend.entry;
  await transaction.addCellDepsOfKnownScripts(spend.client, ccc.KnownScript.OmniLock);
  transaction.addCellDeps({ outPoint: spend.adminList, depType: "code" });
  if (preimage) transaction.addCellDeps(joyIdVerifierCellDep(spend.client));
  const placeholder = omnilockAdminWitnessLock({ signature: new Uint8Array(signatureLength), auth, proof, preimage });
  await transaction.prepareSighashAllWitness(lock, ccc.bytesFrom(placeholder).length, spend.client);
  const info = await transaction.getSignHashInfo(lock, spend.client);
  if (!info) throw new Error("The transaction spends nothing from this account");
  const signature = await sign(info.message);
  if (ccc.bytesFrom(signature).length !== signatureLength) throw new Error("The signature has the wrong length");
  const witness = transaction.getWitnessArgsAt(info.position) ?? ccc.WitnessArgs.from({});
  witness.lock = omnilockAdminWitnessLock({ signature, auth, proof, preimage });
  transaction.setWitnessArgsAt(info.position, witness);
  return transaction;
}

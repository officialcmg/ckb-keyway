import * as ccc from "@ckb-ccc/core";
import type { KeyWayRecovery } from "./account-lock";
import { KeyWayApiClient } from "./api-client";
import { withEmailCode, type RequestEmailCode } from "./email-code";
import { parseBackup, recoveryBackupChallenge, type RecoveryBackup, type RecoveryBackupProof } from "./recovery-backups";

/** What turning recovery on does, as the backend computed it. */
export type RecoveryPreview = {
  network: "CKB testnet";
  /** The account's new address. */
  newAddress: string;
  /** Its address until now, which stays the account's too. */
  legacyAddress: string;
  backups: Array<RecoveryBackup & { label: string }>;
  /** CKB held by the cell that lists the backups. */
  adminListCkb: string;
  /** The smallest plain cell at the new address. */
  minimumCellCkb: string;
  /** Extra capacity token cells need at the new address. */
  tokenCellsExtraCkb: string;
  /** CKB that stops being spendable: the recovery list plus the token cells' extra capacity. */
  lockedCkb: string;
  feeCkb: string;
  /** Plain CKB that arrives at the new address. */
  movedCkb: string;
  tokens: Array<{ asset: string; amount: string; amountText: string }>;
  /** Cells that can't be moved and stay at the old address. */
  cellsLeft: number;
  transactionHash: string;
};

/** Your own confirmation for turning recovery on. Return false to cancel. The emailed code follows. */
export type ApproveRecovery = (preview: RecoveryPreview) => boolean | Promise<boolean>;

export type RecoveryEnabled = { transactionHash: string; ckbAddress: string; recovery: KeyWayRecovery };

/** An injected EIP-1193 wallet, such as `window.ethereum`. */
export type EthereumProvider = { request: (args: { method: string; params?: unknown[] }) => Promise<unknown> };

/** The account's secp256k1 address, which every backup signs for. */
export async function recoveryAccountAddress(publicKey: string, client: ccc.Client = new ccc.ClientPublicTestnet()): Promise<string> {
  const lock = await ccc.Script.fromKnownScript(client, ccc.KnownScript.Secp256k1Blake160, ccc.hashCkbShort(publicKey));
  return ccc.Address.fromScript(lock, client).toString();
}

/** Asks an injected EVM wallet for its address and a personal_sign of the recovery challenge. */
export async function createEvmBackup(account: string, ethereum?: EthereumProvider): Promise<RecoveryBackupProof> {
  const provider = ethereum ?? (globalThis as { ethereum?: EthereumProvider }).ethereum;
  if (!provider) throw new Error("No EVM wallet found in this browser");
  const [address] = await provider.request({ method: "eth_requestAccounts" }) as string[];
  if (typeof address !== "string") throw new Error("The EVM wallet didn't share an address");
  const backup = { kind: "evm" as const, address: address.toLowerCase() };
  const message = ccc.hexFrom(new TextEncoder().encode(recoveryBackupChallenge(account, backup)));
  const signature = await provider.request({ method: "personal_sign", params: [message, address] });
  if (typeof signature !== "string") throw new Error("The EVM wallet didn't sign");
  return { ...backup, signature };
}

/** Asks a CCC JoyID signer (from @ckb-ccc/joy-id) to sign the recovery challenge with its passkey. */
export async function createJoyIdBackup(account: string, signer: ccc.Signer): Promise<RecoveryBackupProof> {
  if (!await signer.isConnected()) await signer.connect();
  if (signer.signType !== ccc.SignerSignType.JoyId) throw new Error("A JoyID backup needs CCC's JoyID signer");
  const address = await signer.getRecommendedAddress();
  const signed = await signer.signMessage(recoveryBackupChallenge(account, { kind: "joyid", address }));
  return { kind: "joyid", address, signature: signed.signature, identity: signed.identity };
}

/** Preview, the user's approval, then the emailed code, which turning recovery on always needs. */
export async function enableRecovery(options: {
  authToken: string;
  backups: RecoveryBackupProof[];
  approve: ApproveRecovery;
  requestEmailCode: RequestEmailCode;
  api?: KeyWayApiClient;
}): Promise<RecoveryEnabled> {
  const api = options.api ?? new KeyWayApiClient();
  const base = { backups: options.backups };
  const { preview, confirmationNonce } = await api.recovery(options.authToken, { ...base, operation: "preview" }) as { preview: RecoveryPreview; confirmationNonce: string };
  if (!await options.approve(preview)) throw new Error("Turning on recovery was cancelled");
  return withEmailCode(
    options.requestEmailCode,
    "recovery",
    () => api.recovery(options.authToken, { ...base, operation: "request-email-code", confirmationNonce }).then(() => undefined),
    (emailCode) => api.recovery(options.authToken, { ...base, operation: "enable", confirmationNonce, emailCode }) as Promise<RecoveryEnabled>,
  );
}

/** What adding or removing a backup does, as the backend computed it. */
export type BackupChangePreview = {
  network: "CKB testnet";
  change: "add" | "remove";
  backup: RecoveryBackup & { label: string };
  /** The backups after the change. */
  backups: Array<RecoveryBackup & { label: string }>;
  feeCkb: string;
  transactionHash: string;
};

/** Your own confirmation for adding or removing a backup. Return false to cancel. The emailed code follows. */
export type ApproveBackupChange = (preview: BackupChangePreview) => boolean | Promise<boolean>;

export type BackupChanged = { transactionHash: string; recovery: KeyWayRecovery };

/**
 * Adds a backup (with its signature over the recovery challenge, from `createEvmBackup` or
 * `createJoyIdBackup`) or removes one: preview, the user's approval, then the emailed code, which a backup
 * change always needs. The address doesn't change.
 */
export async function changeRecoveryBackup(options: {
  authToken: string;
  change: "add" | "remove";
  backup: RecoveryBackupProof | RecoveryBackup;
  approve: ApproveBackupChange;
  requestEmailCode: RequestEmailCode;
  api?: KeyWayApiClient;
}): Promise<BackupChanged> {
  const api = options.api ?? new KeyWayApiClient();
  const backup = options.change === "add" ? options.backup : parseBackup(options.backup);
  const base = { change: options.change, backup };
  const { preview, confirmationNonce } = await api.recoveryBackups(options.authToken, { ...base, operation: "preview" }) as { preview: BackupChangePreview; confirmationNonce: string };
  if (!await options.approve(preview)) throw new Error(options.change === "add" ? "Adding the backup was cancelled" : "Removing the backup was cancelled");
  return withEmailCode(
    options.requestEmailCode,
    "recovery-backup",
    () => api.recoveryBackups(options.authToken, { ...base, operation: "request-email-code", confirmationNonce }).then(() => undefined),
    (emailCode) => api.recoveryBackups(options.authToken, { ...base, operation: "apply", confirmationNonce, emailCode }) as Promise<BackupChanged>,
  );
}

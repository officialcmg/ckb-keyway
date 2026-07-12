import { sha256 } from "@noble/hashes/sha2.js";
import type { User } from "stytch";
import { updateTrustedMetadata } from "./stytch.ts";

const METADATA_KEY = "keywaySigningConfirmation";
const TTL_MS = 5 * 60_000;

type Confirmation = { nonce: string; transactionDigest: string; expiresAt: string };

export async function issueConfirmation(user: User, serializedTransaction: string): Promise<string> {
  const confirmation: Confirmation = {
    nonce: crypto.randomUUID(),
    transactionDigest: digest(serializedTransaction),
    expiresAt: new Date(Date.now() + TTL_MS).toISOString(),
  };
  await updateTrustedMetadata(user.user_id, {
    ...(user.trusted_metadata ?? {}),
    [METADATA_KEY]: confirmation,
  });
  return confirmation.nonce;
}

export function verifyConfirmation(user: User, nonce: string, serializedTransaction: string): void {
  const value = user.trusted_metadata?.[METADATA_KEY];
  if (!value || typeof value !== "object") throw new Error("Transaction confirmation is required");
  const confirmation = value as Partial<Confirmation>;
  if (
    confirmation.nonce !== nonce ||
    confirmation.transactionDigest !== digest(serializedTransaction) ||
    typeof confirmation.expiresAt !== "string" ||
    Date.parse(confirmation.expiresAt) <= Date.now()
  ) throw new Error("Transaction confirmation is invalid or expired");
}

export async function consumeConfirmation(user: User): Promise<void> {
  const metadata = { ...(user.trusted_metadata ?? {}) };
  delete metadata[METADATA_KEY];
  await updateTrustedMetadata(user.user_id, metadata);
}

function digest(value: string): string {
  return Buffer.from(sha256(new TextEncoder().encode(value))).toString("hex");
}

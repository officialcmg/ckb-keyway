import * as ccc from "@ckb-ccc/core";

type FiberScript = { code_hash: string; hash_type: string; args: string };

/** What the app asked Fiber to open: its funding_amount (CKB, or the token for a token channel). */
export type FundingRequest = {
  fundingAmount: bigint;
  udtTypeScript?: FiberScript | null;
  /** The account's shutdown script, which sets the CKB a token channel reserves. */
  shutdownScript?: FiberScript | null;
};

const CKB = 100_000_000n;
/** Fiber's DEFAULT_MIN_SHUTDOWN_FEE (fiber-lib v0.9.1 fiber/config.rs). */
const MIN_SHUTDOWN_FEE = CKB;

/**
 * The CKB Fiber reserves on one side of a token channel, as fiber-lib v0.9.1 `reserved_capacity` works it out: the
 * occupied capacity of a cell under the shutdown lock (at least 57 bytes of args) with the token's type and 16 bytes
 * of data, plus the minimum shutdown fee.
 */
export function tokenChannelReservedCkb(udtTypeScript: FiberScript, shutdownScript?: FiberScript | null): bigint {
  const lockArgs = Math.max(57, shutdownScript ? ccc.bytesFrom(shutdownScript.args).length : 0);
  const bytes = 8 + (32 + 1 + lockArgs) + (32 + 1 + ccc.bytesFrom(udtTypeScript.args).length) + 16;
  return BigInt(bytes) * CKB + MIN_SHUTDOWN_FEE;
}

/**
 * Refuses a funding whose share from the account is more than the app asked for, before it is shown for approval.
 * Fiber puts exactly funding_amount of CKB into a CKB channel; a token channel takes funding_amount of the token
 * and its CKB reserve. The network fee is shown apart and is not part of the amount; the fee reserve is a separate
 * transaction sent after the channel opens.
 */
export function refuseFundingBeyondRequest(preview: { amountCkb: string; token?: { amount: string } }, request: FundingRequest | undefined): void {
  if (!request) throw new Error("This channel funding wasn't requested through KeyWay");
  const amount = ccc.fixedPointFrom(preview.amountCkb);
  if (!request.udtTypeScript) {
    if (preview.token || amount > request.fundingAmount) throw new Error("The channel funding takes more from the account than was requested");
    return;
  }
  if (!preview.token || BigInt(preview.token.amount) > request.fundingAmount) {
    throw new Error("The channel funding takes more of the token than was requested");
  }
  if (amount > tokenChannelReservedCkb(request.udtTypeScript, request.shutdownScript)) {
    throw new Error("The channel funding takes more CKB than a token channel reserves");
  }
}

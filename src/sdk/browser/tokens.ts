import * as ccc from "@ckb-ccc/core";

/** Tokens KeyWay can name, by type script hash. Others show as a short hash with their raw amount. */
export const KNOWN_TOKENS: Record<string, { symbol: string; decimals: number }> = {
  // Stable++ RUSD on CKB testnet, the token Fiber's testnet nodes accept.
  "0x45b32a2bc4285d0a09678eb11960ddc8707bc2779887a09d482e9bfe9a2cdf52": { symbol: "RUSD", decimals: 8 },
};

/** A token's ID: the hash of its type script, given in Fiber's RPC shape or as molecule bytes from an invoice. */
export function tokenAsset(script: { code_hash: string; hash_type: string; args: string } | string): string {
  if (typeof script === "string") return ccc.hashCkb(script);
  return ccc.Script.from({ codeHash: script.code_hash, hashType: script.hash_type as ccc.HashType, args: script.args }).hash();
}

/** "1.5 CKB", "20 RUSD", or the raw amount of an unknown token with its short ID. */
export function formatAsset(amount: bigint, asset: "ckb" | string): string {
  if (asset === "ckb") return `${decimal(amount, 8)} CKB`;
  const known = KNOWN_TOKENS[asset.toLowerCase()];
  return known ? `${decimal(amount, known.decimals)} ${known.symbol}` : `${amount} of token ${asset.slice(0, 10)}…${asset.slice(-6)}`;
}

function decimal(amount: bigint, decimals: number): string {
  const unit = 10n ** BigInt(decimals);
  const fraction = (amount % unit).toString().padStart(decimals, "0").replace(/0+$/, "");
  return fraction ? `${amount / unit}.${fraction}` : (amount / unit).toString();
}

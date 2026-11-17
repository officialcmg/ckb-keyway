import * as ccc from "@ckb-ccc/core";

/** Tokens KeyWay can name, by type script hash. Others show as a short hash with their raw amount. */
export const KNOWN_TOKENS: Record<string, { symbol: string; decimals: number }> = {
  // Stable++ RUSD on CKB testnet, the token Fiber's testnet nodes accept.
  "0x45b32a2bc4285d0a09678eb11960ddc8707bc2779887a09d482e9bfe9a2cdf52": { symbol: "RUSD", decimals: 8 },
};

/**
 * Token contracts that behave like xUDT but aren't CCC's standard deployment, by code hash. Stable++
 * deployed its own copy for RUSD, the token Fiber's testnet nodes accept.
 */
export const XUDT_COMPATIBLE: ReadonlyArray<{ codeHash: string; hashType: "type" | "data" | "data1" | "data2" }> = [
  { codeHash: "0x1142755a044bf2ee358cba9f2da187ce928c91cd4dc8692ded0337efa677d21a", hashType: "type" },
];

export function isXudtCompatible(script: { codeHash: string; hashType: string }): boolean {
  return XUDT_COMPATIBLE.some((known) => known.codeHash === script.codeHash.toLowerCase() && known.hashType === script.hashType);
}

/**
 * The xUDT binary itself, referenced by its data hash (hash_type "data1"), as RGB++ and mainnet tokens do. It is
 * read as a token, but kept out of XUDT_COMPATIBLE, whose entries also pick the RUSD contract as the cell dep.
 */
export const XUDT_DATA1_HASH = "0x50bd8d6680b8b9cf98b73f3c08faf8b2a21914311954118ad6609be6e78a1b95";

export function isXudtByDataHash(script: { codeHash: string; hashType: string }): boolean {
  return script.hashType === "data1" && script.codeHash.toLowerCase() === XUDT_DATA1_HASH;
}

/**
 * Whether a token cell's xUDT args are just the owner's lock hash (optionally with zero flags). Args that carry
 * flags name extension scripts or need witness data to move, which KeyWay's sweeps and the rescue page can't
 * supply, so those cells are left where they are rather than block everything else.
 */
export function hasPlainTokenArgs(type: { args: string }): boolean {
  const args = ccc.bytesFrom(type.args);
  return args.length === 32 || (args.length === 36 && args.slice(32).every((byte) => byte === 0));
}

/** A token's ID: the hash of its type script, given in Fiber's RPC shape or as molecule bytes from an invoice. */
export function tokenAsset(script: { code_hash: string; hash_type: string; args: string } | string): string {
  if (typeof script === "string") return ccc.hashCkb(script);
  return ccc.Script.from({ codeHash: script.code_hash, hashType: script.hash_type as ccc.HashType, args: script.args }).hash();
}

/**
 * "1.5 CKB", "20 RUSD", or the raw amount of an unknown token with its whole ID (type script hash): a shortened
 * one could be ground to match another token's.
 */
export function formatAsset(amount: bigint, asset: "ckb" | string): string {
  if (asset === "ckb") return `${decimal(amount, 8)} CKB`;
  const known = KNOWN_TOKENS[asset.toLowerCase()];
  return known ? `${decimal(amount, known.decimals)} ${known.symbol}` : `${amount} of token ${asset}`;
}

function decimal(amount: bigint, decimals: number): string {
  const unit = 10n ** BigInt(decimals);
  const fraction = (amount % unit).toString().padStart(decimals, "0").replace(/0+$/, "");
  return fraction ? `${amount / unit}.${fraction}` : (amount / unit).toString();
}

export function normalizeFiberPubkey(value: string): `0x${string}` {
  const bare = value.startsWith("0x") ? value.slice(2) : value;
  if (!/^(02|03)[0-9a-fA-F]{64}$/.test(bare)) throw new Error("Fiber returned an invalid peer identity");
  return `0x${bare}`;
}

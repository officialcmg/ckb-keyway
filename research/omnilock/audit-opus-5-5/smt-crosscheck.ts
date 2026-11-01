// Cross-checks src/sdk/browser/recovery-smt.ts against the Rust sparse-merkle-tree 0.6.1 crate (smt-crosscheck/,
// the spike's reference helper) on random whitelists of 1 to 8 backups (the most KeyWay allows), including auths
// that share long prefixes. The rescue rebuilds every proof with the TypeScript port, so a mismatch would strand
// a backup. Run: (cd smt-crosscheck && cargo build --release) && npx tsx smt-crosscheck.ts
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as ccc from "@ckb-ccc/core";
import { smtKeyOfAuth, smtProofRoot, whitelistTree } from "../../../src/sdk/browser/recovery-smt.ts";

const bin = join(dirname(fileURLToPath(import.meta.url)), "smt-crosscheck/target/release/smt-ref");
const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));
let checked = 0;
for (let round = 0; round < 400; round++) {
  const count = 1 + (round % 8);
  const base = random(20);
  const auths = new Set<string>();
  while (auths.size < count) {
    const id = round % 3 === 0 ? base.slice() : random(20);
    // Every third round: ids that differ from each other in one late byte only, so the tree forks deep.
    if (round % 3 === 0) id[19 - (auths.size % 3)] ^= 1 + auths.size;
    auths.add(ccc.hexFrom(ccc.bytesConcat([auths.size % 2 ? 0x12 : 0xfd], id)));
  }
  const list = [...auths];
  const ours = whitelistTree(list);
  const theirs = JSON.parse(execFileSync(bin, list.map(smtKeyOfAuth), { encoding: "utf8" })) as { root: string; proofs: Record<string, string> };
  if (ours.root !== theirs.root) throw new Error(`root mismatch for ${list.join(",")}`);
  for (const auth of list) {
    const key = smtKeyOfAuth(auth);
    if (ours.proofs[auth] !== theirs.proofs[key]) throw new Error(`proof mismatch for ${auth} in ${list.join(",")}`);
    if (smtProofRoot(ours.proofs[auth], [{ key }]) !== ours.root) throw new Error("proof doesn't verify");
    checked++;
  }
}
console.log(`400 random whitelists, ${checked} proofs: roots and compiled proofs identical to sparse-merkle-tree 0.6.1`);
process.exit(0);

// Deploys contracts/build/evm-personal-sign and contracts/build/joyid-webauthn (version 3: identities salted with
// the account's AdminList type hash) as code cells referenced by data hash (data1), under a lock nobody can
// unlock. Records them in state.json: npx tsx deploy-verifiers.ts evm-personal-sign joyid-webauthn
import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as ccc from "@ckb-ccc/core";
import { deployCodeCell, FUNDERS, HERE, loadState, saveState } from "./lib.ts";

const funders: Record<string, string[]> = { "evm-personal-sign": FUNDERS.slice(0, 10), "joyid-webauthn": [...FUNDERS.slice(10, 14), FUNDERS[15]] };
for (const name of process.argv.slice(2)) {
  if (loadState()[name]) { console.log(name, "already deployed"); continue; }
  const binary = readFileSync(join(HERE, "../../contracts/build", name));
  const { txHash, capacity } = await deployCodeCell(binary, funders[name]);
  saveState({ [name]: { outPoint: { txHash, index: 0 }, codeHash: ccc.hashCkb(binary), hashType: "data1", size: binary.length, capacity: ccc.fixedPointToString(capacity) } });
  console.log(name, "committed; code hash", ccc.hashCkb(binary));
}
process.exit(0);

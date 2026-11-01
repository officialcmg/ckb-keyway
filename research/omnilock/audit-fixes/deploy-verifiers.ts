// Deploys contracts/build/evm-personal-sign and contracts/build/joyid-webauthn (version 2, readable approvals)
// as code cells referenced by data hash (data1), under a lock nobody can unlock. Records them in state.json.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as ccc from "@ckb-ccc/core";
import { deployCodeCell, FUNDERS, HERE, loadState, saveState } from "./lib.ts";

const names = process.argv.slice(2);
const funders = { "evm-personal-sign": FUNDERS.slice(17, 28), "joyid-webauthn": FUNDERS.slice(28) } as Record<string, string[]>;
for (const name of names) {
  if (loadState()[name]) { console.log(name, "already deployed"); continue; }
  const binary = readFileSync(join(HERE, "../../../contracts/build", name));
  const { txHash, capacity } = await deployCodeCell(binary, funders[name]);
  saveState({ [name]: { outPoint: { txHash, index: 0 }, codeHash: ccc.hashCkb(binary), hashType: "data1", size: binary.length, capacity: ccc.fixedPointToString(capacity) } });
  console.log(name, "committed; code hash", ccc.hashCkb(binary));
}
process.exit(0);

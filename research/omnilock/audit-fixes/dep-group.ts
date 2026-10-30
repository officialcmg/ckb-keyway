// Lists what the official testnet Omnilock dep group holds.
import * as ccc from "@ckb-ccc/core";
import { client } from "./lib.ts";
const info = await client.getKnownScript(ccc.KnownScript.OmniLock);
for (const { cellDep } of info.cellDeps) {
  if (cellDep.depType !== "depGroup") continue;
  const tx = await client.getTransaction(cellDep.outPoint.txHash);
  const data = ccc.bytesFrom(tx!.transaction.outputsData[Number(cellDep.outPoint.index)]);
  for (let at = 4; at < data.length; at += 36) {
    const txHash = ccc.hexFrom(data.slice(at, at + 32));
    const index = ccc.numLeFromBytes(data.slice(at + 32, at + 36));
    const cell = await client.getTransaction(txHash);
    const bytes = ccc.bytesFrom(cell!.transaction.outputsData[Number(index)]);
    console.log("member", txHash, index.toString(), "size", bytes.length, "data hash", ccc.hashCkb(bytes));
  }
}
const secp = await client.getKnownScript(ccc.KnownScript.Secp256k1Blake160);
console.log("secp256k1 deps", JSON.stringify(secp.cellDeps.map(({ cellDep }) => cellDep), (k, v) => typeof v === "bigint" ? v.toString() : v));
process.exit(0);

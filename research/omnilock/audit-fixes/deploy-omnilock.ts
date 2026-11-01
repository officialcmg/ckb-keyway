// Deploys KeyWay's own copy of the testnet Omnilock binary, byte for byte, so KeyWay accounts reference Omnilock
// by data hash (data1) and the code can't change under them. Reads the bytes from the official cell, checks their
// hash, deploys them under a lock nobody can unlock and records the out point in state.json.
import * as ccc from "@ckb-ccc/core";
import { client, deployCodeCell, FUNDERS, saveState } from "./lib.ts";

const official = (await client.getKnownScript(ccc.KnownScript.OmniLock)).cellDeps.find(({ cellDep }) => cellDep.depType === "code")!.cellDep.outPoint;
const created = await client.getTransaction(official.txHash);
const data = ccc.bytesFrom(created!.transaction.outputsData[Number(official.index)]);
const dataHash = ccc.hashCkb(data);
console.log("official cell", official.txHash, Number(official.index), "size", data.length, "data hash", dataHash);
if (dataHash !== "0x6b29b6f10346b43c540e53806ba88ba0fe3a0c3a29d7448ef555840c8f8318fa") throw new Error("unexpected Omnilock bytes");
const { txHash, capacity } = await deployCodeCell(data, FUNDERS.slice(0, 17));
saveState({ omnilock: { outPoint: { txHash, index: 0 }, codeHash: dataHash, hashType: "data1", size: data.length, capacity: ccc.fixedPointToString(capacity) } });
console.log("committed; Omnilock data hash", dataHash);
process.exit(0);

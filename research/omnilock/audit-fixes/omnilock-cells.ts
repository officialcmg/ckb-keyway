import * as ccc from "@ckb-ccc/core";
for (const client of [new ccc.ClientPublicTestnet(), new ccc.ClientPublicMainnet()]) {
  const info = await client.getKnownScript(ccc.KnownScript.OmniLock);
  console.log(client.addressPrefix, JSON.stringify(info, (k, v) => typeof v === "bigint" ? v.toString() : v));
  for (const dep of info.cellDeps) {
    const op = dep.cellDep.outPoint;
    const tx = await client.getTransaction(op.txHash);
    const out = tx!.transaction.outputs[Number(op.index)];
    const data = tx!.transaction.outputsData[Number(op.index)];
    const live = await client.getCellLive(op, false);
    console.log(" dep", op.txHash, op.index, "depType", dep.cellDep.depType, "size", ccc.bytesFrom(data).length, "capacity", ccc.fixedPointToString(out.capacity), "lock", JSON.stringify(out.lock), "type", out.type?.hash(), "dataHash", ccc.hashCkb(data), "live", !!live);
  }
}

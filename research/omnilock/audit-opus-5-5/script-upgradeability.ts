// Who can upgrade the third-party scripts a recovery account depends on: for each known script CCC uses, the
// code cell CCC puts in cell deps (the one carrying a Type ID), whether it is live, and its lock. A Type ID cell
// under a lock someone holds can be replaced with any code, which then runs for every cell using that type hash.
import * as ccc from "@ckb-ccc/core";

for (const [label, client] of [["testnet", new ccc.ClientPublicTestnet()], ["mainnet", new ccc.ClientPublicMainnet()]] as const) {
  for (const name of [ccc.KnownScript.OmniLock, ccc.KnownScript.JoyId, ccc.KnownScript.XUdt, ccc.KnownScript.Secp256k1Blake160]) {
    const info = await client.getKnownScript(name);
    console.log(`${label} ${name}: ${info.hashType} ${info.codeHash}`);
    for (const { cellDep, type } of info.cellDeps) {
      const tx = await client.getTransaction(cellDep.outPoint.txHash);
      const output = tx?.transaction.outputs[Number(cellDep.outPoint.index)];
      const live = await client.getCellLive(cellDep.outPoint, false);
      console.log(`   dep ${cellDep.outPoint.txHash}:${cellDep.outPoint.index} ${cellDep.depType} live=${Boolean(live)}`);
      if (type) console.log(`     resolved by type ${type.hash()} (Type ID args ${type.args})`);
      if (output) console.log(`     type ${JSON.stringify(output.type ?? null)}\n     lock ${JSON.stringify(output.lock)}`);
    }
  }
}
process.exit(0);

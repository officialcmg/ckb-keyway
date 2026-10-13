import * as ccc from "@ckb-ccc/core";
import { isXudtCompatible } from "./tokens";

const RUSD_CONTRACT_TYPE_ID_ARGS = "0x97d30b723c0b2c66e9cb8d4d0df4ab5d7222cbb00d4a9a2055ce2e5d7f0d8b0f";
const MAX_CELLS = 50;

/**
 * Stopgap until Fiber pays force-closed channels to their close address: moves everything at a node's
 * settlement key to the user's own address, keeping tokens as they are, with the fee taken from the CKB.
 * Cells with a type script it can't move safely are left where they are. Returns the transaction hash, or
 * undefined when there is nothing to sweep.
 */
export async function sweepSettlement(client: ccc.Client, settlementKey: ccc.HexLike, destination: ccc.ScriptLike): Promise<string | undefined> {
  const signer = new ccc.SignerCkbPrivateKey(client, settlementKey);
  const from = (await signer.getRecommendedAddressObj()).script;
  const to = ccc.Script.from(destination);
  if (from.eq(to)) return undefined;

  const xudt = await client.getKnownScript(ccc.KnownScript.XUdt);
  const movable = (type: ccc.Script | undefined) => !type
    || (type.codeHash === xudt.codeHash && type.hashType === xudt.hashType)
    || isXudtCompatible(type);
  const cells: ccc.Cell[] = [];
  for await (const cell of client.findCellsByLock(from, undefined, true)) {
    if (movable(cell.cellOutput.type)) cells.push(cell);
    if (cells.length >= MAX_CELLS) break;
  }
  if (cells.length === 0) return undefined;

  const tx = ccc.Transaction.from({
    inputs: cells.map((cell) => ({ previousOutput: cell.outPoint })),
    outputs: cells.map((cell) => ({ lock: to, type: cell.cellOutput.type, capacity: cell.cellOutput.capacity })),
    outputsData: cells.map((cell) => cell.outputData),
  });
  await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.Secp256k1Blake160);
  if (cells.some((cell) => cell.cellOutput.type && !isXudtCompatible(cell.cellOutput.type))) {
    await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.XUdt);
  }
  if (cells.some((cell) => cell.cellOutput.type && isXudtCompatible(cell.cellOutput.type))) {
    const contract = await client.findSingletonCellByType({ codeHash: TYPE_ID_CODE_HASH, hashType: "type", args: RUSD_CONTRACT_TYPE_ID_ARGS }, true);
    if (!contract) throw new Error("Could not find the token contract to move token cells");
    tx.addCellDeps({ outPoint: contract.outPoint, depType: "code" });
  }

  // The fee comes out of the largest plain CKB output, or a token cell's spare capacity if there is none.
  const plain = tx.outputs.map((output, index) => ({ output, index })).filter(({ output }) => !output.type);
  const payer = (plain.length ? plain : tx.outputs.map((output, index) => ({ output, index })))
    .reduce((best, item) => item.output.capacity > best.output.capacity ? item : best);
  await tx.completeFeeChangeToOutput(signer, payer.index);
  return signer.sendTransaction(tx);
}

const TYPE_ID_CODE_HASH = "0x00000000000000000000000000000000000000000000000000545950455f4944";

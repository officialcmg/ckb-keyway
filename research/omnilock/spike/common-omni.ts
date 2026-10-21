import { ccc } from "@ckb-ccc/core";
import { client, loadState } from "./lib.ts";

export async function omniLock(): Promise<ccc.Script> {
  const st = loadState();
  return ccc.Script.fromKnownScript(client, ccc.KnownScript.OmniLock, st.omniArgs);
}

/** Current AdminList cell, found by its Type ID script (the address never depends on its outpoint). */
export async function adminListCell(): Promise<ccc.Cell> {
  const st = loadState();
  const type = await ccc.Script.fromKnownScript(client, ccc.KnownScript.TypeId, st.adminTypeArgs);
  const cell = await client.findSingletonCellByType(type, true);
  if (!cell) throw new Error("AdminList cell not found");
  return cell;
}

/** Plain (no type, no data) cells under the Omnilock, largest first. */
export async function plainOmniCells(lock: ccc.Script): Promise<ccc.Cell[]> {
  const out: ccc.Cell[] = [];
  for await (const c of client.findCellsByLock(lock, null, true)) {
    if (!c.cellOutput.type && c.outputData === "0x") out.push(c);
  }
  return out.sort((a, b) => (b.cellOutput.capacity > a.cellOutput.capacity ? 1 : -1));
}

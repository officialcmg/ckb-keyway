// Prints capacity held by K's secp address and (if known) K's Omnilock address.
import { ccc } from "@ckb-ccc/core";
import { client, loadKeys, loadState, secpScript, cellsOf } from "./lib.ts";
const keys = loadKeys();
const st = loadState();
const show = async (name: string, lock: ccc.Script) => {
  const cells = await cellsOf(lock);
  const total = cells.reduce((a, c) => a + c.cellOutput.capacity, 0n);
  console.log(name, ccc.Address.fromScript(lock, client).toString(), ccc.fixedPointToString(total), "CKB in", cells.length, "cells");
};
await show("K secp", await secpScript(keys.K));
if (st.omniArgs) await show("K omni", await ccc.Script.fromKnownScript(client, ccc.KnownScript.OmniLock, st.omniArgs));

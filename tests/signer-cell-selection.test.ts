import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { KeyWayAccountSigner, secp256k1Lock } from "../src/sdk/browser/account-lock.ts";
import { RemoteCkbSigner } from "../src/sdk/browser/remote-ckb-signer.ts";

const CKB = 100_000_000n;
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true));
const TOKEN = ccc.Script.from({ codeHash: `0x${"7a".repeat(32)}`, hashType: "type", args: `0x${"01".repeat(32)}` });

let nextCell = 1;
function cell(lock: ccc.Script, capacity: bigint, type?: ccc.Script, outputData: ccc.Hex = "0x"): ccc.Cell {
  return ccc.Cell.from({ outPoint: { txHash: `0x${(nextCell++).toString(16).padStart(64, "0")}`, index: 0 }, cellOutput: { lock, capacity, type }, outputData });
}

/** A testnet client whose indexer answers from these cells, by lock (exact or prefix) and type. */
function indexedClient(cells: ccc.Cell[]): ccc.Client {
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  void client.cache.recordCells(cells);
  Object.assign(client, {
    findCellsOnChain: async function* (keyLike: ccc.ClientIndexerSearchKeyLike) {
      const key = ccc.ClientIndexerSearchKey.from(keyLike);
      for (const found of cells) {
        const { lock, type } = found.cellOutput;
        const matches = key.scriptSearchMode === "prefix"
          ? lock.codeHash === key.script.codeHash && lock.hashType === key.script.hashType && lock.args.startsWith(key.script.args)
          : lock.eq(key.script);
        if (!matches) continue;
        if (key.filter?.script && !type?.eq(key.filter.script)) continue;
        if (key.filter?.scriptLenRange && Number(key.filter.scriptLenRange[1]) <= 1 && type) continue;
        yield found;
      }
    },
  });
  return client;
}

test("the signer never picks anyone-can-pay cells of the account's key, which KeyWay doesn't sign", async () => {
  const offline = indexedClient([]);
  const secp = await secp256k1Lock(offline, publicKey);
  const acpInfo = await offline.getKnownScript(ccc.KnownScript.AnyoneCanPay);
  // Anyone can make a cell under the anyone-can-pay lock of the account's key hash, with or without minimums.
  const acp = ccc.Script.from({ codeHash: acpInfo.codeHash, hashType: acpInfo.hashType, args: secp.args });
  const acpWithMinimum = ccc.Script.from({ codeHash: acpInfo.codeHash, hashType: acpInfo.hashType, args: ccc.bytesConcat(secp.args, [0x00]) });
  const planted = [
    cell(acp, 1_000n * CKB),
    cell(acpWithMinimum, 1_000n * CKB),
    cell(acp, 200n * CKB, TOKEN, ccc.hexFrom(ccc.numLeToBytes(1_000n, 16))),
  ];
  const own = [cell(secp, 500n * CKB), cell(secp, 200n * CKB, TOKEN, ccc.hexFrom(ccc.numLeToBytes(100n, 16)))];
  const client = indexedClient([...planted, ...own]);
  const isPlanted = (input: ccc.CellInput) => planted.some(({ outPoint }) => outPoint.eq(input.previousOutput));

  for (const signer of [new KeyWayAccountSigner(client, publicKey), new RemoteCkbSigner("token", publicKey, () => false, client)]) {
    assert.deepEqual((await signer.getAddressObjs()).map(({ script }) => script.hash()), [secp.hash()]);
    const found: ccc.Cell[] = [];
    for await (const item of signer.findCells({})) found.push(item);
    assert.ok(found.length > 0 && found.every(({ cellOutput }) => cellOutput.lock.eq(secp)), "only cells under the secp256k1 lock");

    // "Send all" and a plain send collect only the account's own cells.
    const all = ccc.Transaction.from({ outputs: [{ lock: secp, capacity: 0n }], outputsData: ["0x"] });
    await all.completeInputsAll(signer);
    assert.equal(all.inputs.some(isPlanted), false);
    assert.equal(all.inputs.length, 1);

    // A partial token send collects only the account's own token cells.
    const token = ccc.Transaction.from({ outputs: [{ lock: secp, type: TOKEN, capacity: 142n * CKB }], outputsData: [ccc.numLeToBytes(50n, 16)] });
    await token.completeInputsByUdt(signer, TOKEN);
    assert.equal(token.inputs.some(isPlanted), false);
    assert.equal(token.inputs.length, 1);

    // So every signing group is the account's own lock, the only one KeyWay signs.
    assert.deepEqual((await signer.getRelatedScripts(token)).map(({ script }) => script.hash()), [secp.hash()]);
  }
});

import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { onOneNode, settlementNodes } from "../src/server/recovery.ts";

const HASH = `0x${"ab".repeat(32)}`;

test("a pending recovery change is settled from clients that each reach exactly one node", async (t) => {
  const asked: string[] = [];
  t.mock.method(globalThis, "fetch", async (url: string | URL) => {
    asked.push(String(url));
    throw new TypeError("fetch failed");
  });
  const nodes = settlementNodes();
  assert.ok(nodes.length >= 2, "more than one node to fall back to");
  const urls = new Set<string>();
  for (const [index, node] of nodes.entries()) {
    assert.ok(node instanceof ccc.ClientJsonRpc);
    // One transport: no HTTP or WebSocket fallback behind it.
    assert.equal((node.requestor.transport as unknown as { transports?: unknown[] }).transports?.length, 1, `node ${index} has no fallback`);
    asked.length = 0;
    // A node that fails stays failed: CCC doesn't quietly ask another one in its place.
    await assert.rejects(node.getTransaction(HASH));
    assert.ok(asked.length > 0, `node ${index} was asked`);
    assert.equal(new Set(asked).size, 1, `node ${index} asked only its own URL, not a fallback: ${asked.join(", ")}`);
    urls.add(asked[0]);
  }
  assert.equal(urls.size, nodes.length, "each client is a different node");
});

test("a settlement read is answered by one node from start to finish", async () => {
  /** A node that answers the change's transaction and inputs from its own view of the chain, or fails part-way. */
  const node = (name: string, failAt?: number) => {
    let calls = 0;
    const answer = <T>(value: T) => {
      calls += 1;
      if (calls === failAt) throw new Error(`${name} is unreachable`);
      return value;
    };
    return {
      getTransaction: async () => answer({ status: name }),
      getCellLive: async () => answer(name),
    } as unknown as ccc.Client;
  };
  const read = async (client: ccc.Client) => [
    (await client.getTransaction(HASH))?.status,
    await client.getCellLive({ txHash: HASH, index: 0 }, false),
  ];
  // The first node answers once and then fails: none of its answers is mixed with the next node's.
  assert.deepEqual(await onOneNode([node("lagging", 2), node("current")], read), ["current", "current"]);
  assert.deepEqual(await onOneNode([node("first"), node("second")], read), ["first", "first"]);
  await assert.rejects(onOneNode([node("a", 1), node("b", 1)], read), /b is unreachable/);
});

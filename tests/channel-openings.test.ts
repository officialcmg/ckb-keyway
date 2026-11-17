import assert from "node:assert/strict";
import test from "node:test";
import { createChannelOpenings, refuseFundingBeyondRequest } from "../src/sdk/browser/funding-limit.ts";

const CKB = 100_000_000n;

test("overlapping channel opens run one at a time, each preview checked against its own request and peer", async () => {
  const openings = createChannelOpenings();
  const seen: Array<{ open: string; peer?: string; refused?: string }> = [];
  // What the funding signer does when Fiber hands it a funding transaction to approve.
  const preview = (open: string, amountCkb: string) => {
    const opening = openings.current();
    try {
      refuseFundingBeyondRequest({ amountCkb }, opening?.request);
      seen.push({ open, peer: opening?.peer });
    } catch (error) {
      seen.push({ open, peer: opening?.peer, refused: (error as Error).message });
    }
  };
  let releaseFirst!: () => void;
  const firstFunded = new Promise<void>((resolve) => { releaseFirst = resolve; });
  const first = openings.run(async (opening) => {
    opening.peer = "peer-a";
    opening.request = { fundingAmount: 1000n * CKB };
    await firstFunded; // still negotiating with its peer
    preview("a", "1000");
    return "a";
  });
  const second = openings.run(async (opening) => {
    opening.peer = "peer-b";
    opening.request = { fundingAmount: 100n * CKB };
    preview("b", "100");
    return "b";
  });
  await new Promise((resolve) => setTimeout(resolve, 10));
  // The second open hasn't replaced the first's request while the first is still going.
  assert.deepEqual(seen, []);
  releaseFirst();
  assert.deepEqual(await Promise.all([first, second]), ["a", "b"]);
  assert.deepEqual(seen, [{ open: "a", peer: "peer-a" }, { open: "b", peer: "peer-b" }]);
});

test("between opens the slot is empty, so a stray funding preview is refused, and a failed open lets the next run", async () => {
  const openings = createChannelOpenings();
  await assert.rejects(openings.run(async (opening) => {
    opening.request = { fundingAmount: 1000n * CKB };
    throw new Error("peer declined");
  }), /peer declined/);
  assert.equal(openings.current(), undefined);
  assert.throws(() => refuseFundingBeyondRequest({ amountCkb: "1000" }, openings.current()?.request), /wasn't requested through KeyWay/);
  assert.equal(await openings.run(async (opening) => opening.withReserve), false, "a fresh open starts with nothing from the last");
});

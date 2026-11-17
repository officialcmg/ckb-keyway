import assert from "node:assert/strict";
import test from "node:test";
import { openFundingFlow } from "../src/sdk/browser/funding-flow.ts";

const id = `0x${"ab".repeat(32)}`;
const tx = { version: "0x0", cell_deps: [], header_deps: [], inputs: [], outputs: [], outputs_data: [], witnesses: [] };
function fixture() {
  const cancelled: string[] = [];
  const options = {
    params: { pubkey: `0x02${"ab".repeat(32)}`, funding_amount: "0x1", public: true } as never,
    node: {
      openChannelWithExternalFunding: async () => ({ channel_id: id, unsigned_funding_tx: tx }) as never,
      submitSignedFundingTx: async () => ({ funding_tx_hash: id }) as never,
    },
    signFundingTx: async () => tx,
  };
  return { options, cancelled, cancel: async (channelId: string) => { cancelled.push(channelId); } };
}

test("a declined or failed signature cancels only its unsigned channel opening", async () => {
  const f = fixture();
  f.options.signFundingTx = async () => { throw new Error("declined"); };
  await assert.rejects(() => openFundingFlow(f.options, f.cancel), /declined/);
  assert.deepEqual(f.cancelled, [id]);
});

test("a lost submission response never abandons potentially funded state", async () => {
  const f = fixture();
  f.options.node.submitSignedFundingTx = async () => { throw new Error("connection lost"); };
  await assert.rejects(() => openFundingFlow(f.options, f.cancel), /connection lost/);
  assert.deepEqual(f.cancelled, []);
});

test("a successful funding is retained and a failed cancellation preserves the original error", async () => {
  const f = fixture();
  assert.equal((await openFundingFlow(f.options, f.cancel)).fundingTxHash, id);
  assert.deepEqual(f.cancelled, []);
  f.options.signFundingTx = async () => { throw new Error("signing unavailable"); };
  await assert.rejects(() => openFundingFlow(f.options, async () => { throw new Error("cancel unavailable"); }), /signing unavailable/);
});

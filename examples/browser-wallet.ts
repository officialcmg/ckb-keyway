import { connectKeyWay, type FundingPreview } from "../src/sdk/browser/index";

const SHANNONS_PER_CKB = 100_000_000n;

export async function openKeyWayWallet(
  authToken: string,
  confirmFunding: (preview: FundingPreview) => boolean | Promise<boolean>,
) {
  const connected = await connectKeyWay({ authToken, confirmFunding });
  const opened = await connected.keyway.activateCkbChannel(1_000n * SHANNONS_PER_CKB);
  await connected.keyway.waitForChannelReady(opened.channelId, {
    timeout: 180_000,
    interval: 3_000,
  });
  return connected;
}

export async function payFiberInvoice(
  keyway: Awaited<ReturnType<typeof openKeyWayWallet>>["keyway"],
  invoice: string,
) {
  const payment = await keyway.sendPayment({
    invoice,
    timeout: "0x1d4c0",
    max_fee_amount: `0x${SHANNONS_PER_CKB.toString(16)}`,
  });
  return keyway.waitForPayment(payment.payment_hash, { timeout: 120_000 });
}

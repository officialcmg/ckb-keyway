import { openChannelWithExternalFundingFlow, type ChannelId } from "@fiber-pay/sdk/browser";

/** Release an unsigned opening when approval/signing fails. Once submission begins its fate is uncertain. */
export async function openFundingFlow(options: Parameters<typeof openChannelWithExternalFundingFlow>[0], cancel: (channelId: ChannelId) => Promise<unknown>) {
  let channelId: ChannelId | undefined;
  let submitted = false;
  try {
    return await openChannelWithExternalFundingFlow({
      ...options,
      node: {
        async openChannelWithExternalFunding(params) {
          const result = await options.node.openChannelWithExternalFunding(params);
          channelId = result.channel_id;
          return result;
        },
        submitSignedFundingTx(params) {
          submitted = true;
          return options.node.submitSignedFundingTx(params);
        },
      },
    });
  } catch (error) {
    if (channelId && !submitted) await cancel(channelId).catch(() => undefined);
    throw error;
  }
}

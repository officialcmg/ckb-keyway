import type { ListChannelsParams, ListChannelsResult } from "@fiber-pay/sdk/browser";
import { approveFiberParams, type ApproveFiberMethod } from "./fiber-methods";
import { normalizeChannel } from "./create-keyway";
import { formatAsset, tokenAsset } from "./tokens";

/** What the close dialog shows. The balance always returns to the user's own KeyWay account. */
export type FiberChannelClosePreview = {
  channelId: string;
  peer: string;
  /** "ckb", or the channel's token type script hash. */
  asset: string;
  /** The user's side of the channel, in the asset's smallest unit, before the closing fee. */
  returning: string;
  returningText: string;
  /** A force close settles on-chain without the peer, after a delay of about 4 hours. */
  force: boolean;
  network: "CKB testnet";
};

/** What the peer dialog shows, for connecting or disconnecting. */
export type FiberPeerPreview = {
  action: "connect" | "disconnect";
  pubkey?: string;
  address?: string;
  /** For a disconnect: open channels with this peer, which go offline until it reconnects. */
  openChannels: number;
};

/** What the channel settings dialog shows: each setting that changes, from old to new. */
export type FiberChannelSettingsPreview = {
  channelId: string;
  peer: string;
  changes: Array<{ setting: "enabled" | "tlc_expiry_delta" | "tlc_minimum_value" | "tlc_fee_proportional_millionths"; from?: string; to: string }>;
};

export type ApproveFiberChannelClose = (preview: FiberChannelClosePreview) => boolean | Promise<boolean>;
export type ApproveFiberPeer = (preview: FiberPeerPreview) => boolean | Promise<boolean>;
export type ApproveFiberChannelSettings = (preview: FiberChannelSettingsPreview) => boolean | Promise<boolean>;

export type FiberActionApprovals = {
  approveFiberChannelClose?: ApproveFiberChannelClose;
  approveFiberPeerConnect?: ApproveFiberPeer;
  approveFiberChannelSettings?: ApproveFiberChannelSettings;
};

type ActionIo = {
  listChannels: (params: ListChannelsParams) => Promise<ListChannelsResult>;
  /** Runs an approved action on the node: the backend for hosted nodes, the page's node in browser mode. */
  act: (method: Exclude<ApproveFiberMethod, "openChannelWithExternalFunding">, params: Record<string, unknown>) => Promise<unknown>;
};

/**
 * Channel closes, peers and channel settings: each is checked, shown to the user (or to the app's own
 * approval), and only then run. Without an approval function the action is refused, so it's never silent.
 */
export function createFiberActions(io: ActionIo, approvals: () => FiberActionApprovals) {
  async function channel(channelId: string) {
    const found = (await io.listChannels({})).channels.find((item) => item.channel_id === channelId);
    if (!found) throw new Error("No open channel has that ID");
    return found;
  }
  const refuse = (what: string) => { throw new Error(`The ${what} was not approved`); };

  return {
    async shutdownChannel(input: unknown): Promise<void> {
      const params = approveFiberParams("shutdownChannel", input);
      const raw = await channel(String(params.channel_id));
      const normalized = normalizeChannel(raw);
      const asset = normalized.asset.kind === "ckb" ? "ckb" : tokenAsset({
        code_hash: normalized.asset.typeScript.code_hash, hash_type: normalized.asset.typeScript.hash_type, args: normalized.asset.typeScript.args,
      });
      const preview: FiberChannelClosePreview = {
        channelId: normalized.id,
        peer: normalized.peer,
        asset,
        returning: normalized.canSend.toString(),
        returningText: formatAsset(normalized.canSend, asset),
        force: params.force === true,
        network: "CKB testnet",
      };
      if (!await approvals().approveFiberChannelClose?.(preview)) refuse("channel close");
      await io.act("shutdownChannel", params);
    },
    async connectPeer(input: unknown): Promise<void> {
      const params = approveFiberParams("connectPeer", input);
      const preview: FiberPeerPreview = { action: "connect", pubkey: params.pubkey as string | undefined, address: params.address as string | undefined, openChannels: 0 };
      if (!await approvals().approveFiberPeerConnect?.(preview)) refuse("peer connection");
      await io.act("connectPeer", params);
    },
    async disconnectPeer(input: unknown): Promise<void> {
      const params = approveFiberParams("disconnectPeer", input);
      const pubkey = String(params.pubkey).toLowerCase();
      const openChannels = (await io.listChannels({})).channels.filter((item) => item.pubkey.toLowerCase().replace(/^0x/, "") === pubkey.replace(/^0x/, "")).length;
      if (!await approvals().approveFiberPeerConnect?.({ action: "disconnect", pubkey: String(params.pubkey), openChannels })) refuse("peer disconnection");
      await io.act("disconnectPeer", params);
    },
    async updateChannel(input: unknown): Promise<void> {
      const params = approveFiberParams("updateChannel", input);
      const raw = await channel(String(params.channel_id)) as unknown as Record<string, unknown>;
      const keys = ["enabled", "tlc_expiry_delta", "tlc_minimum_value", "tlc_fee_proportional_millionths"] as const;
      const current: Record<string, unknown> = { ...raw, tlc_minimum_value: raw.tlc_minimum_value ?? raw.tlc_min_value };
      const changes = keys.filter((key) => params[key] !== undefined).map((key) => ({
        setting: key,
        from: current[key] === undefined ? undefined : String(current[key]),
        to: String(params[key]),
      }));
      if (changes.length === 0) throw new Error("Pass at least one setting to change");
      if (!await approvals().approveFiberChannelSettings?.({ channelId: String(params.channel_id), peer: String(raw.pubkey), changes })) refuse("channel settings change");
      await io.act("updateChannel", params);
    },
  };
}

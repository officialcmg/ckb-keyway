// Page script for browser-proof.ts: a real fiber-wasm browser node with KeyWay's in-page watchtower bridge and
// store (PR #4) and the remote watchtower queue (watchtower-remote.ts), sending to the proof relay instead of the
// KeyWay API. Bundled by browser-proof.ts; nothing here is part of the SDK.
import * as ccc from "@ckb-ccc/core";
import { FiberBrowserNode } from "@fiber-pay/sdk/browser";
import { KeyWayCredentialProvider } from "../../src/sdk/browser/credential-provider";
import { fiberWasmFactory } from "../../src/sdk/browser/fiber-wasm";
import { listenForWatchtowerCalls } from "../../src/sdk/browser/watchtower-bridge";
import { openWatchtowerStore } from "../../src/sdk/browser/watchtower-store";
import { createRemoteWatchtower, remoteWatchUpdate, updatesForStoredChannel } from "../../src/sdk/browser/watchtower-remote";

const scope = window as unknown as Record<string, unknown>;
scope.proof = {
  async start(fiberKeyHex: string, relay: string) {
    const store = openWatchtowerStore("/wasm-proof");
    const remote = createRemoteWatchtower({
      send: async (update) => {
        const response = await fetch(relay, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(update) });
        if (!response.ok) throw new Error(await response.text());
        return response.json();
      },
      registration: async (channelId) => {
        const stored = await store.get(channelId);
        return stored ? updatesForStoredChannel(stored)[0] : undefined;
      },
    });
    const channelName = "keyway-watchtower-proof";
    listenForWatchtowerCalls(channelName, async (call) => {
      await store.apply(call);
      console.info(`[keyway] watchtower: stored ${call.method}`);
      remote.enqueue(remoteWatchUpdate(call));
    });
    const node = new FiberBrowserNode({
      network: "testnet",
      credential: new KeyWayCredentialProvider("proof", async () => ccc.bytesFrom(fiberKeyHex)),
      wasmFactory: fiberWasmFactory("testnet", { watchtowerChannel: channelName }),
    });
    const info = await node.start();
    scope.node = node;
    scope.remote = remote;
    return JSON.parse(JSON.stringify(info));
  },
};

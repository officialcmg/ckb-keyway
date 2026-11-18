import * as ccc from "@ckb-ccc/core";
import {
  createCccExternalFundingResolver,
  FiberBrowserNode,
  shouldDiagnoseFundingAbortError,
  type Channel,
  type ChannelId,
  type NewInvoiceParams,
  type OpenChannelWithExternalFundingParams,
  type Script,
  type SendPaymentParams,
} from "@fiber-pay/sdk/browser";
import { KeyWayCredentialProvider } from "./credential-provider";
import { openFundingFlow } from "./funding-flow";
import { acquireDeviceLock, type DeviceLock } from "./device-lock";
import { acquireDeviceLease, type DeviceLease } from "./device-lease";
import { serializeCccTransactionForRpc } from "./ccc-transaction";
import { fundingLockCellDeps, FUNDING_LOCK_KNOWN_SCRIPTS, type KeyWayRecovery } from "./account-lock";
import { getLockBalance } from "./ckb-balance";
import { RemoteCkbSigner, type ApproveFiberChannelOpen } from "./remote-ckb-signer";
import { getDeviceIdHash, markChannelOpened, type FiberKeyDelivery } from "./bootstrap";
import { ANY_FUNDING, connectChannelPeers, type ChannelPeer } from "./channel-peers";
import { normalizeFiberPubkey } from "./fiber-pubkey";
import { KeyWayApiClient } from "./api-client";
import { createEncryptedNodeBackup } from "./node-backup";
import { createNodeStorage } from "./node-storage";
import { backUpBeforeLogout, restoreBeforeStart, stopBeforeLogout } from "./node-migration";
import { toKeyWayError, type KeyWayError } from "./keyway-error";
import { freeFiberParams, fundingFeeRate, paymentFiberParams } from "./fiber-methods";
import { describePayment, type ApproveFiberPayment } from "./fiber-payment";
import { createFiberActions, type FiberActionApprovals } from "./fiber-actions";
import { approveFiberParams } from "./fiber-methods";
import { createFiberNode, listLoggedPayments, type ListPaymentsParams } from "./fiber-node";
import { createPaymentLog } from "./payment-log";
import { closedBy, sweepSettlement } from "./settlement-sweep";
import { fiberWasmFactory } from "./fiber-wasm";
import { listenForWatchtowerCalls } from "./watchtower-bridge";
import { openWatchtowerStore } from "./watchtower-store";
import { isBuried, settleChannel, trackNodeKeySends, type SettleFailure, type SettleResult } from "./watchtower-settle";
import { closureOf, createReserveGate, openClosureStore, presentChannels, recordSettleResult, type ChannelClosure } from "./channel-closures";
import { createRemoteWatchtower, remoteWatchUpdate, updatesForStoredChannel } from "./watchtower-remote";
import { createNodeLifecycle } from "./node-lifecycle";
import { createChannelOpenings, refuseFundingBeyondRequest, type ChannelOpening } from "./funding-limit";
import { createFeeReserve, FEE_RESERVE, hasFeeReserve } from "./fee-reserve";
import type { RequestEmailCode } from "./email-code";

export type KeyWayFundingParams = Omit<
  OpenChannelWithExternalFundingParams,
  "funding_lock_script" | "funding_lock_script_cell_deps" | "shutdown_script"
>;

export type CreateKeyWayOptions = {
  identifier: string;
  authToken: string;
  ckbPublicKey: string;
  /** The wallet's recovery settings, when it has them: the account then lives at its Omnilock address. */
  recovery?: KeyWayRecovery;
  approveFiberChannelOpen: ApproveFiberChannelOpen;
  /** The app's own payment confirmation, if any. KeyWay draws no payment dialog. */
  approveFiberPayment?: ApproveFiberPayment;
  approvals?: () => FiberActionApprovals;
  requestEmailCode?: RequestEmailCode;
  loadFiberKey: (leaseId: string) => Promise<FiberKeyDelivery>;
  network?: "testnet" | "mainnet";
  apiClient?: KeyWayApiClient;
  restoreRequired?: boolean;
  onLeaseLost?: (error: Error) => void;
  onFiberStartup?: (stage: BrowserNodeStage) => void;
  /**
   * Runs the step that takes the device lock. The provider runs it only while no logout of the session is in
   * progress and the session is still signed in (`startUnlessLoggingOut`, logout-handoff.ts).
   */
  guardClaim?: <T>(claim: () => Promise<T>) => Promise<T>;
};

export type ChannelOpenStage = "connecting" | "negotiating" | "confirming" | "signing" | "broadcasting" | "waiting";
export type ChannelOpenProgress = (stage: ChannelOpenStage) => void;
export type BrowserNodeStage = "claiming_device" | "restoring_channels" | "starting_browser_node";
export type OpenKeyWayChannelOptions = {
  /** Shannons for a CKB channel (default 1,000 CKB), or the token's smallest unit for a token channel. */
  fundingAmount?: bigint;
  /** Opens a token channel instead, for a token the peer accepts (on testnet, RUSD). Requires `fundingAmount`. */
  udtTypeScript?: Script;
  peer?: string;
  public?: boolean;
  fundingFeeRate?: bigint;
  commitmentFeeRate?: bigint;
};
export type KeyWayChannelStatus = "pending" | "ready" | "closing" | "closed" | "failed" | "unknown";
/** The asset a channel or payment moves: CKB, or a token identified by its type script. */
export type KeyWayAsset = { kind: "ckb" } | { kind: "token"; typeScript: Script };
export type KeyWayChannel = {
  id: ChannelId;
  peer: string;
  status: KeyWayChannelStatus;
  asset: KeyWayAsset;
  /**
   * What the user can still send through this channel, in the asset's smallest unit (shannons for CKB). Zero once
   * the channel's funding cell is seen spent on-chain by a force close.
   */
  canSend: bigint;
  /** What the user can still receive through this channel. */
  canReceive: bigint;
  /**
   * The channel's total size: canSend plus canReceive, or, once a force close has spent its funding cell, what
   * those were when it closed.
   */
  capacity: bigint;
  public: boolean;
  raw: Channel;
};
/** One channel as KeyWay's watchtower sees it. */
export type WatchtowerChannelStatus = {
  channelId: string;
  /** watching: open or not yet resolved; penalty-sent/penalized: the peer published a revoked commitment. */
  state: "watching" | "penalty-sent" | "penalized" | "closed" | "missed";
  detail: string | null;
  commitmentNumber: string | null;
  fundingOutPoint: string | null;
  closingTransaction: string | null;
  penaltyTransaction: string | null;
  checkedAt: string | null;
  updatedAt: string;
};
export type PaymentEstimate =
  | { routable: true; fee: bigint }
  | { routable: false; error: KeyWayError };

const DEFAULT_CHANNEL_FUNDING = 1_000n * 100_000_000n;
const WATCH_INTERVAL = 60_000;
/** How long after a start channel lists wait, at most, for the watchtower's first look at the chain. */
const FIRST_WATCH_WAIT = 5_000;

export function createKeyWay(options: CreateKeyWayOptions) {
  let deviceLease: DeviceLease | undefined;
  const credential = new KeyWayCredentialProvider(options.identifier, async () => {
    if (!deviceLease) throw new Error("An active device lease is required");
    return (await options.loadFiberKey(deviceLease.leaseId)).fiberKey;
  });
  const network = options.network ?? "testnet";
  const canonicalPrefix = `/wasm-${options.identifier}`;
  const storage = createNodeStorage(canonicalPrefix, localStorage);
  let databasePrefix = storage.current();
  // Fiber's browser build has no watchtower, so its watchtower events come to the page (watchtower-bridge.ts).
  const watchtowerChannel = `keyway-watchtower-${ccc.hexFrom(crypto.getRandomValues(new Uint8Array(16))).slice(2)}`;
  let watchtower = openWatchtowerStore(databasePrefix);
  // What the in-page watchtower has seen of each channel's close on-chain (channel-closures.ts).
  let closures = openClosureStore(databasePrefix);
  let stopWatchtowerBridge: (() => Promise<void>) | undefined;
  /** Once the node has stopped it sends no more events: finish storing the ones already received, then close. */
  let bridgeDrain: Promise<void> | undefined;
  async function closeWatchtowerBridge() {
    // Overlapping callers (e.g. two logouts) all wait for the same drain before going on to a backup.
    if (!bridgeDrain && stopWatchtowerBridge) {
      const stopBridge = stopWatchtowerBridge;
      stopWatchtowerBridge = undefined;
      bridgeDrain = stopBridge().finally(() => { bridgeDrain = undefined; });
    }
    await bridgeDrain;
  }
  const node = new FiberBrowserNode({
    network,
    credential,
    wasmFactory: fiberWasmFactory(network, { watchtowerChannel }),
    nodeConfig: { get databasePrefix() { return databasePrefix; } },
  });
  let deviceLock: DeviceLock | undefined;
  const api = options.apiClient ?? new KeyWayApiClient();
  const openings = createChannelOpenings();
  let preparedPeers: Promise<ChannelPeer[]> | undefined;
  let preparedFundingAmount: bigint | undefined;
  const fundingSigner = new RemoteCkbSigner(options.authToken, options.ckbPublicKey, async (preview) => {
    const opening = openings.current();
    // The account's share may not exceed what the app asked Fiber for, whatever the peer did to the transaction.
    refuseFundingBeyondRequest(preview, opening?.request);
    opening?.progress?.("confirming");
    const approved = await options.approveFiberChannelOpen({
      ...preview,
      ...(opening?.peer ? { peer: opening.peer } : {}),
      ...(opening?.withReserve ? { feeReserveCkb: ccc.fixedPointToString(FEE_RESERVE) } : {}),
    });
    if (approved) opening?.progress?.("signing");
    return approved;
  }, undefined, api, options.recovery, (error) => options.approvals?.().settled?.("funding", error), options.requestEmailCode);
  const resolveCccFunding = createCccExternalFundingResolver({
    signer: fundingSigner,
    knownScripts: FUNDING_LOCK_KNOWN_SCRIPTS,
    ckbRpcUrl: "https://testnet.ckb.dev/",
    // fiber-pay normalizes field names, but CCC must first serialize bigint fields to CKB RPC hex.
    signFundingTxOptions: { toRpcTransaction: serializeCccTransactionForRpc },
  });
  // KeyWay's pinned Omnilock isn't a CCC known script, so its deps come from the account's recovery settings.
  const resolveExternalFunding: typeof resolveCccFunding = async (context) => {
    const resolved = await resolveCccFunding(context);
    return options.recovery ? { ...resolved, fundingLockScriptCellDeps: fundingLockCellDeps(options.recovery) } : resolved;
  };
  // The node key's claims and sweeps have a client of their own: each watchtower pass rebuilds its cache from what
  // the chain says (trackNodeKeySends), which must not touch the account's own pending transactions. Passes and
  // sweeps take turns with it, so no send lands while a pass rebuilds the cache.
  const nodeKeyClient = new ccc.ClientPublicTestnet();
  const nodeKeySends = trackNodeKeySends(nodeKeyClient);
  // The node settles force-closed channels with the key derived from the Fiber key, so the reserve goes there.
  const feeReserve = createFeeReserve({
    reserveClient: nodeKeyClient,
    authToken: options.authToken,
    ckbPublicKey: options.ckbPublicKey,
    recovery: options.recovery,
    api,
    requestEmailCode: options.requestEmailCode,
    client: fundingSigner.client,
    lock: async () => {
      const key = await credential.getCkbSecretKey();
      try {
        return (await new ccc.SignerCkbPrivateKey(fundingSigner.client, ccc.hexFrom(key)).getRecommendedAddressObj()).script;
      } finally {
        key.fill(0);
      }
    },
  });
  let paymentLog = createPaymentLog(databasePrefix);
  function useDatabases(prefix: string) {
    watchtower.close();
    databasePrefix = prefix;
    watchtower = openWatchtowerStore(prefix);
    closures = openClosureStore(prefix);
    paymentLog = createPaymentLog(prefix);
  }
  let restoreRequired = options.restoreRequired ?? false;
  // KeyWay's watchtower punishes a peer that publishes a revoked commitment while this tab is closed. It gets the
  // funding keys and the newest revocation only (watchtower-remote.ts); the keys stay here.
  const remoteWatchtower = createRemoteWatchtower({
    send: (update) => api.watchtower(options.authToken, update),
    registration: async (channelId) => {
      const stored = await watchtower.get(channelId);
      return stored ? updatesForStoredChannel(stored)[0] : undefined;
    },
  });
  /** While KeyWay's watchtower is missing a revocation, closing the tab leaves that state unwatched: ask first. */
  function warnBeforeUnload(event: BeforeUnloadEvent) {
    if (remoteWatchtower.pending() === 0) return;
    event.preventDefault();
    // Some browsers only ask when returnValue is a non-empty string; none show the text.
    event.returnValue = "Fiber channel updates have not reached KeyWay's watchtower yet.";
  }

  const lifecycle = createNodeLifecycle({
    node,
    async claim() {
      options.onFiberStartup?.("claiming_device");
      const lockDevice = () => acquireDeviceLock(options.identifier);
      deviceLock = await (options.guardClaim ? options.guardClaim(lockDevice) : lockDevice());
      deviceLease = await acquireDeviceLease(options.authToken, api, (cause) => {
        const error = cause instanceof Error ? cause : new Error("The active KeyWay device lease expired");
        void stop().finally(() => options.onLeaseLost?.(error));
      });
      useDatabases(storage.current());
      if (restoreRequired) {
        options.onFiberStartup?.("restoring_channels");
        await restoreClaimedBackup();
      }
    },
    openBridge() {
      options.onFiberStartup?.("starting_browser_node");
      stopWatchtowerBridge ??= listenForWatchtowerCalls(watchtowerChannel, async (call) => {
        await watchtower.apply(call);
        console.info(`[keyway] watchtower: stored ${call.method}`);
        remoteWatchtower.enqueue(remoteWatchUpdate(call));
      });
      if (typeof window !== "undefined") window.addEventListener("beforeunload", warnBeforeUnload);
      // Bring KeyWay's watchtower up to date with every channel this device already watches (it ignores repeats).
      void watchtower.list().then((channels) => {
        for (const channel of channels) for (const update of updatesForStoredChannel(channel)) remoteWatchtower.enqueue(update);
      }).catch((error) => console.warn("[keyway] watchtower: could not read the stored channels", error));
    },
    closeBridge: closeWatchtowerBridge,
    afterStart: startSweeping,
    async stopTimers() {
      if (sweepTimer) clearInterval(sweepTimer);
      sweepTimer = undefined;
      await stopWatching();
    },
    async release() {
      // The bridge has drained. Give KeyWay's watchtower whatever is still queued before the page lets go of the node.
      await Promise.race([remoteWatchtower.flush(), new Promise((resolve) => setTimeout(resolve, 10_000))]);
      // Anything still queued keeps being retried after the stop, so closing the tab still needs the warning.
      if (typeof window !== "undefined" && remoteWatchtower.pending() === 0) window.removeEventListener("beforeunload", warnBeforeUnload);
      watchtower.close();
      const lease = deviceLease;
      const lock = deviceLock;
      deviceLease = undefined;
      deviceLock = undefined;
      await Promise.allSettled([lease?.release(), lock?.release()]);
    },
    overtaken: () => toKeyWayError(new Error("The Fiber node was stopped while it was starting")),
  });

  async function start() {
    if (typeof window !== "undefined" && window.crossOriginIsolated !== true) {
      throw toKeyWayError(new Error("Cross-origin isolated browser context is required"));
    }
    return lifecycle.start();
  }

  /**
   * Stopgap until Fiber pays force-closed channels to their close address: the node settles to a key
   * derived from the user's Fiber key, and this moves anything there to the user's own address.
   */
  let sweepTimer: ReturnType<typeof setInterval> | undefined;
  const sweepNow = () => nodeKeySends.exclusive(() => sweepWithNodeKey());
  /** `returning`: the sweep that follows the reserve no longer being needed; says so if the reserve can't leave. */
  async function sweepWithNodeKey(returning = false) {
    if (!node.isRunning || !credential.isUnlocked()) return;
    const key = await credential.getCkbSecretKey();
    try {
      const destination = (await fundingSigner.getRecommendedAddressObj()).script;
      // The decision that can move the reserve: every verdict it rests on is asked about again now.
      const keep = await reserve.needed({ fresh: true }) ? FEE_RESERVE : 0n;
      // While the reserve stays, it stays at a size that can be returned to this account's address later.
      const swept = await sweepSettlement(nodeKeyClient, ccc.hexFrom(key), destination, keep, { returnableReserve: true });
      if (swept) nodeKeySends.record(swept as ccc.Hex);
      else if (returning && keep === 0n) {
        const nodeLock = (await new ccc.SignerCkbPrivateKey(nodeKeyClient, ccc.hexFrom(key)).getRecommendedAddressObj()).script;
        if (await hasFeeReserve(nodeKeyClient, nodeLock)) {
          console.info("[keyway] the fee reserve is no longer needed, but it is smaller than the smallest cell the account's address can hold, so it stays on the node's key: the next channel uses it, and the next settlement carries it back");
        }
      }
    } finally {
      key.fill(0);
    }
  }
  /**
   * Whether any channel may still need the fee reserve: as the node lists them, less the force-closed ones the
   * in-page watchtower has established as finished on-chain (channel-closures.ts `createReserveGate`).
   */
  const reserve = createReserveGate({
    listChannels: async () => (await node.listChannels({ include_closed: true })).channels,
    listClosures: () => closures.list(),
    isBuried: (txHash) => isBuried(nodeKeyClient, txHash),
    opening: () => openings.current() !== undefined,
  });
  function startSweeping() {
    // A stop() that ran while start() was finishing leaves the node stopped: don't start the timers then.
    if (!node.isRunning) return;
    watchStopped = false;
    reserveHeld = undefined;
    // What the chain said in an earlier run of the node is asked again in this one.
    reserve.reset();
    // The first pass goes before the first sweep, so the first channel list waits for as little as it can.
    const first = watchNow().catch(() => undefined).finally(() => { if (firstWatch?.pass === first) firstWatch = undefined; });
    firstWatch = { pass: first, until: Date.now() + FIRST_WATCH_WAIT };
    watchTimer ??= setInterval(() => void watchNow().catch(() => undefined), WATCH_INTERVAL);
    void sweepNow().catch(() => undefined);
    sweepTimer ??= setInterval(() => void sweepNow().catch(() => undefined), 10 * 60_000);
  }

  /**
   * The in-page watchtower's pass (Fiber's own runs every 60 s): for each channel the node handed it, claim the
   * user's share once a force-close commitment's delay has passed, then sweep it to the user's address.
   */
  let watchTimer: ReturnType<typeof setInterval> | undefined;
  let watchPass: Promise<void> | undefined;
  let watchStopped = false;
  /** Claims sent but not yet swept: the sweep follows once the claim is on-chain, on a later pass. */
  const claimsToSweep = new Set<ccc.Hex>();
  const watchStatus = new Map<string, string>();
  /**
   * The first pass after a start, while it runs: until it has looked, a channel the peer closed while the page was
   * shut reads as ready. Channel lists wait for it, but not past `until`.
   */
  let firstWatch: { pass: Promise<void>; until: number } | undefined;
  /** Whether the last pass found the fee reserve still needed; the pass that finds it no longer is returns it. */
  let reserveHeld: boolean | undefined;
  function watchNow(): Promise<void> {
    if (watchPass || watchStopped || !node.isRunning || !credential.isUnlocked()) return watchPass ?? Promise.resolve();
    watchPass = nodeKeySends.exclusive(watchOnce).finally(() => { watchPass = undefined; });
    return watchPass;
  }
  async function watchOnce() {
    {
      // A claim or sweep the chain dropped would otherwise stay in ccc's cache, its payout usable and its fee
      // reserve spent, and break every later claim: start each pass from what the chain says.
      await nodeKeySends.refresh();
      if (watchStopped) return;
      // The 10-minute sweep (and the one at start) also picks up claims whose follow-up sweep was missed.
      for (const txHash of [...claimsToSweep]) {
        if (watchStopped) return;
        const found = await nodeKeyClient.getTransactionNoCache(txHash).catch(() => null);
        if (watchStopped) return;
        // A dropped or rejected claim leaves its commitment cell live, so this pass claims it again.
        if (found === undefined || found?.status === "rejected") claimsToSweep.delete(txHash);
        if (found?.status !== "committed") continue;
        claimsToSweep.delete(txHash);
        // Already this pass's turn with the node key.
        await sweepWithNodeKey().catch((error) => console.warn("[keyway] could not sweep the claimed funds yet", error));
      }
      if (watchStopped) return;
      const watched = await watchtower.list();
      if (watchStopped) return;
      const { channels } = await node.listChannels({ include_closed: true });
      if (watchStopped) return;
      const seen: ChannelClosure[] = watched.length > 0 ? await closures.list().catch(() => []) : [];
      let finishedThisPass = false;
      const key = watched.length > 0 ? await credential.getCkbSecretKey() : new Uint8Array(0);
      try {
        for (const channel of watched) {
          if (watchStopped) break;
          const raw = channels.find((item) => String(item.channel_id).toLowerCase() === channel.channelId);
          const outpoint = raw?.channel_outpoint ? String(raw.channel_outpoint) : undefined;
          // Fiber hands a force-closed channel over again at every start; one finished for good needs no second look.
          if (raw && await reserve.settledForGood(closureOf(seen, raw), raw)) {
            await watchtower.remove(channel.channelId).catch(() => undefined);
            continue;
          }
          if (!outpoint) {
            if (watchStatus.get(channel.channelId) !== "missing") {
              watchStatus.set(channel.channelId, "missing");
              console.warn(`[keyway] watchtower: channel ${channel.channelId} is not in the node's channel list; it can't be checked until it is`);
            }
            continue;
          }
          try {
            const result = await settleChannel({
              client: nodeKeyClient, network, channel, nodeKey: ccc.hexFrom(key),
              ref: { channelId: channel.channelId, fundingOutPoint: ccc.OutPoint.decode(outpoint) },
              preimage: (paymentHash) => watchtower.preimage(paymentHash),
            });
            if (watchStatus.get(channel.channelId) !== result.status) {
              watchStatus.set(channel.channelId, result.status);
              console.info(`[keyway] watchtower: channel ${channel.channelId}: ${result.status}${result.txHash ? ` ${result.txHash}` : ""}`);
            }
            if (result.txHash) {
              nodeKeySends.record(result.txHash);
              claimsToSweep.add(result.txHash);
            }
            // Remembers a force close seen on-chain and, once the channel is finished for good, ends its watch.
            if (await noteOnChain(channel.channelId, result, outpoint, raw)) finishedThisPass = true;
          } catch (error) {
            console.warn(`[keyway] watchtower: channel ${channel.channelId} could not be settled yet`, error);
            // A claim that couldn't be built or sent (no fee cell, an RPC error) doesn't unsee the close.
            // And a claim that was due contradicts any verdict that nothing is left.
            const failure = error as SettleFailure | undefined;
            if (failure?.closingTx) {
              await noteOnChain(channel.channelId, { channelId: channel.channelId, status: "could not be settled yet", closingTx: failure.closingTx, ...(failure.unsettled ? { unsettled: true as const } : {}) }, outpoint, raw);
            }
          }
        }
      } finally {
        key.fill(0);
      }
      if (watchStopped) return;
      // The node comes to report a close, and the watchtower to call it finished, at different times: the pass
      // that first finds no channel needing the reserve any more returns it, instead of the next 10-minute sweep.
      const held = await reserve.needed();
      if ((reserveHeld === true || finishedThisPass) && !held && !watchStopped) {
        await sweepWithNodeKey(true).catch((error) => console.warn("[keyway] could not return the fee reserve yet", error));
      }
      reserveHeld = held;
    }
  }
  /** Records what a pass saw of a channel on-chain (channel-closures.ts); true when that finished the channel. */
  async function noteOnChain(channelId: string, result: SettleResult, fundingOutPoint: string, raw: Parameters<typeof closedBy>[0] | undefined): Promise<boolean> {
    try {
      const finished = await recordSettleResult({
        result, fundingOutPoint, closures, watchtower,
        nodeClosedBy: raw ? closedBy(raw) : undefined,
        isBuried: (txHash) => isBuried(nodeKeyClient, txHash),
      });
      if (finished) console.info(`[keyway] watchtower: channel ${channelId} is finished on-chain (${result.status}); nothing is left to claim`);
      return finished;
    } catch (error) {
      console.warn(`[keyway] watchtower: could not record what channel ${channelId} looks like on-chain; the next pass tries again`, error);
      return false;
    }
  }

  /** Stops the watchtower passes and waits for one in progress, so none runs after the node stops. */
  async function stopWatching() {
    if (watchTimer) clearInterval(watchTimer);
    watchTimer = undefined;
    watchStopped = true;
    await watchPass?.catch(() => undefined);
  }

  async function stop() {
    try {
      // Waits for a start it overtook to stop its node, then drains the bridge before the store closes.
      await lifecycle.stop();
    } finally {
      preparedPeers = undefined;
      preparedFundingAmount = undefined;
    }
  }

  function stopForLogout() {
    // A start in progress settles first: one that already holds the lease is backed up below.
    return lifecycle.logout(async (steps) => {
      if (!deviceLease) {
        await stopBeforeLogout({
          async stop() {
            try {
              await steps.stop();
            } finally {
              preparedPeers = undefined;
              preparedFundingAmount = undefined;
            }
          },
          // An earlier stop() may have left revocations queued; they still have to reach KeyWay's watchtower.
          flushWatchtower: () => remoteWatchtower.deliver(10_000),
        });
        remoteWatchtower.stop();
        return;
      }
      const lease = deviceLease;
      const deviceIdHash = await getDeviceIdHash();
      // The backup is accepted only while this is the device's latest key delivery: if its upload stalls and the
      // node runs again, the upload is refused when it lands (the node has moved past it).
      let keyDelivery = "";
      await backUpBeforeLogout({
        loadFiberKey: async () => {
          const delivered = await options.loadFiberKey(lease.leaseId);
          keyDelivery = delivered.keyDelivery;
          return delivered.fiberKey;
        },
        // The backup is taken only after the bridge has drained, so it holds every watchtower call.
        stopNode: steps.stopNodeAndDrain,
        // Once the session ends nothing more reaches KeyWay's watchtower from this page, so it must have every
        // revocation first; until then the logout fails and the user stays signed in.
        flushWatchtower: () => remoteWatchtower.deliver(10_000),
        createBackup: (fiberKey) => createEncryptedNodeBackup(databasePrefix, fiberKey, canonicalPrefix),
        saveBackup: (backup) => api.saveNodeBackup(options.authToken, {
          deviceIdHash,
          leaseId: lease.leaseId,
          keyDelivery,
          backup,
        }),
        releaseOwnership: steps.releaseGuards,
      });
      // The session ends with the logout, so nothing more can reach KeyWay's watchtower from this page.
      remoteWatchtower.stop();
    });
  }

  async function restoreClaimedBackup() {
    if (!deviceLease) throw new Error("An active device lease is required to restore Fiber state");
    const deviceIdHash = await getDeviceIdHash();
    const leaseId = deviceLease.leaseId;
    await restoreBeforeStart({
      loadFiberKey: async () => (await options.loadFiberKey(leaseId)).fiberKey,
      loadBackup: () => api.loadNodeBackup(options.authToken, { deviceIdHash, leaseId }),
      restoreBackup: async (backup, fiberKey) => useDatabases(await storage.restore(backup, fiberKey)),
      confirmRestore: (generation) => api.confirmNodeBackup(options.authToken, {
        deviceIdHash,
        leaseId,
        generation,
      }),
    });
    restoreRequired = false;
  }

  /**
   * Opens a channel funded from the account, recording the request so its funding preview can be checked against it.
   * Opens run one at a time (see `createChannelOpenings`).
   */
  function openFundedChannel(params: KeyWayFundingParams, progress?: ChannelOpenProgress) {
    return openings.run((opening) => openFundedChannelNow(opening, params, progress));
  }
  async function openFundedChannelNow(opening: ChannelOpening, params: KeyWayFundingParams, progress?: ChannelOpenProgress) {
    if (!node.isRunning) throw new Error("Start the Fiber node before opening a channel");
    opening.peer = params.pubkey;
    opening.progress = progress;
    // Asked in turn with the node key's sweeps, of the client that sends them: a reserve a sweep has just sent
    // back is gone, even while that sweep is unconfirmed. From here to the end of this open the reserve stays put.
    opening.withReserve = await nodeKeySends.exclusive(() => feeReserve.needed());
    const funding = await resolveExternalFunding(undefined);
    opening.request = { fundingAmount: BigInt(params.funding_amount), udtTypeScript: params.funding_udt_type_script, shutdownScript: funding.shutdownScript };
    const result = await openFundingFlow({
      node,
      params: {
        ...params,
        funding_fee_rate: fundingFeeRate(params.funding_fee_rate, funding.fundingLockScript),
        shutdown_script: funding.shutdownScript,
        funding_lock_script: funding.fundingLockScript,
        funding_lock_script_cell_deps: funding.fundingLockScriptCellDeps,
      },
      signFundingTx: funding.signFundingTx,
    }, (channelId) => node.abandonChannel({ channel_id: channelId }));
    await markChannelOpened(options.authToken, api);
    const feeReserveTxHash = opening.withReserve ? await feeReserve.send(result.fundingTxHash) : undefined;
    return { ...result, ...(feeReserveTxHash ? { feeReserveTxHash } : {}) };
  }

  function prepareCkbChannel(fundingAmount: bigint): Promise<ChannelPeer[]> {
    if (preparedFundingAmount !== fundingAmount) preparedPeers = undefined;
    preparedFundingAmount = fundingAmount;
    preparedPeers ??= connectChannelPeers(node, fundingAmount).catch((error) => {
      preparedPeers = undefined;
      preparedFundingAmount = undefined;
      throw error;
    });
    return preparedPeers;
  }

  async function activateCkbChannel(
    input: bigint | OpenKeyWayChannelOptions = DEFAULT_CHANNEL_FUNDING,
    onProgress?: ChannelOpenProgress,
  ) {
    const config: OpenKeyWayChannelOptions = typeof input === "bigint" ? { fundingAmount: input } : input;
    if (config.udtTypeScript && config.fundingAmount === undefined) throw new Error("A token channel needs a fundingAmount");
    const fundingAmount = config.fundingAmount ?? DEFAULT_CHANNEL_FUNDING;
    onProgress?.("connecting");
    const candidates = config.peer
      ? [{ pubkey: normalizeFiberPubkey(config.peer), nodeName: "selected peer" }]
      // The official peers' minimums are in CKB, so any of them will do for a token channel.
      : await prepareCkbChannel(config.udtTypeScript ? ANY_FUNDING : fundingAmount);
    let lastAbort: unknown;
    for (const candidate of candidates) {
      try {
        onProgress?.("negotiating");
        const result = await openFundedChannel({
          pubkey: normalizeFiberPubkey(candidate.pubkey),
          funding_amount: `0x${fundingAmount.toString(16)}`,
          public: config.public ?? true,
          ...(config.udtTypeScript ? { funding_udt_type_script: config.udtTypeScript } : {}),
          funding_fee_rate: config.fundingFeeRate === undefined ? undefined : toHex(config.fundingFeeRate),
          commitment_fee_rate: config.commitmentFeeRate === undefined ? undefined : toHex(config.commitmentFeeRate),
        }, onProgress);
        onProgress?.("broadcasting");
        return result;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (!shouldDiagnoseFundingAbortError(message)) throw error;
        lastAbort = error;
      }
    }
    preparedPeers = undefined;
    preparedFundingAmount = undefined;
    throw new Error("Available Fiber peers declined the channel funding request", { cause: lastAbort });
  }

  async function getCkbBalance(): Promise<bigint> {
    const address = await fundingSigner.getRecommendedAddressObj();
    return getLockBalance(address.script);
  }

  /**
   * The node's channels, corrected by what the in-page watchtower has seen on-chain: a channel whose funding cell a
   * force close has spent isn't ready and has nothing to send, whatever the node still says, and stays listed as
   * closing until nothing is left to claim (channel-closures.ts).
   */
  async function getChannels(options?: { includeClosed?: boolean }): Promise<KeyWayChannel[]> {
    // Right after a start the watchtower may not have looked yet; give its first pass a moment, FIRST_WATCH_WAIT
    // from the start at most, however many lists are asked for meanwhile.
    const first = firstWatch;
    const wait = first ? first.until - Date.now() : 0;
    if (first && wait > 0) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      await Promise.race([first.pass, new Promise((resolve) => { timer = setTimeout(resolve, wait); })]);
      clearTimeout(timer);
    }
    // Closed ones too: the node calls a force-closed channel closed while the user's share is still to be claimed.
    const { channels } = await node.listChannels({ include_closed: true });
    const seen: ChannelClosure[] = await closures.list().catch((error) => {
      console.warn("[keyway] could not read what the watchtower has seen; showing the node's own channel states", error);
      return [];
    });
    return presentChannels(channels.map((channel) => normalizeChannel(channel)), seen, options?.includeClosed ?? false);
  }

  async function closeChannel(channelId: ChannelId, closeOptions?: { force?: boolean; feeRate?: bigint }): Promise<void> {
    try {
      await fiberNode.shutdownChannel({
        channel_id: channelId,
        ...(closeOptions?.force ? { force: true } : {}),
        ...(closeOptions?.feeRate === undefined ? {} : { fee_rate: toHex(closeOptions.feeRate) }),
      });
    } catch (error) {
      throw toKeyWayError(error, "CHANNEL_FAILED");
    }
  }

  async function estimatePayment(params: Omit<SendPaymentParams, "dry_run">): Promise<PaymentEstimate> {
    try {
      const payment = await node.sendPayment({ ...params, dry_run: true });
      return { routable: true, fee: BigInt(payment.fee) };
    } catch (error) {
      return { routable: false, error: toKeyWayError(error, "PAYMENT_FAILED") };
    }
  }

  async function sendPayment(params: SendPaymentParams) {
    try {
      return await fiberNode.sendPayment(params);
    } catch (error) {
      throw toKeyWayError(error, "PAYMENT_FAILED");
    }
  }

  // The same method table as hosted nodes, applied in the page because this node runs here.
  const fiberNode = createFiberNode(async (method, input) => {
    if (!node.isRunning) throw new Error("Start Fiber before using the node");
    const params = freeFiberParams(method, input, network);
    switch (method) {
      case "nodeInfo": return node.nodeInfo();
      case "listPeers": return node.listPeers();
      case "listPayments": return listLoggedPayments(await paymentLog.hashes(), params as ListPaymentsParams, (query) => node.getPayment(query));
      default: return (node[method] as (params: unknown) => Promise<unknown>).call(node, params);
    }
  }, async (method, input) => {
    if (!node.isRunning) throw new Error("Start Fiber before using the node");
    const params = paymentFiberParams(method, input, network);
    const run = (next: Record<string, unknown>) => (node[method] as (params: unknown) => Promise<{ payment_hash: string; fee: string }>).call(node, next);
    if (params.dry_run === true) return run(params);
    // The node runs in this page, so there is no server to count this payment or ask for an email code.
    if (options.approveFiberPayment) {
      const { preview } = await describePayment(method, params, { parseInvoice: (invoice) => node.parseInvoice({ invoice }), dryRun: run });
      if (!await options.approveFiberPayment({ ...preview, requiresEmailCode: false })) throw new Error("The payment was not approved");
    }
    const payment = await run(params);
    // Browser nodes have no payment history of their own; failing to log never fails the payment.
    await paymentLog.record(payment.payment_hash).catch(() => undefined);
    return payment;
  }, createFiberActions({
    listChannels: (params) => node.listChannels(params),
    act: (method, params) => {
      if (!node.isRunning) throw new Error("Start Fiber before using the node");
      return (node[method] as (params: unknown) => Promise<unknown>).call(node, params);
    },
  }, () => options.approvals?.() ?? {}), (input) => {
    const params = approveFiberParams("openChannelWithExternalFunding", input) as unknown as KeyWayFundingParams;
    return openFundedChannel(params).then(({ channelId, fundingTxHash }) => ({ channelId, fundingTxHash }));
  });

  return {
    node: fiberNode,
    start,
    stop,
    stopForLogout,
    /**
     * Whether this page still holds the device. After a failed `stopForLogout()` it does when the logout stopped
     * before letting go (e.g. KeyWay's watchtower or the backup upload was unreachable): `start()` then brings the
     * node back on the same device lease, and the next `stopForLogout()` retries the delivery and the backup.
     */
    holdsDevice: lifecycle.holdsDevice,
    nodeInfo: () => node.nodeInfo(),
    connectPeer: node.connectPeer.bind(node),
    listPeers: node.listPeers.bind(node),
    listChannels: node.listChannels.bind(node),
    getChannels,
    shutdownChannel: node.shutdownChannel.bind(node),
    closeChannel,
    graphNodes: node.graphNodes.bind(node),
    graphChannels: node.graphChannels.bind(node),
    waitForChannelReady: node.waitForChannelReady.bind(node),
    newInvoice: (params: Omit<NewInvoiceParams, "currency"> & { currency?: NewInvoiceParams["currency"] }) => fiberNode.newInvoice(params),
    getInvoice: node.getInvoice.bind(node),
    parseInvoice: node.parseInvoice.bind(node),
    estimatePayment,
    sendPayment,
    buildRouter: node.buildRouter.bind(node),
    sendPaymentWithRouter: node.sendPaymentWithRouter.bind(node),
    getPayment: node.getPayment.bind(node),
    waitForPayment: node.waitForPayment.bind(node),
    openFundedChannel,
    prepareCkbChannel,
    activateCkbChannel,
    getCkbBalance,
    openChannelWithExternalFunding: node.openChannelWithExternalFunding.bind(node),
    submitSignedFundingTx: node.submitSignedFundingTx.bind(node),
    /** What KeyWay's watchtower knows about this account's channels and how each one stands on-chain. */
    watchtowerStatus: () => api.watchtower<{ channels: WatchtowerChannelStatus[] }>(options.authToken, { operation: "status" }),
    /** Channels with an update KeyWay's watchtower doesn't have yet; closing the tab now leaves that state unwatched. */
    watchtowerPending: () => remoteWatchtower.pending(),
    get state() { return node.state; },
    get isRunning() { return node.isRunning; },
  };
}

export function normalizeChannel(channel: Channel): KeyWayChannel {
  const canSend = BigInt(channel.local_balance);
  const canReceive = BigInt(channel.remote_balance);
  const typeScript = (channel as Channel & { funding_udt_type_script?: Script | null }).funding_udt_type_script;
  const state = String(channel.state.state_name);
  const status: KeyWayChannelStatus = state === "CHANNEL_READY" ? "ready"
    : state.includes("SHUTDOWN") || state.includes("SHUTTING") || state.includes("CLOSING") ? "closing"
    : state.includes("CLOSED") ? "closed"
    : state.includes("FAILED") ? "failed"
    : state.includes("NEGOTIATING") || state.includes("AWAITING") ? "pending"
    : "unknown";
  return {
    id: channel.channel_id,
    peer: channel.pubkey,
    status,
    asset: typeScript ? { kind: "token", typeScript } : { kind: "ckb" },
    canSend,
    canReceive,
    capacity: canSend + canReceive,
    public: channel.is_public,
    raw: channel,
  };
}

function toHex(value: bigint): `0x${string}` {
  return `0x${value.toString(16)}`;
}

export type KeyWay = ReturnType<typeof createKeyWay>;

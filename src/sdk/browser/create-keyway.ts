import * as ccc from "@ckb-ccc/core";
import {
  createCccExternalFundingResolver,
  FiberBrowserNode,
  openChannelWithExternalFundingFlow,
  shouldDiagnoseFundingAbortError,
  type Channel,
  type ChannelId,
  type NewInvoiceParams,
  type OpenChannelWithExternalFundingParams,
  type Script,
  type SendPaymentParams,
} from "@fiber-pay/sdk/browser";
import { KeyWayCredentialProvider, type FiberKeyLoader } from "./credential-provider";
import { acquireDeviceLock, type DeviceLock } from "./device-lock";
import { acquireDeviceLease, type DeviceLease } from "./device-lease";
import { serializeCccTransactionForRpc } from "./ccc-transaction";
import { fundingLockCellDeps, FUNDING_LOCK_KNOWN_SCRIPTS, type KeyWayRecovery } from "./account-lock";
import { getLockBalance } from "./ckb-balance";
import { RemoteCkbSigner, type ApproveFiberChannelOpen } from "./remote-ckb-signer";
import { getDeviceIdHash, markChannelOpened } from "./bootstrap";
import { ANY_FUNDING, connectChannelPeers, type ChannelPeer } from "./channel-peers";
import { normalizeFiberPubkey } from "./fiber-pubkey";
import { KeyWayApiClient } from "./api-client";
import { createEncryptedNodeBackup, restoreEncryptedNodeBackup } from "./node-backup";
import { backUpBeforeLogout, restoreBeforeStart } from "./node-migration";
import { toKeyWayError, type KeyWayError } from "./keyway-error";
import { freeFiberParams, fundingFeeRate, paymentFiberParams } from "./fiber-methods";
import { describePayment, type ApproveFiberPayment } from "./fiber-payment";
import { createFiberActions, type FiberActionApprovals } from "./fiber-actions";
import { approveFiberParams } from "./fiber-methods";
import { createFiberNode, listLoggedPayments, type ListPaymentsParams } from "./fiber-node";
import { createPaymentLog } from "./payment-log";
import { sweepSettlement } from "./settlement-sweep";
import { fiberWasmFactory } from "./fiber-wasm";
import { listenForWatchtowerCalls } from "./watchtower-bridge";
import { openWatchtowerStore } from "./watchtower-store";
import { settleChannel } from "./watchtower-settle";
import { createRemoteWatchtower, remoteWatchUpdate, updatesForStoredChannel } from "./watchtower-remote";
import { createFeeReserve, FEE_RESERVE, needsFeeReserve } from "./fee-reserve";
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
  loadFiberKey: (leaseId: string) => ReturnType<FiberKeyLoader>;
  network?: "testnet" | "mainnet";
  apiClient?: KeyWayApiClient;
  restoreRequired?: boolean;
  onLeaseLost?: (error: Error) => void;
  onFiberStartup?: (stage: BrowserNodeStage) => void;
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
  /** What the user can still send through this channel, in the asset's smallest unit (shannons for CKB). */
  canSend: bigint;
  /** What the user can still receive through this channel. */
  canReceive: bigint;
  /** The channel's total size: canSend plus canReceive. */
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

export function createKeyWay(options: CreateKeyWayOptions) {
  let deviceLease: DeviceLease | undefined;
  const credential = new KeyWayCredentialProvider(options.identifier, () => {
    if (!deviceLease) throw new Error("An active device lease is required");
    return options.loadFiberKey(deviceLease.leaseId);
  });
  const network = options.network ?? "testnet";
  const databasePrefix = `/wasm-${options.identifier}`;
  // Fiber's browser build has no watchtower, so its watchtower events come to the page (watchtower-bridge.ts).
  const watchtowerChannel = `keyway-watchtower-${ccc.hexFrom(crypto.getRandomValues(new Uint8Array(16))).slice(2)}`;
  const watchtower = openWatchtowerStore(databasePrefix);
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
  });
  let deviceLock: DeviceLock | undefined;
  const api = options.apiClient ?? new KeyWayApiClient();
  let activationProgress: ChannelOpenProgress | undefined;
  let openingPeer: string | undefined;
  let openingWithReserve = false;
  let preparedPeers: Promise<ChannelPeer[]> | undefined;
  let preparedFundingAmount: bigint | undefined;
  const fundingSigner = new RemoteCkbSigner(options.authToken, options.ckbPublicKey, async (preview) => {
    activationProgress?.("confirming");
    const approved = await options.approveFiberChannelOpen({
      ...preview,
      ...(openingPeer ? { peer: openingPeer } : {}),
      ...(openingWithReserve ? { feeReserveCkb: ccc.fixedPointToString(FEE_RESERVE) } : {}),
    });
    if (approved) activationProgress?.("signing");
    return approved;
  }, undefined, api, options.recovery, (error) => options.approvals?.().settled?.("funding", error));
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
  // The node settles force-closed channels with the key derived from the Fiber key, so the reserve goes there.
  const feeReserve = createFeeReserve({
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
  const paymentLog = createPaymentLog(databasePrefix);
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

  /** Bumped by every stop, so a start that a stop overtook (e.g. while the key was loading) can undo itself. */
  let stopGeneration = 0;
  /** True while start() is running: a stop then leaves the bridge to start(), which closes it after the node stops. */
  let starting = false;

  async function start() {
    if (node.isRunning) return node.nodeInfo();
    const generation = stopGeneration;
    if (typeof window !== "undefined" && window.crossOriginIsolated !== true) {
      throw toKeyWayError(new Error("Cross-origin isolated browser context is required"));
    }
    options.onFiberStartup?.("claiming_device");
    deviceLock = await acquireDeviceLock(options.identifier);
    try {
      starting = true;
      deviceLease = await acquireDeviceLease(options.authToken, api, (cause) => {
        const error = cause instanceof Error ? cause : new Error("The active KeyWay device lease expired");
        void stop().finally(() => options.onLeaseLost?.(error));
      });
      if (restoreRequired) {
        options.onFiberStartup?.("restoring_channels");
        await restoreClaimedBackup();
      }
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
      const info = await node.start();
      if (generation !== stopGeneration) {
        // @fiber-pay/sdk's stop() doesn't cancel a start that is still unlocking the key, so the node can come up
        // after stop() returned. Stop it again rather than leave it (and its timers) running without a lease.
        await node.stop().catch(() => undefined);
        throw toKeyWayError(new Error("The Fiber node was stopped while it was starting"));
      }
      startSweeping();
      return info;
    } catch (error) {
      starting = false;
      await releaseGuards();
      throw error;
    } finally {
      starting = false;
    }
  }

  /**
   * Stopgap until Fiber pays force-closed channels to their close address: the node settles to a key
   * derived from the user's Fiber key, and this moves anything there to the user's own address.
   */
  let sweepTimer: ReturnType<typeof setInterval> | undefined;
  async function sweepNow() {
    if (!node.isRunning || !credential.isUnlocked()) return;
    const key = await credential.getCkbSecretKey();
    try {
      const destination = (await fundingSigner.getRecommendedAddressObj()).script;
      const { channels } = await node.listChannels({ include_closed: true });
      await sweepSettlement(fundingSigner.client, ccc.hexFrom(key), destination, needsFeeReserve(channels) ? FEE_RESERVE : 0n);
    } finally {
      key.fill(0);
    }
  }
  function startSweeping() {
    // A stop() that ran while start() was finishing leaves the node stopped: don't start the timers then.
    if (!node.isRunning) return;
    void sweepNow().catch(() => undefined);
    sweepTimer ??= setInterval(() => void sweepNow().catch(() => undefined), 10 * 60_000);
    watchStopped = false;
    void watchNow().catch(() => undefined);
    watchTimer ??= setInterval(() => void watchNow().catch(() => undefined), WATCH_INTERVAL);
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
  // Statuses after which the channel needs nothing more from the watchtower. A cooperative close is left to
  // Fiber's own remove_watch_channel, so an unexpected closing transaction never drops the data.
  const DONE = new Set(["settled", "the user's share is already claimed", "the user has no share in this channel"]);
  function watchNow(): Promise<void> {
    if (watchPass || watchStopped || !node.isRunning || !credential.isUnlocked()) return watchPass ?? Promise.resolve();
    watchPass = watchOnce().finally(() => { watchPass = undefined; });
    return watchPass;
  }
  async function watchOnce() {
    {
      // The 10-minute sweep (and the one at start) also picks up claims whose follow-up sweep was missed.
      for (const txHash of [...claimsToSweep]) {
        if (watchStopped) return;
        const status = (await fundingSigner.client.getTransaction(txHash).catch(() => undefined))?.status;
        if (watchStopped) return;
        if (status !== "committed") continue;
        claimsToSweep.delete(txHash);
        await sweepNow().catch((error) => console.warn("[keyway] could not sweep the claimed funds yet", error));
      }
      if (watchStopped) return;
      const watched = await watchtower.list();
      if (watched.length === 0 || watchStopped) return;
      const { channels } = await node.listChannels({ include_closed: true });
      if (watchStopped) return;
      const key = await credential.getCkbSecretKey();
      try {
        for (const channel of watched) {
          if (watchStopped) break;
          const raw = channels.find((item) => String(item.channel_id).toLowerCase() === channel.channelId);
          const outpoint = raw?.channel_outpoint ? String(raw.channel_outpoint) : undefined;
          if (!outpoint) {
            if (watchStatus.get(channel.channelId) !== "missing") {
              watchStatus.set(channel.channelId, "missing");
              console.warn(`[keyway] watchtower: channel ${channel.channelId} is not in the node's channel list; it can't be checked until it is`);
            }
            continue;
          }
          try {
            const result = await settleChannel({
              client: fundingSigner.client, network, channel, nodeKey: ccc.hexFrom(key),
              ref: { channelId: channel.channelId, fundingOutPoint: ccc.OutPoint.decode(outpoint) },
            });
            if (watchStatus.get(channel.channelId) !== result.status) {
              watchStatus.set(channel.channelId, result.status);
              console.info(`[keyway] watchtower: channel ${channel.channelId}: ${result.status}${result.txHash ? ` ${result.txHash}` : ""}`);
            }
            if (result.txHash) {
              claimsToSweep.add(result.txHash);
            } else if (DONE.has(result.status)) {
              await watchtower.remove(channel.channelId);
            }
          } catch (error) {
            console.warn(`[keyway] watchtower: channel ${channel.channelId} could not be settled yet`, error);
          }
        }
      } finally {
        key.fill(0);
      }
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
    stopGeneration++;
    if (sweepTimer) clearInterval(sweepTimer);
    sweepTimer = undefined;
    await stopWatching();
    try {
      await node.stop();
    } finally {
      preparedPeers = undefined;
      preparedFundingAmount = undefined;
      await releaseGuards();
    }
  }

  async function stopForLogout() {
    stopGeneration++;
    if (sweepTimer) clearInterval(sweepTimer);
    sweepTimer = undefined;
    await stopWatching();
    if (!deviceLease) {
      await stop();
      remoteWatchtower.stop();
      return;
    }
    const lease = deviceLease;
    const deviceIdHash = await getDeviceIdHash();
    await backUpBeforeLogout({
      loadFiberKey: () => options.loadFiberKey(lease.leaseId),
      stopNode: async () => {
        await node.stop();
        await closeWatchtowerBridge();
      },
      createBackup: (fiberKey) => createEncryptedNodeBackup(databasePrefix, fiberKey),
      saveBackup: (backup) => api.saveNodeBackup(options.authToken, {
        deviceIdHash,
        leaseId: lease.leaseId,
        backup,
      }),
      releaseOwnership: releaseGuards,
    });
    // The session ends with the logout, so nothing more can reach KeyWay's watchtower from this page.
    remoteWatchtower.stop();
  }

  async function restoreClaimedBackup() {
    if (!deviceLease) throw new Error("An active device lease is required to restore Fiber state");
    const deviceIdHash = await getDeviceIdHash();
    const leaseId = deviceLease.leaseId;
    await restoreBeforeStart({
      loadFiberKey: () => options.loadFiberKey(leaseId),
      loadBackup: () => api.loadNodeBackup(options.authToken, { deviceIdHash, leaseId }),
      restoreBackup: (backup, fiberKey) => restoreEncryptedNodeBackup(backup, databasePrefix, fiberKey),
      confirmRestore: (generation) => api.confirmNodeBackup(options.authToken, {
        deviceIdHash,
        leaseId,
        generation,
      }),
    });
    restoreRequired = false;
  }

  async function releaseGuards() {
    // The node has stopped by now, so it sends no more watchtower events. A start() still in progress may yet bring
    // the node up (and then stop it); it calls this again once it has, and the bridge closes then.
    if (!starting) {
      await closeWatchtowerBridge();
      // Give KeyWay's watchtower whatever is still queued before the page lets go of the node.
      await Promise.race([remoteWatchtower.flush(), new Promise((resolve) => setTimeout(resolve, 10_000))]);
      if (typeof window !== "undefined") window.removeEventListener("beforeunload", warnBeforeUnload);
      watchtower.close();
    }
    const lease = deviceLease;
    const lock = deviceLock;
    deviceLease = undefined;
    deviceLock = undefined;
    await Promise.allSettled([lease?.release(), lock?.release()]);
  }

  async function openFundedChannel(params: KeyWayFundingParams) {
    if (!node.isRunning) throw new Error("Start the Fiber node before opening a channel");
    openingPeer = params.pubkey;
    openingWithReserve = await feeReserve.needed();
    const funding = await resolveExternalFunding(undefined);
    const result = await openChannelWithExternalFundingFlow({
      node,
      params: {
        ...params,
        funding_fee_rate: fundingFeeRate(params.funding_fee_rate, funding.fundingLockScript),
        shutdown_script: funding.shutdownScript,
        funding_lock_script: funding.fundingLockScript,
        funding_lock_script_cell_deps: funding.fundingLockScriptCellDeps,
      },
      signFundingTx: funding.signFundingTx,
    });
    await markChannelOpened(options.authToken, api);
    const feeReserveTxHash = openingWithReserve ? await feeReserve.send(result.fundingTxHash) : undefined;
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
    activationProgress = onProgress;
    activationProgress?.("connecting");
    try {
      const candidates = config.peer
        ? [{ pubkey: normalizeFiberPubkey(config.peer), nodeName: "selected peer" }]
        // The official peers' minimums are in CKB, so any of them will do for a token channel.
        : await prepareCkbChannel(config.udtTypeScript ? ANY_FUNDING : fundingAmount);
      let lastAbort: unknown;
      for (const candidate of candidates) {
        try {
          activationProgress?.("negotiating");
          const result = await openFundedChannel({
            pubkey: normalizeFiberPubkey(candidate.pubkey),
            funding_amount: `0x${fundingAmount.toString(16)}`,
            public: config.public ?? true,
            ...(config.udtTypeScript ? { funding_udt_type_script: config.udtTypeScript } : {}),
            funding_fee_rate: config.fundingFeeRate === undefined ? undefined : toHex(config.fundingFeeRate),
            commitment_fee_rate: config.commitmentFeeRate === undefined ? undefined : toHex(config.commitmentFeeRate),
          });
          activationProgress?.("broadcasting");
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
    } finally {
      activationProgress = undefined;
    }
  }

  async function getCkbBalance(): Promise<bigint> {
    const address = await fundingSigner.getRecommendedAddressObj();
    return getLockBalance(address.script);
  }

  async function getChannels(options?: { includeClosed?: boolean }): Promise<KeyWayChannel[]> {
    const { channels } = await node.listChannels({ include_closed: options?.includeClosed ?? false });
    return channels.map(normalizeChannel);
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

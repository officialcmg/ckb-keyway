"use client";

import { useEffect, useRef, useState } from "react";
import { createEvmBackup, createJoyIdBackup, recoveryAccountAddress, type EthereumProvider } from "../browser/account-recovery";
import { getCkbAccountBalance } from "../browser/ckb-balance";
import type { RecoveryBackupProof } from "../browser/recovery-backups";
import type * as ccc from "@ckb-ccc/core";
import type { KeyWay, KeyWayChannel, OpenKeyWayChannelOptions, ChannelOpenProgress } from "../browser/create-keyway";
import { useKeyWayContext } from "./keyway-provider";

export function useCkbWallet() {
  const { authenticated, wallet, signer, error: recoveryError, enableRecovery } = useKeyWayContext();
  const [balance, setBalance] = useState<bigint>();
  const [balanceError, setBalanceError] = useState<Error>();
  const [refreshing, setRefreshing] = useState(false);
  const generation = useRef(0);

  async function refreshBalance() {
    if (!wallet) throw new Error("Recover the CKB account before reading its balance");
    const run = generation.current;
    setRefreshing(true);
    try {
      const next = await getCkbAccountBalance(wallet.litPublicKey, wallet.recovery);
      if (run === generation.current) { setBalance(next); setBalanceError(undefined); }
      return next;
    } catch (cause) {
      const error = cause instanceof Error ? cause : new Error("Could not read CKB balance");
      if (run === generation.current) setBalanceError(error);
      throw error;
    } finally {
      if (run === generation.current) setRefreshing(false);
    }
  }

  useEffect(() => {
    ++generation.current;
    setBalance(undefined);
    setBalanceError(undefined);
    setRefreshing(false);
    if (wallet) void refreshBalance().catch(() => undefined);
    return () => { ++generation.current; };
  }, [wallet?.litPublicKey, wallet?.recovery?.omnilockArgs]);

  return {
    status: !authenticated ? "disconnected" as const : !wallet ? recoveryError ? "error" as const : "loading" as const : "ready" as const,
    /** A CCC signer for this account. Every transaction and message is shown to the user before signing. */
    signer,
    address: wallet?.ckbAddress,
    /** The account's address from before it turned recovery on, if it has. */
    legacyAddress: wallet?.recovery?.legacyAddress,
    /** The account's compressed secp256k1 public key. */
    publicKey: wallet?.litPublicKey,
    balance,
    refreshing,
    refreshBalance,
    error: wallet ? balanceError : recoveryError,
    /** Opt-in account recovery: backup signers that can recover the account. Turning it on changes the address. */
    recovery: {
      status: wallet?.recovery ? "on" as const : "off" as const,
      backups: wallet?.recovery?.backups ?? [],
      legacyAddress: wallet?.recovery?.legacyAddress,
      /** Turns recovery on with these backups, after the user approves and enters the emailed code. */
      enable: async (backups: RecoveryBackupProof[]) => {
        const result = await enableRecovery(backups);
        void refreshBalance().catch(() => undefined);
        return result;
      },
      /** Asks an injected EVM wallet (`window.ethereum` by default) to sign up as a backup. */
      createEvmBackup: async (ethereum?: EthereumProvider) => {
        if (!wallet) throw new Error("Recover the CKB account before adding a backup");
        return createEvmBackup(await recoveryAccountAddress(wallet.litPublicKey), ethereum);
      },
      /** Asks a CCC JoyID signer (from @ckb-ccc/joy-id) to sign up as a backup with its passkey. */
      createJoyIdBackup: async (joyIdSigner: ccc.Signer) => {
        if (!wallet) throw new Error("Recover the CKB account before adding a backup");
        return createJoyIdBackup(await recoveryAccountAddress(wallet.litPublicKey, joyIdSigner.client), joyIdSigner);
      },
    },
  };
}

export function useFiber() {
  const { connection, startFiber, stopFiber, fiberStarting, fiberError, fiberNode, fiberStartupStage } = useKeyWayContext();
  const connectionRef = useRef(connection);
  connectionRef.current = connection;
  const [channels, setChannels] = useState<KeyWayChannel[]>([]);
  const [channelError, setChannelError] = useState<Error>();
  const generation = useRef(0);

  function client() {
    if (!connectionRef.current) throw new Error("Start Fiber before using channels or payments");
    return connectionRef.current.keyway;
  }

  async function start() {
    const next = await startFiber();
    connectionRef.current = next;
  }

  async function stop() {
    await stopFiber();
    connectionRef.current = undefined;
  }

  async function refreshChannels() {
    const run = generation.current;
    try {
      const next = await client().getChannels();
      if (run === generation.current) { setChannels(next); setChannelError(undefined); }
      return next;
    } catch (cause) {
      const error = cause instanceof Error ? cause : new Error("Could not read Fiber channels");
      if (run === generation.current) setChannelError(error);
      throw error;
    }
  }

  useEffect(() => {
    ++generation.current;
    setChannels([]);
    setChannelError(undefined);
    if (!connection) return;
    void refreshChannels().catch(() => undefined);
    const timer = setInterval(() => void refreshChannels().catch(() => undefined), 10_000);
    return () => { ++generation.current; clearInterval(timer); };
  }, [connection]);

  async function openChannel(options: OpenKeyWayChannelOptions = {}, onProgress?: ChannelOpenProgress) {
    const current = client();
    const result = await current.activateCkbChannel(options, onProgress);
    await current.waitForChannelReady(result.channelId, { timeout: 180_000, interval: 3_000 });
    await refreshChannels().catch(() => undefined);
    return result;
  }

  async function closeChannel(...args: Parameters<KeyWay["closeChannel"]>) {
    await client().closeChannel(...args);
    await refreshChannels().catch(() => undefined);
  }

  async function payInvoice(invoice: string, options: Omit<Parameters<KeyWay["sendPayment"]>[0], "invoice"> = {}) {
    const current = client();
    const payment = await current.sendPayment({ ...options, invoice });
    const result = await current.waitForPayment(payment.payment_hash, { timeout: 120_000 });
    if (result.status !== "Success") throw new Error(result.failed_error ?? "Fiber payment failed");
    await refreshChannels().catch(() => undefined);
    return result;
  }

  return {
    status: fiberStarting ? "starting" as const : connection ? "running" as const : fiberError ? "error" as const : "stopped" as const,
    /** Where the node runs: "hosted" on KeyWay's servers, or "browser" in this page. */
    fiberNode,
    /** The current step while the node starts. */
    startupStage: fiberStartupStage,
    start,
    stop,
    /** The user's Fiber node, with Fiber's own method names. Available once `status` is "running". */
    node: connection?.keyway.node,
    channels,
    refreshChannels,
    openChannel,
    closeChannel,
    createInvoice: (...args: Parameters<KeyWay["newInvoice"]>) => client().newInvoice(...args),
    getInvoice: (...args: Parameters<KeyWay["getInvoice"]>) => client().getInvoice(...args),
    parseInvoice: (...args: Parameters<KeyWay["parseInvoice"]>) => client().parseInvoice(...args),
    estimatePayment: (...args: Parameters<KeyWay["estimatePayment"]>) => client().estimatePayment(...args),
    payInvoice,
    error: fiberError ?? channelError,
  };
}

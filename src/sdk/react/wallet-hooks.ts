"use client";

import { useEffect, useRef, useState } from "react";
import { getCkbAccountBalance } from "../browser/ckb-balance";
import type { KeyWay, KeyWayChannel, OpenKeyWayChannelOptions, ActivationProgress } from "../browser/create-keyway";
import { useKeyWayContext } from "./keyway-provider";

export function useCkbWallet() {
  const { authenticated, wallet, error: recoveryError } = useKeyWayContext();
  const [balance, setBalance] = useState<bigint>();
  const [balanceError, setBalanceError] = useState<Error>();
  const [refreshing, setRefreshing] = useState(false);
  const generation = useRef(0);

  async function refreshBalance() {
    if (!wallet) throw new Error("Recover the CKB account before reading its balance");
    const run = generation.current;
    setRefreshing(true);
    try {
      const next = await getCkbAccountBalance(wallet.litPublicKey);
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
  }, [wallet?.litPublicKey]);

  return {
    status: !authenticated ? "disconnected" as const : !wallet ? recoveryError ? "error" as const : "recovering" as const : "ready" as const,
    wallet,
    address: wallet?.ckbAddress,
    balance,
    refreshing,
    refreshBalance,
    error: wallet ? balanceError : recoveryError,
  };
}

export function useFiber() {
  const { connection, connect, disconnect, fiberStarting, fiberError, nodeMode } = useKeyWayContext();
  const connectionRef = useRef(connection);
  connectionRef.current = connection;
  const [channels, setChannels] = useState<KeyWayChannel[]>([]);
  const [channelError, setChannelError] = useState<Error>();
  const generation = useRef(0);

  function client() {
    if (!connectionRef.current) throw new Error("Connect Fiber before using channels or payments");
    return connectionRef.current.keyway;
  }

  async function connectFiber() {
    const next = await connect();
    connectionRef.current = next;
    return next;
  }

  async function disconnectFiber() {
    await disconnect();
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

  async function openChannel(options: OpenKeyWayChannelOptions = {}, onProgress?: ActivationProgress) {
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
    status: fiberStarting ? "connecting" as const : connection ? "connected" as const : fiberError ? "error" as const : "disconnected" as const,
    nodeMode,
    connect: connectFiber,
    disconnect: disconnectFiber,
    channels,
    refreshChannels,
    openChannel,
    closeChannel,
    createInvoice: (...args: Parameters<KeyWay["newInvoice"]>) => client().newInvoice(...args),
    getInvoice: (...args: Parameters<KeyWay["getInvoice"]>) => client().getInvoice(...args),
    parseInvoice: (...args: Parameters<KeyWay["parseInvoice"]>) => client().parseInvoice(...args),
    preflightPayment: (...args: Parameters<KeyWay["preflightPayment"]>) => client().preflightPayment(...args),
    payInvoice,
    error: fiberError ?? channelError,
    // Raw Fiber access is an escape hatch, not required for normal payments.
    connection,
  };
}

import * as ccc from "@ckb-ccc/core";
import { cccScriptToFiberScript, getLockBalanceShannons } from "@fiber-pay/sdk/browser";
import { adminListCapacity, currentLock, type KeyWayRecovery } from "./account-lock";

const CKB_RPC_URL = "https://testnet.ckbapp.dev/";

/** Read the embedded account's on-chain balance without connecting Fiber. */
export async function getCkbAccountBalance(publicKey: string, recovery?: KeyWayRecovery): Promise<bigint> {
  const client = new ccc.ClientPublicTestnet();
  return getLockBalance(client, await currentLock(client, publicKey, recovery), recovery);
}

/** CKB under the account's current lock, not counting the AdminList cell, which isn't spendable balance. */
export async function getLockBalance(
  client: ccc.Client,
  lock: ccc.Script,
  recovery?: KeyWayRecovery,
  readBalance = (script: ccc.Script) => getLockBalanceShannons(CKB_RPC_URL, cccScriptToFiberScript(script)),
): Promise<bigint> {
  const [balance, reserved] = await Promise.all([readBalance(lock), adminListCapacity(client, lock, recovery)]);
  return balance - reserved;
}

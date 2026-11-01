import * as ccc from "@ckb-ccc/core";
import { cccScriptToFiberScript, getLockBalanceShannons } from "@fiber-pay/sdk/browser";
import { currentLock, type KeyWayRecovery } from "./account-lock";

const CKB_RPC_URL = "https://testnet.ckbapp.dev/";

/** Read the embedded account's on-chain balance without connecting Fiber. */
export async function getCkbAccountBalance(publicKey: string, recovery?: KeyWayRecovery): Promise<bigint> {
  const client = new ccc.ClientPublicTestnet();
  return getLockBalance(await currentLock(client, publicKey, recovery));
}

/** CKB under the account's current lock. The AdminList has its own lock, so it is never counted. */
export async function getLockBalance(
  lock: ccc.Script,
  readBalance = (script: ccc.Script) => getLockBalanceShannons(CKB_RPC_URL, cccScriptToFiberScript(script)),
): Promise<bigint> {
  return readBalance(lock);
}

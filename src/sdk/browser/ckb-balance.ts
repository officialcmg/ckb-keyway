import * as ccc from "@ckb-ccc/core";
import { cccScriptToFiberScript, getLockBalanceShannons } from "@fiber-pay/sdk/browser";

/** Read the embedded account's on-chain balance without connecting Fiber. */
export async function getCkbAccountBalance(publicKey: string): Promise<bigint> {
  const account = new ccc.SignerCkbPublicKey(new ccc.ClientPublicTestnet(), publicKey);
  const address = await account.getRecommendedAddressObj();
  return getLockBalanceShannons("https://testnet.ckbapp.dev/", cccScriptToFiberScript(address.script));
}

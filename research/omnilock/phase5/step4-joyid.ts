// Phase 5, step 4: rescue everything at the KeyWay address to D2 with the JoyID-style backup J1, through the
// rescue page's module (src/rescue/rescue.ts) and nothing else: a public node, the address, the backup.
import { openRescueAccount, planRescue, rescueClient, rescueEntryForJoyId, sendRescue, signRescueWithJoyId } from "../../../src/rescue/rescue.ts";
import { joyIdSigner, loadKeys, loadState, saveState, secpAddress, waitCommitted } from "./lib.ts";

const keys = loadKeys();
const state = loadState();
const client = rescueClient("testnet");
const account = await openRescueAccount(client, state.newAddress);
console.log("backups", account.entries.map(({ backup }) => `${backup.kind} ${backup.address}`));
console.log("ckb", account.ckb.toString(), "token cells", account.tokenCkb.toString(), account.tokens.map(({ amountText }) => amountText));
const prompts: string[] = [];
const signer = await joyIdSigner(keys.J1, (text) => prompts.push(text));
const entry = rescueEntryForJoyId(account, await signer.getRecommendedAddress());
const plan = await planRescue(client, account, entry, await secpAddress(keys.D2));
console.log("plan: ckb", plan.ckb.toString(), "tokens", plan.tokens.map(({ amountText, capacity }) => `${amountText} in ${capacity}`), "fee", plan.fee.toString());
const signed = await signRescueWithJoyId(client, account, plan, signer);
console.log("passkey prompts", prompts.length, JSON.stringify(prompts[0]), "size", signed.toBytes().length + 4);
const hash = await sendRescue(client, signed);
console.log("rescue tx", hash);
await waitCommitted(hash);
saveState({ rescueJoyId: hash });
console.log("committed");
process.exit(0);

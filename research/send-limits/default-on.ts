// Live CKB testnet proof that send limits are on by default (research/send-limits/README.md).
//
//   KEYWAY_LIVE_KEYS=/path/keys.json KEYWAY_FUNDER_KEYS=/path/funder.json DATABASE_URL=postgres://… \
//     node --import tsx research/send-limits/default-on.ts
//
// keys.json holds one throwaway testnet key, "N", for a fresh account; funder.json a funded testnet key, "F". Neither
// is ever printed. As in live.ts, the policy Action runs unchanged under a stand-in Lit runtime against the live RPC,
// the server's own code runs as in production (in the given Postgres), and the SDK's KeyWaySigner is the client.
// The run: a fresh account's first send asks for the daily limit (offered at 100,000 CKB, edited to 300 CKB here),
// turns limits on with the Lit code, and the send chains on the new cell; later sends ask nothing, and one over the
// amount needs the code.
import { readFileSync } from "node:fs";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1Lock } from "../../src/sdk/browser/account-lock.ts";
import type { KeyWayApiClient } from "../../src/sdk/browser/api-client.ts";
import { KeyWaySigner } from "../../src/sdk/browser/keyway-signer.ts";
import { decodeSendLimitSettings, isSendLimitCell, sendLimitInputIndex } from "../../src/sdk/browser/send-limits.ts";
import { serializeTransaction } from "../../src/server/funding-transaction.ts";
import { sendLimitOffer, signingSettings, transactionSigning, type SigningContext } from "../../src/server/general-signing.ts";
import { loadLitAction } from "../../src/server/lit-actions.ts";
import { litPolicyRunner } from "../../src/server/lit-policy.ts";
import { listPendingTransactions, nodeStatus } from "../../src/server/pending-transactions.ts";
import { sendLimitHead } from "../../src/server/send-limits.ts";
import type { ReadyWallet } from "../../src/server/user-wallet.ts";
import { fakeEthers } from "../../tests/lit-action-fixture.ts";

const CKB = 100_000_000n;
const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
const keys = JSON.parse(readFileSync(process.env.KEYWAY_LIVE_KEYS!, "utf8")) as Record<string, string>;
const funderKeys = JSON.parse(readFileSync(process.env.KEYWAY_FUNDER_KEYS!, "utf8")) as Record<string, string>;
const log = (...parts: unknown[]) => console.log(new Date().toISOString().slice(11, 23), ...parts);
const emails: string[] = [];

function runtime(privateKey: ccc.Hex, source: string) {
  const Lit = { Actions: { getPrivateKey: async () => privateKey, getLitActionPrivateKey: async () => ccc.hexFrom(keccak_256(ccc.bytesFrom(privateKey))) } };
  const fetchVia = async (url: string, init: RequestInit) => {
    if (url === "https://api.resend.com/emails") {
      emails.push(JSON.parse(String(init.body)).text);
      return new Response(JSON.stringify({ id: "logged" }), { status: 200 });
    }
    return fetch(url, init);
  };
  return new Function("Lit", "ethers", "fetch", `${source}\nreturn main;`)(Lit, fakeEthers, fetchVia) as (params: Record<string, unknown>) => Promise<unknown>;
}

const lastCode = () => /Your confirmation code is (\d{8})/.exec(emails[emails.length - 1])![1];

async function waitFor(hash: string, status = "committed") {
  for (let i = 0; i < 90; i++) {
    if ((await client.getTransaction(hash))?.status === status) return;
    await new Promise((resolve) => setTimeout(resolve, 3_000));
  }
  throw new Error(`${hash} wasn't ${status} in time`);
}

async function main() {
  process.env.LIT_USAGE_API_KEY ??= "live-proof";
  process.env.RESEND_API_KEY ??= "re_live_proof_only";
  const privateKey = keys.N as ccc.Hex;
  const publicKey = ccc.hexFrom(secp256k1.getPublicKey(ccc.bytesFrom(privateKey), true));
  const pkpId = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(ccc.bytesFrom(privateKey), false).slice(1)).slice(12));
  const wallet = { version: 1, status: "ready", litPkpId: pkpId, litPublicKey: publicKey, ckbAddress: "", encryptedFiberKey: "", primaryDeviceIdHash: "a".repeat(64), hasOpenedChannel: false, createdAt: "", updatedAt: "" } as unknown as ReadyWallet;
  const user = { id: crypto.randomUUID() };
  const context: SigningContext = {
    user, wallet, appName: "KeyWay live proof",
    email: async () => "fresh@example.com",
    sendEmail: async () => { throw new Error("no server code expected"); },
    rateLimit: async () => ({ allowed: true, retryAfter: null }),
    recordSigning: async () => undefined,
    client,
  };
  const action = runtime(privateKey, await loadLitAction("sign-ckb-transaction"));
  litPolicyRunner.run = async (_config, params) => action(params);

  // KeyWay's HTTP API as the SDK sees it, served by the server's own functions, the offer included.
  const api = {
    signTransaction: (_token: string, body: Record<string, unknown>) => transactionSigning(context, body),
    signingSettings: (_token: string, body: Record<string, unknown>) => signingSettings(context, body),
    pendingTransactions: async () => {
      const pending = await listPendingTransactions(user.id, nodeStatus(client));
      const head = await sendLimitHead(client, wallet, pending);
      const offer = await sendLimitOffer(user, wallet, head, client);
      return JSON.parse(ccc.stringify({ transactions: pending.map(({ transaction }) => serializeTransaction(transaction)), ...(head ? { sendLimit: head } : {}), ...(offer ? { sendLimitOffer: { ckb: offer.ckb.toString() } } : {}) }));
    },
  } as unknown as KeyWayApiClient;

  const secp = await secp256k1Lock(client, publicKey);
  const funder = new ccc.SignerCkbPrivateKey(client, funderKeys.F);
  const back = (await funder.getAddressObjs())[0].script;

  // A fresh account with 700 CKB, as a new user after a faucet claim.
  const fund = ccc.Transaction.from({ outputs: [{ lock: secp, capacity: 700n * CKB }] });
  await fund.completeInputsByCapacity(funder);
  await fund.completeFeeBy(funder, 1_000n);
  const funded = await funder.sendTransaction(fund);
  log(`fresh account ${ccc.Address.fromScript(secp, client).toString()} funded with 700 CKB: ${funded}`);
  await waitFor(funded);

  let offers = 0;
  let codes = 0;
  const signer = new KeyWaySigner("token", publicKey, {
    approveCkbTransaction: (preview) => { log(`  approve: send ${preview.sendingCkb} CKB, code ${preview.requiresEmailCode ? "needed" : "not needed"}`); return true; },
    approveCkbMessage: () => false,
    approveDailyLimit: (offer) => {
      offers++;
      log(`  "Protect your account" dialog: offered ${ccc.fixedPointToString(offer.ckb)} CKB a day; the user edits it to 300 CKB`);
      return 300n * CKB;
    },
    requestEmailCode: async (request) => { codes++; log(`  code prompt (${request.reason}): ${request.codeLength}-digit code sent to ${request.sentTo}`); return lastCode(); },
  }, new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" }), api);

  const send = async (amount: bigint, label: string) => {
    const start = performance.now();
    const tx = ccc.Transaction.from({ outputs: [{ lock: back, capacity: amount }] });
    await tx.completeInputsByCapacity(signer);
    await tx.completeFeeBy(signer, 1_000n);
    const hash = await signer.sendTransaction(tx);
    log(`${label}: ${ccc.fixedPointToString(amount)} CKB sent in ${Math.round(performance.now() - start)} ms, tx ${hash}`);
    return { hash, tx: (await client.getTransaction(hash))!.transaction };
  };

  // 1. The first send: the dialog, the Lit code, the genesis, then the send itself, chained on the new cell.
  const first = await send(61n * CKB, "1. first send");
  const pending = await listPendingTransactions(user.id, nodeStatus(client));
  const genesis = pending.map(({ transaction }) => transaction).find((tx) => isSendLimitCell(tx.outputs[0], tx.outputsData[0], secp))!;
  log(`   genesis ${genesis.hash()}: daily amount ${ccc.fixedPointToString(decodeSendLimitSettings(genesis.outputsData[0]).ckb!)} CKB, data ${ccc.bytesFrom(genesis.outputsData[0]).length} bytes (fingerprint only)`);
  const chained = sendLimitInputIndex(first.tx, { outPoint: { txHash: genesis.hash(), index: 0 } }) !== -1;
  log(`   the first send spends the new send-limit cell: ${chained}; dialogs ${offers}, codes ${codes}`);
  await waitFor(genesis.hash());
  await waitFor(first.hash);
  log(`   both committed`);

  // 2. The next send, under the amount: no dialog and no code.
  await send(100n * CKB, "2. second send (61 + 100 < 300)");
  log(`   dialogs ${offers}, codes ${codes}`);

  // 3. Over the amount (61 + 100 + 200 > 300): the Lit code is needed.
  await send(200n * CKB, "3. third send (over 300 in 24 hours)");
  log(`   dialogs ${offers}, codes ${codes}`);
  process.exit(0);
}

main().catch((error) => { console.error(error); process.exit(1); });

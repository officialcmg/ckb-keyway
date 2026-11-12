// Live CKB testnet proof for send limits and back-to-back sends (research/send-limits/README.md).
//
//   KEYWAY_LIVE_KEYS=/path/keys.json DATABASE_URL=postgres://… node --import tsx research/send-limits/live.ts
//
// keys.json holds two throwaway testnet keys, "A" and "B", funded from the public faucet; it stays outside the
// repository and is never printed. Each key stands in for an account's Lit PKP: the policy Action runs unchanged
// under a stand-in Lit runtime (its key operations use the test key, its email goes to a log) but talks to the live
// testnet RPC, and the transactions it signs are broadcast for real. The server's own code runs as in production:
// preview, local planning, the Lit code flow, the pending-transaction list (in the given Postgres), and the SDK's
// KeyWaySigner with fresh CCC clients standing in for separate tabs and devices.
import { readFileSync } from "node:fs";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1Lock } from "../../src/sdk/browser/account-lock.ts";
import type { KeyWayApiClient } from "../../src/sdk/browser/api-client.ts";
import { KeyWaySigner } from "../../src/sdk/browser/keyway-signer.ts";
import { chainOnSendLimit, sendLimitInputIndex, setSendLimitRecord } from "../../src/sdk/browser/send-limits.ts";
import { serializeTransaction } from "../../src/server/funding-transaction.ts";
import { signingSettings, transactionSigning, type SigningContext } from "../../src/server/general-signing.ts";
import { loadLitAction } from "../../src/server/lit-actions.ts";
import { litPolicyRunner } from "../../src/server/lit-policy.ts";
import { listPendingTransactions, nodeStatus, recordPendingTransaction } from "../../src/server/pending-transactions.ts";
import { planSendLimits, sendLimitHead } from "../../src/server/send-limits.ts";
import type { ReadyWallet } from "../../src/server/user-wallet.ts";
import { fakeEthers } from "../../tests/lit-action-fixture.ts";

const CKB = 100_000_000n;
const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
const keys = JSON.parse(readFileSync(process.env.KEYWAY_LIVE_KEYS!, "utf8")) as Record<string, string>;
const log = (...parts: unknown[]) => console.log(new Date().toISOString().slice(11, 23), ...parts);
const ms = (start: number) => `${Math.round(performance.now() - start)} ms`;
const lit = { runs: [] as Array<{ mode: string; ms: number }>, emails: [] as string[] };

/** A stand-in Lit runtime around the Action's source: the test key for key operations, the live RPC for the rest. */
function runtime(privateKey: ccc.Hex, source: string) {
  const Lit = { Actions: { getPrivateKey: async () => privateKey, getLitActionPrivateKey: async () => ccc.hexFrom(keccak_256(ccc.bytesFrom(privateKey))) } };
  const fetchVia = async (url: string, init: RequestInit) => {
    if (url === "https://api.resend.com/emails") {
      lit.emails.push(JSON.parse(String(init.body)).text);
      return new Response(JSON.stringify({ id: "logged" }), { status: 200 });
    }
    return fetch(url, init);
  };
  return new Function("Lit", "ethers", "fetch", `${source}\nreturn main;`)(Lit, fakeEthers, fetchVia) as (params: Record<string, unknown>) => Promise<unknown>;
}

function account(name: string) {
  const privateKey = keys[name] as ccc.Hex;
  const publicKey = ccc.hexFrom(secp256k1.getPublicKey(ccc.bytesFrom(privateKey), true));
  const pkpId = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(ccc.bytesFrom(privateKey), false).slice(1)).slice(12));
  const wallet = { version: 1, status: "ready", litPkpId: pkpId, litPublicKey: publicKey, ckbAddress: "", encryptedFiberKey: "", primaryDeviceIdHash: "a".repeat(64), hasOpenedChannel: false, createdAt: "", updatedAt: "" } as unknown as ReadyWallet;
  // The same account each run, so its pending list carries over between runs.
  const id = ccc.hashCkb(publicKey).slice(2, 34);
  const user = { id: `${id.slice(0, 8)}-${id.slice(8, 12)}-4${id.slice(13, 16)}-8${id.slice(17, 20)}-${id.slice(20, 32)}` };
  const context: SigningContext = {
    user, wallet, appName: "KeyWay live proof",
    email: async () => `${name.toLowerCase()}@example.com`,
    sendEmail: async () => { throw new Error("no server code expected"); },
    rateLimit: async () => ({ allowed: true, retryAfter: null }),
    recordSigning: async () => undefined,
    client,
  };
  return { name, privateKey, publicKey, wallet, user, context };
}
type Account = ReturnType<typeof account>;

/** KeyWay's HTTP API as the SDK sees it, served by the server's own functions. */
function api(who: Account): KeyWayApiClient {
  return {
    signTransaction: (_token: string, body: Record<string, unknown>) => transactionSigning(who.context, body),
    signingSettings: (_token: string, body: Record<string, unknown>) => signingSettings(who.context, body),
    pendingTransactions: async () => {
      const pending = await listPendingTransactions(who.user.id, nodeStatus(client));
      const head = await sendLimitHead(client, who.wallet, pending);
      return JSON.parse(ccc.stringify({ transactions: pending.map(({ transaction }) => serializeTransaction(transaction)), ...(head ? { sendLimit: head } : {}) }));
    },
  } as unknown as KeyWayApiClient;
}

const lastCode = () => /Your confirmation code is (\d{8})/.exec(lit.emails[lit.emails.length - 1])![1];

/** A fresh client (its own CCC client and cache), as another tab or device would be. */
function freshSigner(who: Account, codes = true) {
  const fresh = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  return new KeyWaySigner("token", who.publicKey, {
    approveCkbTransaction: (preview) => { log(`  approve: send ${preview.sendingCkb} CKB, fee ${preview.feeCkb}, code ${preview.requiresEmailCode ? "needed" : "not needed"}`); return true; },
    approveCkbMessage: () => false,
    requestEmailCode: async (request) => { if (!codes) return undefined; log(`  code prompt: ${request.codeLength}-digit code sent to ${request.sentTo}`); return lastCode(); },
  }, fresh, api(who));
}

async function send(who: Account, to: ccc.Script, amount: bigint, label: string, codes = true) {
  const signer = freshSigner(who, codes);
  const start = performance.now();
  const runsBefore = lit.runs.length;
  const tx = ccc.Transaction.from({ outputs: [{ lock: to, capacity: amount }] });
  await tx.completeInputsByCapacity(signer);
  await tx.completeFeeBy(signer);
  const hash = await signer.sendTransaction(tx);
  const litMs = lit.runs.slice(runsBefore).filter((run) => run.mode === "transaction").reduce((sum, run) => sum + run.ms, 0);
  log(`${label}: ${ccc.fixedPointToString(amount)} CKB sent in ${ms(start)} end to end (Lit Action ${litMs} ms), tx ${hash}`);
  return hash;
}

async function turnOn(A: Account) {
  const start = performance.now();
  const asked = await signingSettings(A.context, { operation: "set-daily-amount", asset: "ckb", amount: (300n * CKB).toString() }) as { requiresEmailCode?: boolean; confirmationNonce: string; codeLength?: number };
  log(`1. turning limits on (300 CKB a day): code needed ${asked.requiresEmailCode}, ${asked.codeLength}-digit Lit code emailed`);
  await signingSettings(A.context, { operation: "set-daily-amount", asset: "ckb", amount: (300n * CKB).toString(), confirmationNonce: asked.confirmationNonce, emailCode: lastCode() });
  const genesis = (await listPendingTransactions(A.user.id, nodeStatus(client))).at(-1)!.transaction;
  log(`   genesis ${genesis.hash()} sent in ${ms(start)}; send-limit cell ${genesis.hash()}:0, data ${ccc.bytesFrom(genesis.outputsData[0]).length} bytes (fingerprint only)`);
}

async function main() {
  process.env.LIT_USAGE_API_KEY ??= "live-proof";
  process.env.RESEND_API_KEY ??= "re_live_proof_only";
  const source = await loadLitAction("sign-ckb-transaction");
  const A = account("A");
  const B = account("B");
  const actions = new Map([[A.wallet.litPkpId, runtime(A.privateKey, source)], [B.wallet.litPkpId, runtime(B.privateKey, source)]]);
  litPolicyRunner.run = async (_config, params) => {
    const start = performance.now();
    try { return await actions.get(String(params.pkpId))!(params); } finally { lit.runs.push({ mode: String(params.mode), ms: Math.round(performance.now() - start) }); }
  };
  const secpA = await secp256k1Lock(client, A.publicKey);
  const secpB = await secp256k1Lock(client, B.publicKey);
  log("account A", ccc.Address.fromScript(secpA, client).toString(), "balance", ccc.fixedPointToString(await client.getBalance([secpA])));
  log("account B", ccc.Address.fromScript(secpB, client).toString(), "balance", ccc.fixedPointToString(await client.getBalance([secpB])));

  // 1. Turning limits on for A: 300 CKB a day. The genesis needs the Lit code, which binds the email's fingerprint.
  const existing = await sendLimitHead(client, A.wallet, await listPendingTransactions(A.user.id, nodeStatus(client)));
  if (existing) log(`1. limits already on (send-limit cell ${existing.outPoint.txHash}:${existing.outPoint.index}); skipping the genesis`);
  else await turnOn(A);

  // 2. Back-to-back sends from fresh clients, each before the previous one confirms, chained on the pending cell.
  const one = await send(A, secpB, 100n * CKB, "2. send 1 from client X");
  const two = await send(A, secpB, 100n * CKB, "   send 2 from fresh client Y (send 1 still pending)");
  log(`   status now: send 1 ${(await client.getTransaction(one))?.status}, send 2 ${(await client.getTransaction(two))?.status}`);

  // 3. A compromised server asks Lit for two sends at once, each under the amount on its own (200 + 90 < 300).
  const pending = await listPendingTransactions(A.user.id, nodeStatus(client));
  const head = (await sendLimitHead(client, A.wallet, pending))!;
  const parallel = await Promise.all([0, 1].map(async (i) => {
    const signer = freshSigner(A);
    const tx = ccc.Transaction.from({ outputs: [{ lock: secpB, capacity: 90n * CKB + BigInt(i) }] });
    await tx.completeInputsByCapacity(signer);
    await tx.completeFeeBy(signer);
    chainOnSendLimit(tx, head);
    await signer.prepareTransaction(tx);
    const plan = await planSendLimits(A.wallet, tx);
    setSendLimitRecord(tx, sendLimitInputIndex(tx, head), plan.record!);
    const runner = actions.get(A.wallet.litPkpId)!;
    const signed = await runner({ mode: "transaction", pkpId: A.wallet.litPkpId, transaction: serializeTransaction(tx) }) as { signatures: Array<{ witnessIndex: number; r: string; s: string; recoveryParam: number }> };
    for (const signature of signed.signatures) {
      const witness = tx.getWitnessArgsAt(signature.witnessIndex)!;
      witness.lock = ccc.hexFrom(`${signature.r}${signature.s.slice(2)}${signature.recoveryParam.toString(16).padStart(2, "0")}`);
      tx.setWitnessArgsAt(signature.witnessIndex, witness);
    }
    return { tx, plan };
  }));
  log(`3. two parallel requests, each planned under the amount (code needed: ${parallel.map(({ plan }) => plan.needsCode).join(", ")}), both signed by the Action`);
  for (const [i, { tx }] of parallel.entries()) {
    try {
      log(`   broadcast ${i + 1}: accepted ${await client.sendTransaction(tx, "passthrough")}`);
      // KeyWay's server lists what it signs; a server that hid it would only make the next honest send conflict
      // until this one commits.
      await recordPendingTransaction(A.user.id, tx);
    } catch (error) { log(`   broadcast ${i + 1}: refused by the node: ${(error instanceof Error ? error.message : String(error)).slice(0, 160)}`); }
  }

  // 4. The next send counts everything before it and needs the code.
  await send(A, secpB, 70n * CKB, "4. send over the amount from fresh client Z (code entered)");
  try {
    await send(A, secpB, 70n * CKB, "   the same without the code", false);
  } catch (error) {
    log(`   without the code: refused (${error instanceof Error ? error.message : String(error)})`);
  }

  // 5. A compromised server leaves the send-limit cell out: Lit refuses without the code.
  const unchained = ccc.Transaction.from({ outputs: [{ lock: secpB, capacity: 100n * CKB }] });
  const bare = new KeyWaySigner("token", A.publicKey, { approveCkbTransaction: () => true, approveCkbMessage: () => false, requestEmailCode: async () => undefined }, new ccc.ClientPublicTestnet(), { pendingTransactions: async () => ({ transactions: (await listPendingTransactions(A.user.id, nodeStatus(client))).map(({ transaction }) => serializeTransaction(transaction)) }) } as unknown as KeyWayApiClient);
  await unchained.completeInputsByCapacity(bare);
  await unchained.completeFeeBy(bare);
  await bare.prepareTransaction(unchained);
  let unchainedPlan = await planSendLimits(A.wallet, unchained);
  log(`5. a send without the send-limit cell: plan says ${unchainedPlan.limits}, code needed ${unchainedPlan.needsCode}`);
  if (unchainedPlan.limits === "legacy") {
    // The indexer only sees committed cells: until the genesis commits, the account is as it was before limits.
    log("   the genesis isn't committed yet, so the indexer can't show the cell; waiting for it");
    const waitStart = performance.now();
    while (unchainedPlan.limits === "legacy" && performance.now() - waitStart < 300_000) {
      await new Promise((resolve) => setTimeout(resolve, 5_000));
      unchainedPlan = await planSendLimits(A.wallet, unchained);
    }
    log(`   after ${ms(waitStart)}: plan says ${unchainedPlan.limits}, code needed ${unchainedPlan.needsCode}`);
  }
  try {
    await actions.get(A.wallet.litPkpId)!({ mode: "transaction", pkpId: A.wallet.litPkpId, transaction: serializeTransaction(unchained) });
    log("   UNEXPECTED: signed");
  } catch (error) {
    log(`   Lit refuses: ${error instanceof Error ? error.message : String(error)}`);
  }

  // 6. Account B (no limits): back-to-back sends from fresh clients, then the old behaviour for comparison.
  const b1 = await send(B, secpA, 100n * CKB, "6. B send 1 from client P");
  const b2 = await send(B, secpA, 100n * CKB, "   B send 2 from fresh client Q (send 1 still pending)");
  log(`   status: ${(await client.getTransaction(b1))?.status}, ${(await client.getTransaction(b2))?.status}`);
  const blind = new ccc.SignerCkbPrivateKey(new ccc.ClientPublicTestnet(), B.privateKey);
  const old = ccc.Transaction.from({ outputs: [{ lock: secpA, capacity: 100n * CKB }] });
  await old.completeInputsByCapacity(blind);
  await old.completeFeeBy(blind);
  try {
    await blind.sendTransaction(old);
    log("   a client without the list: accepted (the chain had already confirmed the earlier sends)");
  } catch (error) {
    log(`   a client without the list picks a spent cell and the node refuses it: ${(error instanceof Error ? error.message : String(error)).slice(0, 160)}`);
  }

  // 7. Latency of one Lit run, this Action against the previous one, same RPC.
  const previousSource = readFileSync(process.env.KEYWAY_PREVIOUS_ACTION!, "utf8");
  const previous = runtime(B.privateKey, previousSource);
  const current = runtime(B.privateKey, source);
  const currentA = runtime(A.privateKey, source);
  const probe = ccc.Transaction.from({ outputs: [{ lock: secpA, capacity: 100n * CKB }] });
  const probeSigner = freshSigner(B);
  await probe.completeInputsByCapacity(probeSigner);
  await probe.completeFeeBy(probeSigner);
  await probeSigner.prepareTransaction(probe);
  const chainedSigner = freshSigner(A);
  const chained = ccc.Transaction.from({ outputs: [{ lock: secpB, capacity: 61n * CKB }] });
  await chained.completeInputsByCapacity(chainedSigner);
  await chained.completeFeeBy(chainedSigner);
  await chainedSigner.prepareTransaction(chained);
  const chainedPlan = await planSendLimits(A.wallet, chained);
  const chainedHead = (await chainedSigner.pending.refresh(true)).sendLimit!;
  setSendLimitRecord(chained, sendLimitInputIndex(chained, chainedHead), chainedPlan.record!);
  const time = async (run: () => Promise<unknown>) => { const s = performance.now(); try { await run(); } catch { /* code needed is fine */ } return performance.now() - s; };
  const samples: Record<string, number[]> = { previous: [], legacy: [], chained: [], plan: [] };
  for (let i = 0; i < 5; i++) {
    samples.previous.push(await time(() => previous({ mode: "transaction", pkpId: B.wallet.litPkpId, transaction: serializeTransaction(probe) })));
    samples.legacy.push(await time(() => current({ mode: "transaction", pkpId: B.wallet.litPkpId, transaction: serializeTransaction(probe) })));
    samples.chained.push(await time(() => currentA({ mode: "transaction", pkpId: A.wallet.litPkpId, transaction: serializeTransaction(chained), email: "a@example.com", emailCode: undefined })));
    samples.plan.push(await time(() => planSendLimits(A.wallet, chained)));
  }
  const median = (values: number[]) => Math.round([...values].sort((a, b) => a - b)[Math.floor(values.length / 2)]);
  log(`7. one Action run, median of 5 against live testnet RPC from this machine:`);
  log(`   previous policy Action, plain send: ${median(samples.previous)} ms`);
  log(`   this Action, send from an account without limits: ${median(samples.legacy)} ms`);
  log(`   this Action, chained send with limits on: ${median(samples.chained)} ms`);
  log(`   server-side plan at preview (keyless, same rules): ${median(samples.plan)} ms`);
  log(`Lit runs during the proof: ${lit.runs.map((run) => `${run.mode} ${run.ms}`).join(", ")}`);
  process.exit(0);
}

main().catch((error) => { console.error(error); process.exit(1); });

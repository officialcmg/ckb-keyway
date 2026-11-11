import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import * as ccc from "@ckb-ccc/core";
import { adminListLock, adminListTypeScript, keywayOmnilock, omnilockArgsFor, omnilockScript, secp256k1Lock, verifyRecoveryAnchor, OMNILOCK_OWNER_WITNESS_LOCK_LENGTH, type KeyWayRecovery } from "../sdk/browser/account-lock.ts";
import { BACKUP_CHALLENGE_TTL_MS, backupChallengeExpiry, describeBackup, MAX_RECOVERY_BACKUPS, parseBackup, parseBackups, verifyBackupOwnership, type RecoveryBackup } from "../sdk/browser/recovery-backups.ts";
import { backupAuths, readRecoveryList, recoveryListRecord, recoveryListRecordOf, recoverySalt, setRecoveryListRecord } from "../sdk/browser/recovery-list.ts";
import { adminListData, whitelistTree } from "../sdk/browser/recovery-smt.ts";
import { addTokenCellDeps } from "../sdk/browser/settlement-sweep.ts";
import { formatAsset, hasPlainTokenArgs, isXudtCompatible } from "../sdk/browser/tokens.ts";
import { withUserLock } from "./database.ts";
import { createRecoveryNoticeEmailTemplate } from "./email-template.ts";
import { serializeTransaction } from "./funding-transaction.ts";
import { codeLimit, consumeRequest, countLitCodeAttempt, hashText, issueRequest, limit, loadRequest, recordLitCode, REQUEST_EXPIRED, sendCode, signGroups, verifyCode, type SigningContext } from "./general-signing.ts";
import { litPolicyEnabled, parseLitEmailCode, policySendCode, setEmailBinding } from "./lit-policy.ts";
import { recordPendingTransaction } from "./pending-transactions.ts";
import { feeRateCap, formatCkb } from "./transaction-policy.ts";
import type { User } from "./auth-user.ts";
import { readWallet, saveWallet, type PendingRecoveryChange, type ReadyWallet } from "./user-wallet.ts";

/** What the recovery service needs beyond signing: a CKB client and a way to broadcast, both replaceable in tests. */
export type RecoveryContext = SigningContext & {
  client?: ccc.Client;
  broadcast?: (transaction: ccc.Transaction) => Promise<ccc.Hex>;
};

const FEE_RATE = 1500n;
const MAX_CELLS = 60;
const SECP_WITNESS_LOCK_LENGTH = 65;

export type RecoveryPreview = {
  network: "CKB testnet";
  /** The account's new Omnilock address. */
  newAddress: string;
  /** Its secp256k1 address, which stays the account's too. */
  legacyAddress: string;
  backups: Array<RecoveryBackup & { label: string }>;
  /** CKB held by the AdminList cell that lists the backups. */
  adminListCkb: string;
  /** The smallest plain cell at the new address. */
  minimumCellCkb: string;
  /** Extra capacity token cells need at the longer Omnilock lock. */
  tokenCellsExtraCkb: string;
  /** AdminList plus the token cells' extra capacity: CKB that stops being spendable. */
  lockedCkb: string;
  feeCkb: string;
  /** Plain CKB that arrives at the new address after the AdminList, token cells and fee. */
  movedCkb: string;
  tokens: Array<{ asset: string; amount: string; amountText: string }>;
  /** Cells the transaction can't move (other contracts' cells, cells with data); they stay at the old address. */
  cellsLeft: number;
  transactionHash: string;
};

export type RecoveryPlan = {
  transaction: ccc.Transaction;
  inputCells: ccc.Cell[];
  secp: ccc.Script;
  omnilock: ccc.Script;
  adminListType: ccc.Script;
  adminListData: ccc.Hex;
  preview: RecoveryPreview;
};

/**
 * Turning recovery on: challenge, preview, request-email-code, enable, status. The emailed code is always
 * required. Enabling sends the transaction and records it as pending; the account switches to its new address,
 * and the notice email goes out, only once the transaction is committed (`settleRecoveryChange`).
 */
export async function recoverySetup(context: RecoveryContext, body: Record<string, unknown>): Promise<unknown> {
  const client = context.client ?? new ccc.ClientPublicTestnet();
  if (body.operation === "challenge") return issueBackupChallenge(context.user);
  if (body.operation === "status") return recoveryStatus(await settleRecoveryChange(context));
  if (context.wallet.recovery) throw new Error("Account recovery is already on");
  refusePending(context.wallet);
  const backups = parseBackups(body.backups);
  // One decision for the whole flow, so a plan with the binding's placeholder is only ever signed by the Action.
  const policy = litPolicyEnabled() && !context.signDigest;
  const plan = (wallet: ReadyWallet) => planRecovery(client, wallet, backups, { emailBinding: policy });
  if (body.operation === "preview") {
    await limit(context, "sign", { max: 10, window: 60 });
    await verifyBackups(client, context.user, context.wallet, body.backups as unknown[]);
    const planned = await plan(context.wallet);
    const confirmationNonce = await issueRequest(context.user, "recovery", planDigest(planned, backups), { lines: recoveryLines(planned.preview), signer: policy ? "policy" : "digest" }, true);
    return { preview: planned.preview, confirmationNonce, requiresEmailCode: true };
  }
  const nonce = requiredNonce(body.confirmationNonce);
  if (body.operation === "request-email-code") {
    const planned = await plan(context.wallet);
    const request = await loadRequest(context.user, "recovery", nonce, planDigest(planned, backups)).catch((cause) => {
      // With a different signer the plan differs (the binding's placeholder), so the request can't match.
      throw cause instanceof Error && cause.message === REQUEST_EXPIRED ? cause : new Error(`${cause instanceof Error ? cause.message : "Signing confirmation is invalid"}. If KeyWay was just updated, start again`);
    });
    checkSignerMode(request.summary, policy ? "policy" : "digest");
    if (policy) {
      // The policy Action emails the code and returns a keyed fingerprint of this address for the chain (never the
      // address itself); the code never comes here.
      await codeLimit(context);
      const sent = await policySendCode(planned.transaction, context.wallet, { email: await context.email(), appName: context.appName, backups, client });
      await recordLitCode(context.user, "recovery", nonce, { litTicket: sent.ticket, litBinding: sent.binding });
      return { sent: true, sentTo: sent.sentTo, codeLength: 8 };
    }
    const sentTo = await sendCode(context, "recovery", nonce, "Turn on account recovery", request.summary.lines ?? []);
    return { sent: true, sentTo };
  }
  if (body.operation !== "enable") throw new Error("A valid recovery operation is required");
  return withUserLock(context.user.id, async (sql) => {
    const wallet = await readWallet(context.user, sql);
    if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");
    if (wallet.recovery) throw new Error("Account recovery is already on");
    refusePending(wallet);
    await verifyBackups(client, context.user, wallet, body.backups as unknown[]);
    const planned = await plan(wallet);
    // The digest binds the approval to this exact transaction; any change in the account's cells refuses it.
    const digest = planDigest(planned, backups);
    const request = await loadRequest(context.user, "recovery", nonce, digest).catch((cause) => {
      throw cause instanceof Error && cause.message === REQUEST_EXPIRED ? cause : new Error("Your account changed since the preview, or KeyWay was updated. Review turning on recovery again");
    });
    checkSignerMode(request.summary, policy ? "policy" : "digest");
    let signed: ccc.Transaction;
    if (policy) {
      // The Action checks the code it emailed; the request is used up only once it has signed.
      const emailCode = parseLitEmailCode(body.emailCode, request.summary.litTicket);
      if (typeof request.summary.litBinding !== "string") throw new Error("The email code has expired. Request a new one");
      setEmailBinding(planned.transaction, request.summary.litBinding);
      await checkRecoveryTransaction(client, planned.transaction, wallet.litPublicKey, backups);
      await countLitCodeAttempt(context.user, "recovery", nonce);
      await context.recordSigning(context.user.id);
      signed = await signGroups({ ...context, wallet }, planned.transaction, [{ script: planned.secp, kind: "secp256k1" }], client, { email: await context.email(), emailCode, backups });
      await consumeRequest(context.user, "recovery", nonce);
    } else {
      await verifyCode(context.user, "recovery", nonce, body.emailCode);
      await consumeRequest(context.user, "recovery", nonce);
      await checkRecoveryTransaction(client, planned.transaction, wallet.litPublicKey, backups);
      await context.recordSigning(context.user.id);
      signed = await signGroups({ ...context, wallet }, planned.transaction, [{ script: planned.secp, kind: "secp256k1" }], client);
    }
    const transactionHash = signed.hash();
    const recovery: KeyWayRecovery = {
      omnilockArgs: planned.omnilock.args,
      omnilock: keywayOmnilock(client),
      adminListTypeArgs: planned.adminListType.args,
      adminListTypeHash: planned.adminListType.hash(),
      adminListOutPoint: { txHash: transactionHash, index: 0 },
      enableTransactionHash: transactionHash,
      legacyAddress: planned.preview.legacyAddress,
      enabledAt: new Date().toISOString(),
      backups,
      ...(policy ? { litEmailBound: true } : {}),
    };
    // Recorded before sending, so a crash in between leaves a pending change the chain settles, not a lost one.
    const pending: PendingRecoveryChange = { kind: "enable", transactionHash, recovery, ckbAddress: planned.preview.newAddress, sentAt: new Date().toISOString(), transaction: ccc.hexFrom(signed.toBytes()) };
    await saveWallet(context.user, { ...wallet, recoveryPending: pending, updatedAt: new Date().toISOString() }, sql);
    await broadcast(context, client, signed, async () => saveWallet(context.user, { ...wallet, updatedAt: new Date().toISOString() }, sql));
    return { transactionHash, pending: true, recovery, ckbAddress: planned.preview.newAddress, transaction: serializeTransaction(signed) };
  });
}

/**
 * Sends the transaction. Only a refusal that means it can never commit clears the pending change. Any other
 * failure (a timeout, a lost answer) may come after a node took it, so the change stays pending and
 * `settleRecoveryChange` settles it from the chain.
 */
async function broadcast(context: RecoveryContext, client: ccc.Client, signed: ccc.Transaction, clear: () => Promise<void>): Promise<void> {
  // Listed for the account's other clients until the node reports it committed or gone (pending-transactions.ts).
  await recordPendingTransaction(context.user.id, signed);
  try {
    await send(context, client, signed);
  } catch (error) {
    if (!neverCommits(error)) return;
    await clear();
    throw error;
  }
}

async function send(context: Pick<RecoveryContext, "broadcast">, client: ccc.Client, signed: ccc.Transaction): Promise<void> {
  try {
    await (context.broadcast ?? ((transaction) => client.sendTransaction(transaction, "passthrough")))(signed);
  } catch (error) {
    // Already in a node's pool, as after a resend once the first answer was lost: it was sent.
    if (error instanceof ccc.ErrorClientDuplicatedTransaction || (error instanceof Error && /PoolRejectedDuplicatedTransaction/.test(error.message))) return;
    throw error;
  }
}

/** A send refusal that holds for any node at any time: the scripts reject it, it is malformed, or its fee is off. */
function neverCommits(error: unknown): boolean {
  if (error instanceof ccc.ErrorClientVerification || error instanceof ccc.ErrorClientMaxFeeRateExceeded) return true;
  return error instanceof ccc.ErrorClientBase && /TransactionFailedToVerify|PoolRejectedMalformedTransaction/.test(`${error.message} ${error.data}`);
}

/** Which signer a recovery request was issued under. A request finishes under the same one, or not at all. */
type SignerMode = "policy" | "digest";
const SIGNER_CHANGED = "KeyWay switched signers while this request was open. Start again.";

function checkSignerMode(summary: Record<string, unknown>, mode: SignerMode): void {
  if ((summary.signer ?? "digest") !== mode) throw new Error(SIGNER_CHANGED);
}

function refusePending(wallet: ReadyWallet): void {
  if (wallet.recoveryPending) throw new Error("A recovery change is still confirming on chain. Try again in a minute");
}

/** How long a sent change the node no longer knows is still treated as in flight. */
const PENDING_GRACE_MS = 10 * 60_000;

export type RecoveryStatus = { pending: boolean; transactionHash?: string; recovery?: KeyWayRecovery; ckbAddress: string };

function recoveryStatus(wallet: ReadyWallet): RecoveryStatus {
  return { pending: Boolean(wallet.recoveryPending), transactionHash: wallet.recoveryPending?.transactionHash, recovery: wallet.recovery, ckbAddress: wallet.ckbAddress };
}

/**
 * Settles a pending recovery change from the chain: once its transaction is committed the account takes the new
 * settings (and, when turning recovery on, the new address) and the notice email goes out. One the node reports
 * rejected, or hasn't known for the grace period, is dropped only once it can no longer commit. Called on every
 * sign-in and status check.
 */
export async function settleRecoveryChange(context: Pick<RecoveryContext, "user" | "client" | "broadcast" | "appName" | "email" | "sendEmail">, now = new Date()): Promise<ReadyWallet> {
  const settled = await withUserLock(context.user.id, async (sql) => {
    const wallet = await readWallet(context.user, sql);
    if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");
    const pending = wallet.recoveryPending;
    if (!pending) return { wallet };
    // When no node that has caught up with the change's inputs can decide, it stays pending until one can.
    const state = await onOneNode(context.client ? [context.client] : settlementNodes(), (client) => pendingState(context, client, pending, now), "kept");
    if (state === "kept") return { wallet };
    const { recoveryPending: _done, ...rest } = wallet;
    if (state === "committed") {
      const updated: ReadyWallet = { ...rest, recovery: pending.recovery, ckbAddress: pending.ckbAddress, updatedAt: now.toISOString() };
      await saveWallet(context.user, updated, sql);
      return { wallet: updated, notice: pending };
    }
    const updated: ReadyWallet = { ...rest, updatedAt: now.toISOString() };
    await saveWallet(context.user, updated, sql);
    return { wallet: updated };
  });
  if (settled.notice) {
    const { kind, ckbAddress, recovery, transactionHash } = settled.notice;
    const heading = kind === "enable" ? "Account recovery is on" : kind === "add" ? "A recovery backup was added" : "A recovery backup was removed";
    await sendRecoveryNotice(context, heading, ckbAddress, recovery.backups ?? [], transactionHash);
  }
  return settled.wallet;
}

/** The public testnet nodes a pending change is settled from, each a client of its own with no fallback. */
const SETTLEMENT_NODES = ["https://testnet.ckb.dev/", "https://testnet.ckbapp.dev/"];

export function settlementNodes(): ccc.Client[] {
  return SETTLEMENT_NODES.map((url) => new ccc.ClientPublicTestnet({ url, fallbacks: [] }));
}

/** The node doesn't know a cell the change spends, so it can't say whether that cell is spent: ask another. */
export class NodeBehind extends Error {}

/**
 * Runs `read` against one node at a time, so every answer it combines comes from the same node: CCC's fallback
 * would send a failed request to another node mid-way, and two nodes can disagree (one lagging, one reorged).
 * If a node fails, the whole read starts again on the next one. When none answers, `undecided` is returned if a
 * node was only behind (`NodeBehind`), and the last failure is thrown otherwise.
 */
export async function onOneNode<T>(nodes: ccc.Client[], read: (client: ccc.Client) => Promise<T>, undecided?: T): Promise<T> {
  let failure: unknown;
  let behind = false;
  for (const node of nodes) {
    try {
      return await read(node);
    } catch (error) {
      failure = error;
      behind ||= error instanceof NodeBehind;
    }
  }
  if (behind && undecided !== undefined) return undecided;
  throw failure ?? new Error("No CKB node to read from");
}

/** Where a pending change stands on this node: committed, dropped for good, or still pending (and sent again if needed). */
async function pendingState(context: Pick<RecoveryContext, "broadcast">, client: ccc.Client, pending: PendingRecoveryChange, now: Date): Promise<"kept" | "committed" | "dropped"> {
  const found = await client.getTransaction(pending.transactionHash);
  if (found?.status === "committed") return "committed";
  const unknown = !found || found.status === "unknown";
  // A node also reports "rejected" for removals that aren't final (expiry, a full pool), so that is checked the same way.
  const gone = found?.status === "rejected" || (unknown && now.getTime() - Date.parse(pending.sentAt) > PENDING_GRACE_MS);
  return gone ? resendStale(context, client, pending) : "kept";
}

/**
 * A change the node rejected or hasn't known for the grace period. While all its inputs are unspent the signed
 * transaction can still commit, so it is sent again (no node may have got it, or one dropped it) and stays pending,
 * unless the resend is refused in a way that holds for good. Any other refusal can pass, however long it lasts. Once
 * an input is spent, the change's own AdminList output (output 0) being live means it committed. Otherwise the
 * input counts as spent only if the node knows the transaction that made it (CCC reads a cell the node hasn't seen
 * as not live too); if it doesn't, the node is behind and another one decides. Then the change is kept while the
 * node still has it pending, proposed or committed, and dropped otherwise. A change recorded without its
 * transaction is dropped unless its AdminList output is live.
 */
async function resendStale(context: Pick<RecoveryContext, "broadcast">, client: ccc.Client, pending: PendingRecoveryChange): Promise<"kept" | "committed" | "dropped"> {
  const adminListLive = async () => Boolean(await client.getCellLive({ txHash: pending.transactionHash, index: 0 }, false));
  if (!pending.transaction) return await adminListLive() ? "committed" : "dropped";
  const transaction = ccc.Transaction.fromBytes(pending.transaction);
  for (const input of transaction.inputs) {
    if (await client.getCellLive(input.previousOutput, false)) continue;
    if (await adminListLive()) return "committed";
    if ((await client.getTransaction(input.previousOutput.txHash))?.status !== "committed") throw new NodeBehind("The CKB node hasn't caught up with this change's inputs");
    const status = (await client.getTransaction(pending.transactionHash))?.status;
    return status === "pending" || status === "proposed" || status === "committed" ? "kept" : "dropped";
  }
  try {
    await send(context, client, transaction);
  } catch (error) {
    if (neverCommits(error)) return "dropped";
  }
  return "kept";
}

/**
 * A nonce for a backup's ownership proof: `<expiry ms>.<random>.<tag>`, where the tag is an HMAC binding the
 * expiry and the random part to this user. Nothing is stored; `checkBackupChallenge` recomputes the tag.
 */
export function issueBackupChallenge(user: Pick<User, "id">, now = Date.now()): { challengeNonce: string; expiresAt: string } {
  const expiry = String(now + BACKUP_CHALLENGE_TTL_MS);
  const random = randomBytes(16).toString("hex");
  return { challengeNonce: `${expiry}.${random}.${challengeTag(user, expiry, random)}`, expiresAt: new Date(Number(expiry)).toISOString() };
}

export function checkBackupChallenge(user: Pick<User, "id">, nonce: unknown, now = new Date()): void {
  const invalid = () => new Error("The backup's approval request is invalid or expired. Sign with the backup again");
  if (typeof nonce !== "string") throw invalid();
  let expiry: Date;
  try { expiry = backupChallengeExpiry(nonce); } catch { throw invalid(); }
  const [time, random, tag] = nonce.split(".");
  const expected = Buffer.from(challengeTag(user, time, random), "hex");
  if (!timingSafeEqual(expected, Buffer.from(tag, "hex")) || expiry <= now) throw invalid();
}

function challengeTag(user: Pick<User, "id">, expiry: string, random: string): string {
  const secret = process.env.KEYWAY_RATE_LIMIT_SECRET;
  if (!secret || secret.length < 32) throw new Error("KEYWAY_RATE_LIMIT_SECRET must contain at least 32 characters");
  return createHmac("sha256", secret).update(`keyway-backup-challenge:${user.id}:${expiry}:${random}`).digest("hex");
}

/**
 * Emails the account's address, its backups and the rescue page after the change is on chain, so the user can
 * reach their funds with a backup even if KeyWay is gone. The change already happened, so a failed email is
 * logged, not thrown.
 */
async function sendRecoveryNotice(context: Pick<RecoveryContext, "appName" | "email" | "sendEmail">, heading: string, address: string, backups: RecoveryBackup[], transactionHash: string): Promise<void> {
  try {
    const template = createRecoveryNoticeEmailTemplate(context.appName, { heading, address, backups: backups.map(({ kind, address }) => `${kind === "evm" ? "EVM wallet" : "JoyID"} ${address}`), network: "CKB testnet" });
    await context.sendEmail(await context.email(), template, `keyway-recovery-notice/${transactionHash}`);
  } catch (error) {
    console.error("[keyway] recovery notice email failed", { cause: error instanceof Error ? error.message.slice(0, 200) : "email" });
  }
}

/** Each proof must be over a challenge nonce KeyWay issued to this user, unexpired, signed by the backup. */
async function verifyBackups(client: ccc.Client, user: Pick<User, "id">, wallet: ReadyWallet, proofs: unknown[]): Promise<void> {
  const account = ccc.Address.fromScript(await secp256k1Lock(client, wallet.litPublicKey), client).toString();
  for (const proof of proofs) {
    checkBackupChallenge(user, (proof as { challengeNonce?: unknown } | null)?.challengeNonce);
    await verifyBackupOwnership(client, account, proof);
  }
}

function planDigest(plan: RecoveryPlan, backups: RecoveryBackup[]): string {
  return hashText(JSON.stringify({ transaction: serializeTransaction(plan.transaction), backups }));
}

/** Movable cells: plain CKB, and xUDT tokens (CCC's deployment or RUSD's) without extension flags whose data starts with the amount. */
function cellKind(cell: ccc.Cell, xudt: ccc.ScriptInfo): "plain" | "token" | "other" {
  const type = cell.cellOutput.type;
  if (!type) return cell.outputData === "0x" ? "plain" : "other";
  const isXudt = (type.codeHash === xudt.codeHash && type.hashType === xudt.hashType) || isXudtCompatible(type);
  return isXudt && hasPlainTokenArgs(type) && ccc.bytesFrom(cell.outputData).length >= 16 ? "token" : "other";
}

const occupied = (output: ccc.CellOutput, data: ccc.HexLike) => ccc.fixedPointFrom(output.occupiedSize + ccc.bytesFrom(data).length);

/**
 * The one transaction that turns recovery on, built from the account's own secp256k1 cells: input 0 is its
 * largest plain cell, which fixes the AdminList's Type ID and so the new address. Output 0 is the AdminList
 * (Type ID, locked by the Lit key's owner-only Omnilock so no backup can touch it, RCRule data with the backups'
 * root, at its exact occupied capacity),
 * then each token cell moves as it is, and the rest of the CKB less the fee goes to the new address. Witness 0
 * records the backups' salted auths (`recoveryListRecord`) in its output_type.
 */
export async function planRecovery(client: ccc.Client, wallet: ReadyWallet, backups: RecoveryBackup[], options: { emailBinding?: boolean } = { emailBinding: litPolicyEnabled() }): Promise<RecoveryPlan> {
  const secp = await secp256k1Lock(client, wallet.litPublicKey);
  const xudt = await client.getKnownScript(ccc.KnownScript.XUdt);
  const cells: ccc.Cell[] = [];
  for await (const cell of client.findCellsByLock(secp, null, true)) cells.push(cell);
  cells.sort((a, b) => outPointKey(a).localeCompare(outPointKey(b)));
  const plain = cells.filter((cell) => cellKind(cell, xudt) === "plain");
  const tokens = cells.filter((cell) => cellKind(cell, xudt) === "token");
  if (plain.length === 0) throw new Error("Your balance can't cover turning on recovery: it needs plain CKB at your address");
  if (plain.length + tokens.length > MAX_CELLS) throw new Error("Your account has too many cells to move in one transaction");
  const first = plain.reduce((best, cell) => cell.cellOutput.capacity > best.cellOutput.capacity ? cell : best);
  const inputCells = [first, ...[...plain, ...tokens].filter((cell) => cell !== first)];

  const input0 = ccc.CellInput.from({ previousOutput: first.outPoint });
  const adminListType = adminListTypeScript({ adminListTypeArgs: ccc.hashTypeId(input0, 0) });
  const deployment = keywayOmnilock(client);
  const omnilock = omnilockScript({ omnilock: deployment, omnilockArgs: omnilockArgsFor(wallet.litPublicKey, adminListType.hash()) });
  // Each backup's identity is salted with this account's AdminList type hash, so it differs in every account.
  const auths = await backupAuths(client, backups, adminListType.hash());
  const { root } = whitelistTree(auths);
  const data = adminListData(root);

  const adminList = ccc.CellOutput.from({ lock: adminListLock({ omnilock: deployment, omnilockArgs: omnilock.args }), type: adminListType, capacity: 0n });
  adminList.capacity = occupied(adminList, data);
  const tokenOutputs = tokens.map((cell) => {
    const output = ccc.CellOutput.from({ lock: omnilock, type: cell.cellOutput.type, capacity: 0n });
    output.capacity = ccc.numMax(cell.cellOutput.capacity, occupied(output, cell.outputData));
    return output;
  });
  const change = ccc.CellOutput.from({ lock: omnilock, capacity: 0n });
  const transaction = ccc.Transaction.from({
    inputs: inputCells.map((cell) => ({ previousOutput: cell.outPoint })),
    outputs: [adminList, ...tokenOutputs, change],
    outputsData: [data, ...tokens.map((cell) => cell.outputData), "0x"],
  });
  await transaction.addCellDepsOfKnownScripts(client, ccc.KnownScript.Secp256k1Blake160);
  await addTokenCellDeps(client, transaction, tokens);
  transaction.witnesses = inputCells.map((_, index) => index === 0
    ? ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(SECP_WITNESS_LOCK_LENGTH)) }).toBytes())
    : "0x");
  // The list's salted auths go on chain beside the AdminList (output 0), so its proofs can be rebuilt without KeyWay.
  setRecoveryListRecord(transaction, 0, recoveryListRecord(auths));
  // With the policy Action, witness 0 also carries the encrypted email binding, at a fixed size, so the fee
  // (and the transaction hash the emailed code is for) is the same before and after the binding goes in.
  if (options.emailBinding) setEmailBinding(transaction);

  const totalIn = inputCells.reduce((sum, cell) => sum + cell.cellOutput.capacity, 0n);
  const fee = (BigInt(transaction.toBytes().length + 4) * FEE_RATE + 999n) / 1000n;
  const reserved = adminList.capacity + tokenOutputs.reduce((sum, output) => sum + output.capacity, 0n);
  const minimum = occupied(change, "0x");
  if (totalIn < reserved + fee + minimum) {
    throw new Error(`Your balance can't cover turning on recovery: it needs ${formatCkb(reserved + fee + minimum - totalIn)} CKB more`);
  }
  transaction.outputs[transaction.outputs.length - 1].capacity = totalIn - reserved - fee;

  const tokenTotals = new Map<string, bigint>();
  for (const cell of tokens) {
    const asset = cell.cellOutput.type!.hash();
    tokenTotals.set(asset, (tokenTotals.get(asset) ?? 0n) + ccc.numLeFromBytes(ccc.bytesFrom(cell.outputData).slice(0, 16)));
  }
  const tokenExtra = tokenOutputs.reduce((sum, output, index) => sum + output.capacity - tokens[index].cellOutput.capacity, 0n);
  return {
    transaction, inputCells, secp, omnilock, adminListType, adminListData: data,
    preview: {
      network: "CKB testnet",
      newAddress: ccc.Address.fromScript(omnilock, client).toString(),
      legacyAddress: ccc.Address.fromScript(secp, client).toString(),
      backups: backups.map((backup) => ({ ...backup, label: describeBackup(backup) })),
      adminListCkb: formatCkb(adminList.capacity),
      minimumCellCkb: formatCkb(minimum),
      tokenCellsExtraCkb: formatCkb(tokenExtra),
      lockedCkb: formatCkb(adminList.capacity + tokenExtra),
      feeCkb: formatCkb(fee),
      movedCkb: formatCkb(totalIn - reserved - fee),
      tokens: [...tokenTotals].map(([asset, amount]) => ({ asset, amount: amount.toString(), amountText: formatAsset(amount, asset) })),
      cellsLeft: cells.length - inputCells.length,
      transactionHash: transaction.hash(),
    },
  };
}

/**
 * Checks the transaction against the rules of turning recovery on, independently of how it was built: it
 * spends only the account's secp256k1 cells, output 0 is the AdminList for input 0's Type ID under the key's
 * owner-only lock with exactly these backups and their on-chain record, every other output goes to the Omnilock
 * that AdminList belongs to (KeyWay's pinned deployment),
 * tokens are kept whole, and the fee is within the cap.
 */
export async function checkRecoveryTransaction(client: ccc.Client, transaction: ccc.Transaction, publicKey: ccc.HexLike, backups: RecoveryBackup[]): Promise<void> {
  const refuse = (reason: string) => { throw new Error(`The recovery transaction doesn't match what KeyWay computed: ${reason}`); };
  const secp = await secp256k1Lock(client, publicKey);
  const inputCells = await Promise.all(transaction.inputs.map((input) => input.getCell(client)));
  if (inputCells.length === 0 || inputCells.some(({ cellOutput }) => !cellOutput.lock.eq(secp))) refuse("an input isn't this account's");
  if (inputCells[0].cellOutput.type || inputCells[0].outputData !== "0x") refuse("input 0 isn't plain CKB");
  const adminListType = adminListTypeScript({ adminListTypeArgs: ccc.hashTypeId(transaction.inputs[0], 0) });
  const deployment = keywayOmnilock(client);
  const omnilock = omnilockScript({ omnilock: deployment, omnilockArgs: omnilockArgsFor(publicKey, adminListType.hash()) });
  const auths = await backupAuths(client, backups, adminListType.hash());
  const { root } = whitelistTree(auths);
  const [adminList, ...rest] = transaction.outputs;
  if (!adminList || !adminList.type?.eq(adminListType)) refuse("output 0 isn't the account's recovery list");
  if (!adminList.lock.eq(adminListLock({ omnilock: deployment, omnilockArgs: omnilock.args }))) refuse("the recovery list isn't locked to your key alone");
  const data = ccc.hexFrom(transaction.outputsData[0] ?? "0x");
  if (data !== adminListData(root)) refuse("the recovery list doesn't hold exactly these backups");
  if (adminList.capacity !== occupied(adminList, data)) refuse("the recovery list's capacity is wrong");
  if (recoveryListRecordOf(transaction, 0) !== recoveryListRecord(auths)) refuse("the recorded backup list isn't exactly these backups");
  if (rest.length === 0) refuse("nothing moves to the new address");
  rest.forEach((output, index) => {
    if (!output.lock.eq(omnilock)) refuse(`output ${index + 1} goes somewhere other than your new address`);
    if (output.type?.codeHash === adminListType.codeHash) refuse(`output ${index + 1} is a second Type ID cell`);
    if (!output.type && ccc.hexFrom(transaction.outputsData[index + 1] ?? "0x") !== "0x") refuse(`output ${index + 1} carries data`);
  });
  const tokens = (cells: Array<{ cellOutput: ccc.CellOutput; outputData: ccc.Hex }>) => {
    const totals = new Map<string, bigint>();
    for (const { cellOutput, outputData } of cells) {
      if (!cellOutput.type) continue;
      const key = cellOutput.type.hash();
      totals.set(key, (totals.get(key) ?? 0n) + ccc.numLeFromBytes(ccc.bytesFrom(outputData).slice(0, 16)));
    }
    return totals;
  };
  const before = tokens(inputCells);
  const after = tokens(rest.map((cellOutput, index) => ({ cellOutput, outputData: ccc.hexFrom(transaction.outputsData[index + 1] ?? "0x") })));
  if (before.size !== after.size || [...before].some(([asset, amount]) => after.get(asset) !== amount)) refuse("tokens don't all move to the new address");
  const fee = inputCells.reduce((sum, { cellOutput }) => sum + cellOutput.capacity, 0n) - transaction.getOutputsCapacity();
  const cap = BigInt(transaction.toBytes().length + 4) * feeRateCap();
  if (fee <= 0n || fee > cap) refuse("the fee is outside KeyWay's limit");
}

/** Lines for the confirmation email, naming the backups. */
export function recoveryLines(preview: RecoveryPreview): string[] {
  return [
    "Turn on account recovery",
    ...preview.backups.map(({ label }) => `Backup: ${label}`),
    `New address: ${preview.newAddress.slice(0, 12)}…${preview.newAddress.slice(-6)}`,
    "Your address will change because you're turning on recovery.",
    `Locks ${preview.lockedCkb} CKB (${preview.adminListCkb} CKB for the recovery list)`,
    `Network fee ${preview.feeCkb} CKB`,
    `Network ${preview.network}`,
  ];
}

function outPointKey(cell: ccc.Cell): string {
  return `${cell.outPoint.txHash}:${cell.outPoint.index.toString().padStart(10, "0")}`;
}

function requiredNonce(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f-]{36}$/i.test(value)) throw new Error("A recovery confirmation is required");
  return value;
}

export type BackupChange = { change: "add" | "remove"; backup: RecoveryBackup };

export type BackupChangePreview = {
  network: "CKB testnet";
  change: "add" | "remove";
  backup: RecoveryBackup & { label: string };
  /** The list after the change. */
  backups: Array<RecoveryBackup & { label: string }>;
  feeCkb: string;
  transactionHash: string;
};

export type BackupChangePlan = {
  transaction: ccc.Transaction;
  omnilock: ccc.Script;
  /** The AdminList's owner-only lock. */
  listLock: ccc.Script;
  adminList: ccc.Cell;
  backups: RecoveryBackup[];
  /** The list before the change. */
  previousBackups: RecoveryBackup[];
  /** The list's record before the change (salted auths), for the policy Action to check against the list's root. */
  previousRecord: ccc.Hex;
  preview: BackupChangePreview;
};

const backupKey = (backup: RecoveryBackup) => `${backup.kind}:${backup.address}`;

/** Every backup on the list before or after a change: the policy Action salts each and matches the records. */
const litBackups = (plan: BackupChangePlan) => [...plan.previousBackups, ...plan.backups.filter((backup) => !plan.previousBackups.some((old) => backupKey(old) === backupKey(backup)))];

/**
 * Adding or removing a backup: challenge, preview, request-email-code, apply, status. The emailed code is always
 * required, and adding needs the new backup's signature over the recovery challenge. Removing the last backup is
 * refused. The stored list changes, and the notice goes out, once the transaction is committed.
 */
export async function recoveryBackupChange(context: RecoveryContext, body: Record<string, unknown>): Promise<unknown> {
  const client = context.client ?? new ccc.ClientPublicTestnet();
  if (body.operation === "challenge") return issueBackupChallenge(context.user);
  if (body.operation === "status") return recoveryStatus(await settleRecoveryChange(context));
  if (!context.wallet.recovery) throw new Error("Account recovery is off");
  refusePending(context.wallet);
  const change = parseBackupChange(body);
  if (body.operation === "preview") {
    await limit(context, "sign", { max: 10, window: 60 });
    if (change.change === "add") await verifyBackups(client, context.user, context.wallet, [body.backup]);
    const plan = await planBackupChange(client, context.wallet, change);
    const mode: SignerMode = litPolicyEnabled() && !context.signDigest && context.wallet.recovery.litEmailBound ? "policy" : "digest";
    const confirmationNonce = await issueRequest(context.user, "recovery", changeDigest(plan, change), { lines: backupChangeLines(plan.preview), signer: mode }, true);
    return { preview: plan.preview, confirmationNonce, requiresEmailCode: true };
  }
  const nonce = requiredNonce(body.confirmationNonce);
  if (body.operation === "request-email-code") {
    const plan = await planBackupChange(client, context.wallet, change);
    const request = await loadRequest(context.user, "recovery", nonce, changeDigest(plan, change));
    const mode: SignerMode = litPolicyEnabled() && !context.signDigest && context.wallet.recovery.litEmailBound ? "policy" : "digest";
    checkSignerMode(request.summary, mode);
    if (mode === "policy") {
      // The policy Action emails the code only if this address matches the fingerprint bound when recovery was turned on.
      await codeLimit(context);
      const sent = await policySendCode(plan.transaction, context.wallet, { enableTransactionHash: context.wallet.recovery.enableTransactionHash, email: await context.email(), appName: context.appName, backups: litBackups(plan), client });
      await recordLitCode(context.user, "recovery", nonce, { litTicket: sent.ticket });
      return { sent: true, sentTo: sent.sentTo, codeLength: 8 };
    }
    const sentTo = await sendCode(context, "recovery", nonce, change.change === "add" ? "Add a recovery backup" : "Remove a recovery backup", request.summary.lines ?? []);
    return { sent: true, sentTo };
  }
  if (body.operation !== "apply") throw new Error("A valid backup operation is required");
  return withUserLock(context.user.id, async (sql) => {
    const wallet = await readWallet(context.user, sql);
    if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");
    if (!wallet.recovery) throw new Error("Account recovery is off");
    refusePending(wallet);
    if (change.change === "add") await verifyBackups(client, context.user, wallet, [body.backup]);
    const plan = await planBackupChange(client, wallet, change);
    const request = await loadRequest(context.user, "recovery", nonce, changeDigest(plan, change)).catch((cause) => {
      throw cause instanceof Error && cause.message === REQUEST_EXPIRED ? cause : new Error("Your account changed since the preview. Review the backup change again");
    });
    const groups = [{ script: plan.listLock, kind: "omnilock" as const }, { script: plan.omnilock, kind: "omnilock" as const }];
    const enableTransactionHash = wallet.recovery.enableTransactionHash;
    const mode: SignerMode = litPolicyEnabled() && !context.signDigest && wallet.recovery.litEmailBound ? "policy" : "digest";
    checkSignerMode(request.summary, mode);
    let signed: ccc.Transaction;
    if (mode === "policy") {
      // The Action checks the code it emailed; the request is used up only once it has signed.
      const emailCode = parseLitEmailCode(body.emailCode, request.summary.litTicket);
      await checkBackupChangeTransaction(client, plan.transaction, wallet.recovery, plan.backups);
      await countLitCodeAttempt(context.user, "recovery", nonce);
      await context.recordSigning(context.user.id);
      signed = await signGroups({ ...context, wallet }, plan.transaction, groups, client, { enableTransactionHash, email: await context.email(), emailCode, previousListRecord: plan.previousRecord, backups: litBackups(plan) });
      await consumeRequest(context.user, "recovery", nonce);
    } else {
      await verifyCode(context.user, "recovery", nonce, body.emailCode);
      await consumeRequest(context.user, "recovery", nonce);
      await checkBackupChangeTransaction(client, plan.transaction, wallet.recovery, plan.backups);
      await context.recordSigning(context.user.id);
      signed = await signGroups({ ...context, wallet }, plan.transaction, groups, client, { enableTransactionHash, previousListRecord: plan.previousRecord, backups: litBackups(plan) });
    }
    const transactionHash = signed.hash();
    const recovery: KeyWayRecovery = { ...wallet.recovery, adminListOutPoint: { txHash: transactionHash, index: 0 }, backups: plan.backups };
    const pending: PendingRecoveryChange = { kind: change.change, transactionHash, recovery, ckbAddress: wallet.ckbAddress, sentAt: new Date().toISOString(), transaction: ccc.hexFrom(signed.toBytes()) };
    await saveWallet(context.user, { ...wallet, recoveryPending: pending, updatedAt: new Date().toISOString() }, sql);
    await broadcast(context, client, signed, async () => saveWallet(context.user, { ...wallet, updatedAt: new Date().toISOString() }, sql));
    return { transactionHash, pending: true, recovery, transaction: serializeTransaction(signed) };
  });
}

function parseBackupChange(body: Record<string, unknown>): BackupChange {
  if (body.change !== "add" && body.change !== "remove") throw new Error("Say whether to add or remove the backup");
  return { change: body.change, backup: parseBackup(body.backup) };
}

function changeDigest(plan: BackupChangePlan, change: BackupChange): string {
  return hashText(JSON.stringify({ transaction: serializeTransaction(plan.transaction), change }));
}

/**
 * The list as it is on chain, by its members: the record holds only salted auths, so the members are KeyWay's
 * stored list, which must give exactly the recorded auths (or, for a list without a record, the cell's root).
 */
async function currentBackups(client: ccc.Client, recovery: KeyWayRecovery): Promise<{ adminList: ccc.Cell; backups: RecoveryBackup[] }> {
  const mismatch = () => new Error("KeyWay's copy of your backups doesn't match the recovery list on chain");
  if (!recovery.backups) throw mismatch();
  const auths = await backupAuths(client, recovery.backups, recoverySalt(recovery));
  try {
    const list = await readRecoveryList(client, recovery);
    if (list.auths.length !== auths.length || list.auths.some((auth, index) => auth !== auths[index])) throw mismatch();
    return { adminList: list.cell, backups: recovery.backups };
  } catch (error) {
    if (!(error instanceof Error) || !/doesn't record its backups/.test(error.message)) throw error;
    const adminList = await client.findSingletonCellByType(adminListTypeScript(recovery), true);
    const { root } = whitelistTree(auths);
    if (!adminList || ccc.hexFrom(adminList.outputData) !== adminListData(root)) throw mismatch();
    return { adminList, backups: recovery.backups };
  }
}

/**
 * The list-update transaction: input 0 is the AdminList cell (under the key's owner-only lock), then the
 * account's plain Omnilock cells, largest first, until they cover the fee and a change cell. Output 0 recreates
 * the AdminList (same lock, Type ID and capacity) with the new root, and witness 0 records the new list; the rest
 * goes back to the account's own address. The Lit key signs both lock groups on the owner path.
 */
export async function planBackupChange(client: ccc.Client, wallet: ReadyWallet, change: BackupChange): Promise<BackupChangePlan> {
  const recovery = wallet.recovery;
  if (!recovery) throw new Error("Account recovery is off");
  await verifyRecoveryAnchor(client, wallet.litPublicKey, recovery);
  const omnilock = omnilockScript(recovery);
  const listLock = adminListLock(recovery);
  const { adminList, backups: current } = await currentBackups(client, recovery);
  if (!adminList.cellOutput.lock.eq(listLock)) throw new Error("The recovery list isn't this account's");
  const listed = current.some((backup) => backupKey(backup) === backupKey(change.backup));
  let backups: RecoveryBackup[];
  if (change.change === "add") {
    if (listed) throw new Error(`${describeBackup(change.backup)} is already a backup`);
    if (current.length >= MAX_RECOVERY_BACKUPS) throw new Error(`At most ${MAX_RECOVERY_BACKUPS} backups can be added`);
    backups = [...current, change.backup];
  } else {
    if (!listed) throw new Error(`${describeBackup(change.backup)} isn't a backup`);
    if (current.length === 1) throw new Error("Keep at least one backup. Add another backup before removing this one");
    backups = current.filter((backup) => backupKey(backup) !== backupKey(change.backup));
  }
  const auths = await backupAuths(client, backups, recoverySalt(recovery));
  const { root } = whitelistTree(auths);
  const data = adminListData(root);

  const plain: ccc.Cell[] = [];
  for await (const cell of client.findCellsByLock(omnilock, null, true)) {
    if (!cell.cellOutput.type && cell.outputData === "0x") plain.push(cell);
  }
  plain.sort((a, b) => a.cellOutput.capacity === b.cellOutput.capacity ? outPointKey(a).localeCompare(outPointKey(b)) : a.cellOutput.capacity > b.cellOutput.capacity ? -1 : 1);
  const output = ccc.CellOutput.from(adminList.cellOutput);
  const changeOutput = ccc.CellOutput.from({ lock: omnilock, capacity: 0n });
  const minimum = occupied(changeOutput, "0x");
  const transaction = ccc.Transaction.from({ inputs: [{ previousOutput: adminList.outPoint }], outputs: [output, changeOutput], outputsData: [data, "0x"] });
  transaction.addCellDeps(recovery.omnilock.cellDeps);
  const ownerWitness = ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(OMNILOCK_OWNER_WITNESS_LOCK_LENGTH)) }).toBytes());
  let funded = 0n;
  let fee = 0n;
  for (const cell of plain) {
    transaction.inputs.push(ccc.CellInput.from({ previousOutput: cell.outPoint }));
    funded += cell.cellOutput.capacity;
    // Witness 0 is the list group's and witness 1 the account group's first witness, each at its final length.
    transaction.witnesses = [ownerWitness, ownerWitness];
    setRecoveryListRecord(transaction, 0, recoveryListRecord(auths));
    fee = (BigInt(transaction.toBytes().length + 4) * FEE_RATE + 999n) / 1000n;
    if (funded >= minimum + fee) break;
    if (transaction.inputs.length > MAX_CELLS) break;
  }
  if (funded < minimum + fee) throw new Error(`Your balance can't cover changing backups: it needs ${formatCkb(minimum + fee - funded)} CKB more`);
  transaction.outputs[1].capacity = funded - fee;
  const label = (backup: RecoveryBackup) => ({ ...backup, label: describeBackup(backup) });
  return {
    transaction, omnilock, listLock, adminList, backups, previousBackups: current,
    previousRecord: recoveryListRecord(await backupAuths(client, current, recoverySalt(recovery))),
    preview: {
      network: "CKB testnet",
      change: change.change,
      backup: label(change.backup),
      backups: backups.map(label),
      feeCkb: formatCkb(fee),
      transactionHash: transaction.hash(),
    },
  };
}

/**
 * Checks a list-update transaction independently of how it was built, the only transaction KeyWay signs that
 * spends the AdminList: input 0 is the account's AdminList under its owner-only lock and every other input is
 * plain CKB at the account's Omnilock; output 0 recreates the AdminList with the same lock, Type ID and capacity,
 * the root of exactly `backups` and their record; every other output is plain CKB at the account's own address;
 * the fee is within the cap.
 */
export async function checkBackupChangeTransaction(client: ccc.Client, transaction: ccc.Transaction, recovery: KeyWayRecovery, backups: RecoveryBackup[]): Promise<void> {
  const refuse = (reason: string) => { throw new Error(`The backup change doesn't match what KeyWay computed: ${reason}`); };
  const omnilock = omnilockScript(recovery);
  const listLock = adminListLock(recovery);
  const type = adminListTypeScript(recovery);
  const inputCells = await Promise.all(transaction.inputs.map((input) => input.getCell(client)));
  if (inputCells.length < 2) refuse("nothing pays the fee");
  if (!inputCells[0].cellOutput.lock.eq(listLock) || !inputCells[0].cellOutput.type?.eq(type)) refuse("input 0 isn't the recovery list");
  if (inputCells.slice(1).some(({ cellOutput }) => !cellOutput.lock.eq(omnilock))) refuse("an input isn't this account's");
  if (inputCells.slice(1).some(({ cellOutput, outputData }) => cellOutput.type || outputData !== "0x")) refuse("an input isn't plain CKB");
  const [adminList, ...rest] = transaction.outputs;
  if (!adminList || !adminList.lock.eq(listLock) || !adminList.type?.eq(type) || adminList.capacity !== inputCells[0].cellOutput.capacity) refuse("output 0 doesn't recreate the recovery list");
  const auths = await backupAuths(client, backups, recoverySalt(recovery));
  const { root } = whitelistTree(auths);
  if (ccc.hexFrom(transaction.outputsData[0] ?? "0x") !== adminListData(root)) refuse("the recovery list doesn't hold exactly these backups");
  if (recoveryListRecordOf(transaction, 0) !== recoveryListRecord(auths)) refuse("the recorded backup list isn't exactly these backups");
  if (rest.length === 0) refuse("nothing returns to your address");
  rest.forEach((output, index) => {
    if (!output.lock.eq(omnilock) || output.type || ccc.hexFrom(transaction.outputsData[index + 1] ?? "0x") !== "0x") refuse(`output ${index + 1} isn't plain CKB at your address`);
  });
  const fee = inputCells.reduce((sum, { cellOutput }) => sum + cellOutput.capacity, 0n) - transaction.getOutputsCapacity();
  const cap = BigInt(transaction.toBytes().length + 4) * feeRateCap();
  if (fee <= 0n || fee > cap) refuse("the fee is outside KeyWay's limit");
}

/** Lines for the confirmation email, naming the backup being added or removed. */
export function backupChangeLines(preview: BackupChangePreview): string[] {
  return [
    preview.change === "add" ? "Add a recovery backup" : "Remove a recovery backup",
    `${preview.change === "add" ? "Adding" : "Removing"}: ${preview.backup.label}`,
    ...(preview.change === "add" ? ["This backup will be able to move everything in your account without KeyWay."] : []),
    `Backups after this change: ${preview.backups.length}`,
    `Network fee ${preview.feeCkb} CKB`,
    `Network ${preview.network}`,
  ];
}

import type { User } from "./auth-user.ts";
import { addPkpToGroup, createPkp, findGroupId } from "./chipotle";
import { loadLitAction } from "./lit-actions";
import { LIT_ACTION_CIDS } from "./lit-config";
import { generateFiberKey } from "./lit";
import { litPolicyEnabled, policyIdentitySignature } from "./lit-policy";
import { derivePkpIdentity } from "./pkp-identity";
import { readActiveLease } from "./device-lease";
import { prepareBackupForDevice } from "./node-backup";
import { database, withUserLock, type DatabaseSql } from "./database";
import {
  readWallet,
  rebindProvisioningWallet,
  rebindReadyWallet,
  saveWallet,
  type ProvisioningWallet,
  type ReadyWallet,
} from "./user-wallet";

const DEVICE_ID_HASH = /^[0-9a-f]{64}$/;
/**
 * How long one request's claim on a new account's setup keeps others from starting it. The claim is renewed before
 * each paid step (creating the PKP, then completing it), so this only has to outlast the longer step, about five
 * minutes at worst with every timeout and Lit retry; a claim left by a process that stopped expires after it.
 */
const PROVISIONING_CLAIM = "10 minutes";

export type BootstrapResult = {
  provisioned: boolean;
  restoreRequired: boolean;
  wallet: Omit<ReadyWallet, "encryptedFiberKey">;
};

/** The Lit and Chipotle calls that set up a new account: slow, paid, and never made while a wallet lock is held. */
export type Provisioning = {
  createPkp(): Promise<string>;
  /** Registers the PKP with KeyWay's group, then learns its public key and has Lit create its Fiber key. */
  complete(litPkpId: string): Promise<Pick<ReadyWallet, "litPublicKey" | "ckbAddress" | "encryptedFiberKey">>;
};

export const litProvisioning: Provisioning = {
  createPkp: async () => {
    requiredEnv("LIT_USAGE_API_KEY");
    return createPkp(requiredEnv("LIT_PROVISIONING_API_KEY"));
  },
  complete: async (litPkpId) => {
    const runtimeApiKey = requiredEnv("LIT_USAGE_API_KEY");
    const provisioningApiKey = requiredEnv("LIT_PROVISIONING_API_KEY");
    await addPkpToGroup(provisioningApiKey, await findGroupId(provisioningApiKey, "CKB Keyway"), litPkpId);
    const policy = litPolicyEnabled();
    const signing = { apiKey: runtimeApiKey, actionCid: policy ? "" : LIT_ACTION_CIDS["sign-ckb-digest"] };
    const identity = await derivePkpIdentity(litPkpId, signing, policy ? (pkpId) => policyIdentitySignature(pkpId) : undefined);
    // Lit creates the Fiber key and returns it encrypted to the PKP; this server never sees it.
    const encryptedFiberKey = await generateFiberKey(litPkpId, {
      apiKey: runtimeApiKey,
      actionCid: LIT_ACTION_CIDS["generate-fiber-key"],
      actionCode: await loadLitAction("generate-fiber-key"),
    });
    return { litPublicKey: identity.publicKey, ckbAddress: identity.ckbAddress, encryptedFiberKey };
  },
};

/**
 * Signs a device in to its wallet, setting the wallet up first for a new account. The wallet lock is held only
 * for short database reads and writes: the Lit and Chipotle calls run between them, so first-time setups never
 * hold a share of the lock budget other users' sign-ins need. A claim stored with the account keeps a second
 * request from starting the same setup (and paying for a second PKP) meanwhile.
 */
export async function bootstrap(
  user: User,
  deviceIdHash: string,
  nodeMode: "browser" | "managed" = "browser",
  provisioning: Provisioning = litProvisioning,
): Promise<BootstrapResult> {
  if (!DEVICE_ID_HASH.test(deviceIdHash)) throw new Error("Device ID hash must be 32-byte lowercase hex");
  type Started = { result: BootstrapResult } | { claimId: string; litPkpId: string | undefined };
  const start = await withUserLock(user.id, async (sql): Promise<Started> => {
    const wallet = await readWallet(user, sql);
    if (wallet?.status === "ready") return { result: await readyResult(user, wallet, deviceIdHash, nodeMode, sql) };
    const claimId = await claimProvisioning(user, sql);
    if (!claimId) throw new Error("Your KeyWay wallet is still being set up. Try again in a moment");
    try {
      if (wallet && wallet.primaryDeviceIdHash !== deviceIdHash) {
        await saveWallet(user, rebindProvisioningWallet(wallet, deviceIdHash, (await readActiveLease(user, sql))?.deviceIdHash), sql);
      }
    } catch (error) {
      await releaseProvisioning(user, claimId, sql);
      throw error;
    }
    return { claimId, litPkpId: wallet?.litPkpId };
  });
  if ("result" in start) return start.result;

  try {
    let litPkpId = start.litPkpId;
    if (!litPkpId) {
      const created = await provisioning.createPkp();
      const saved = await withUserLock(user.id, async (sql): Promise<{ result: BootstrapResult } | { litPkpId: string }> => {
        // Only the claim holder creates a wallet; one is here already only if this claim expired meanwhile.
        const current = await readWallet(user, sql);
        if (current?.status === "ready") return { result: await readyResult(user, current, deviceIdHash, nodeMode, sql) };
        // Renewed before completing the PKP, the second paid step; refused if another request took the claim over.
        await renewProvisioning(user, start.claimId, sql);
        if (current) return { litPkpId: current.litPkpId };
        const wallet: ProvisioningWallet = {
          version: 1,
          status: "provisioning",
          litPkpId: created,
          primaryDeviceIdHash: deviceIdHash,
          createdAt: new Date().toISOString(),
        };
        await saveWallet(user, wallet, sql);
        return { litPkpId: created };
      });
      if ("result" in saved) return saved.result;
      litPkpId = saved.litPkpId;
    }

    const identity = await provisioning.complete(litPkpId);
    return await withUserLock(user.id, async (sql) => {
      const current = await readWallet(user, sql);
      // A wallet that became ready meanwhile is never replaced: its Fiber key may already be in use.
      if (current?.status === "ready") return readyResult(user, current, deviceIdHash, nodeMode, sql);
      if (current?.litPkpId !== litPkpId) throw new Error("KeyWay wallet setup was interrupted. Try again");
      const ready: ReadyWallet = {
        ...current,
        status: "ready",
        ...identity,
        hasOpenedChannel: false,
        updatedAt: new Date().toISOString(),
      };
      await saveWallet(user, ready, sql);
      return publicResult(ready, true, false);
    });
  } finally {
    await releaseProvisioning(user, start.claimId).catch(() => console.error("[keyway] couldn't release a wallet setup claim"));
  }
}

/** A ready wallet signing in on this device: database work only. */
async function readyResult(
  user: User,
  wallet: ReadyWallet,
  deviceIdHash: string,
  nodeMode: "browser" | "managed",
  sql: DatabaseSql,
): Promise<BootstrapResult> {
  if (nodeMode === "managed") return publicResult(wallet, false, false);
  const activeLeaseDevice = (await readActiveLease(user, sql))?.deviceIdHash;
  const migration = await prepareBackupForDevice(
    user,
    wallet.primaryDeviceIdHash,
    deviceIdHash,
    activeLeaseDevice,
    sql,
  );
  const rebound = wallet.primaryDeviceIdHash !== deviceIdHash && wallet.hasOpenedChannel && migration.canRebind
    ? { ...wallet, primaryDeviceIdHash: deviceIdHash, updatedAt: new Date().toISOString() }
    : rebindReadyWallet(wallet, deviceIdHash, activeLeaseDevice);
  if (rebound !== wallet) await saveWallet(user, rebound, sql);
  return publicResult(rebound, false, migration.restoreRequired);
}

/** Claims the account's setup for one request; undefined while another request's claim is still live. */
async function claimProvisioning(user: User, sql: DatabaseSql): Promise<string | undefined> {
  const claimId = crypto.randomUUID();
  const [row] = await sql<Array<{ claim_id: string }>>`
    insert into keyway_v2_provisioning_claims (user_id, claim_id) values (${user.id}, ${claimId})
    on conflict (user_id) do update set claim_id = excluded.claim_id, claimed_at = now()
    where keyway_v2_provisioning_claims.claimed_at < now() - ${PROVISIONING_CLAIM}::interval
    returning claim_id
  `;
  return row ? claimId : undefined;
}

/** Renews this request's claim before a paid step; refuses when another request has taken it over meanwhile. */
async function renewProvisioning(user: User, claimId: string, sql: DatabaseSql): Promise<void> {
  const [row] = await sql`
    update keyway_v2_provisioning_claims set claimed_at = now()
    where user_id = ${user.id} and claim_id = ${claimId}
    returning 1
  `;
  if (!row) throw new Error("Your KeyWay wallet is still being set up. Try again in a moment");
}

async function releaseProvisioning(user: User, claimId: string, connection?: DatabaseSql): Promise<void> {
  const sql = connection ?? await database();
  await sql`delete from keyway_v2_provisioning_claims where user_id = ${user.id} and claim_id = ${claimId}`;
}

function publicResult(wallet: ReadyWallet, provisioned: boolean, restoreRequired: boolean): BootstrapResult {
  const { encryptedFiberKey: _encrypted, ...publicWallet } = wallet;
  return { provisioned, restoreRequired, wallet: publicWallet };
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing server configuration: ${name}`);
  return value;
}

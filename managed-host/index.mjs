import { createCipheriv, createDecipheriv, createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { createReadStream, createWriteStream } from "node:fs";
import { cp, mkdir, mkdtemp, readdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createServer as createTcpServer } from "node:net";
import { join } from "node:path";
import { pipeline } from "node:stream/promises";
import { pathToFileURL } from "node:url";

const USER_ID = /^[0-9a-f]{64}$/;
const SNAPSHOT = /^snap-\d+$/;
const CHANNELS_MARKER = "keyway-channels";
// Written once a node's channels have been checked under the marker scheme. A node without it (one from before
// markers existed) starts after a restart like a marked one, so its channels are found and marked.
const CHECKED_MARKER = "keyway-channels-checked";
// A node is never stopped to make room for this long after a successful step of a channel setup, so a user's
// steps that span several requests, such as connecting to a peer, opening a channel and signing its funding,
// can't lose the node in between. Reads, such as a page polling its node, don't hold a node, and a node serving
// a request is never stopped to make room for one without channels. A setup holds its node at most MAX_HOLD_MS
// from its first step, each user starts at most SETUPS_PER_HOUR held setups an hour, and at most half the host's
// nodes are held at once, so accounts that keep repeating setup steps can't keep the host full.
const RECENT_USE_MS = 5 * 60_000;
const MAX_HOLD_MS = 15 * 60_000;
const SETUPS_PER_HOUR = 3;
// A node serving requests isn't stopped to make room for a node without channels until its user's requests
// have kept it busy this long, however long Fiber takes to answer them.
const BUSY_PROTECTION_MS = 30_000;
// A queue must stay idle this long before a new request starts a new busy period.
const BUSY_IDLE_MS = 10_000;
// Nor for this long after it starts, however it is used, so each slot changes hands at most once a minute and
// no number of accounts can make the host cold-start nodes faster than that.
const RESIDENCY_MS = 60_000;
// Written in a node's data directory: "since <ms>", when the record began, then each channel whose signed
// funding was handed to the node, one ID a line. A node from before the record has none until its next
// submission, and channels created before the record began are judged without it.
const FUNDED_CHANNELS = "keyway-funded-channels";
// A node handing its user's signed funding to Fiber isn't stopped for this long, even for a node with channels.
const SUBMIT_PROTECTION_MS = 60_000;
// After the host found no room, an admission without channels is refused at once for this long.
const NO_ROOM_RETRY_MS = 2_000;
// After a node with channels found no room, its next admission waits this long before scanning again.
const PRIORITY_NO_ROOM_RETRY_MS = 10_000;
// Only node_info may create a node for a user who has none: it is how a hosted node is connected (the SDK's
// start and its fee reserve read it first). Any other call for a user without a node is refused.
const PROVISIONING = new Set(["node_info"]);
// The steps of a channel setup, which hold the node for RECENT_USE_MS.
const CHANNEL_SETUP = new Set(["connect_peer", "open_channel", "open_channel_with_external_funding", "submit_signed_funding_tx"]);
// A node that may hold channels and isn't running is started again after 1s, then 2s, 4s, ... up to every minute.
// The backoff starts over only once a restarted node has stayed up for RESTART_STABLE_MS.
const RESTART_BASE_MS = 1_000;
const RESTART_MAX_MS = 60_000;
const RESTART_STABLE_MS = 60_000;
const nodes = new Map();
const starting = new Map();
const operations = new Map();
// Nodes that may hold channels but aren't running, with their pending retry; and each node's restart attempts.
const offline = new Map();
const restarts = new Map();
const failedStarts = new Map();
// Per user: when their held setups began, and since when they have been handing signed funding to Fiber.
const setups = new Map();
const submitting = new Map();
let bootTimer;
// When each user's queue of requests last went busy after an idle spell, and when it last went idle.
const busySince = new Map();
const idleSince = new Map();
let noRoomAt = 0;
const priorityNoRoomAt = new Map();
// Set from launch until the nodes to start after a restart are known, so /readyz isn't ready before then.
let booting = false;
let shuttingDown = false;
let uses = 0;

export function managedUserId(userId) {
  return createHash("sha256").update(userId).digest("hex");
}

export function authorizationMatches(header, token) {
  if (!header?.startsWith("Bearer ") || !token) return false;
  const supplied = Buffer.from(header.slice(7));
  const expected = Buffer.from(token);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

async function main() {
  required("FIBER_SECRET_KEY_PASSWORD");
  required("KEYWAY_MANAGED_HOST_TOKEN");
  backupKey();
  const server = createServer(handleRequest);
  server.listen(Number(process.env.PORT ?? 8080), "0.0.0.0", () => {
    console.log(`[managed-host] listening on ${process.env.PORT ?? 8080}`);
  });
  void bootKnownNodes();
  const stop = () => {
    server.close();
    void shutdown();
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

async function handleRequest(request, response) {
  try {
    if (!authorizationMatches(request.headers.authorization, required("KEYWAY_MANAGED_HOST_TOKEN"))) {
      return send(response, 401, { error: "Unauthorized" });
    }
    if (request.method === "GET" && request.url === "/readyz") {
      const ready = readiness();
      return send(response, ready.status === "ready" ? 200 : 503, ready);
    }
    if (request.method === "GET" && request.url === "/inventory") {
      return send(response, 200, { users: await existingUsers(), running: runningUsers() });
    }
    const retirement = request.method === "POST" && /^\/users\/([0-9a-f]{64})\/retire$/.exec(request.url ?? "");
    if (retirement) {
      return send(response, 200, await withUserOperation(retirement[1], () => retireUser(retirement[1])));
    }
    const purge = request.method === "POST" && /^\/users\/([0-9a-f]{64})\/purge-retired$/.exec(request.url ?? "");
    if (purge) {
      const { confirmUserId } = await readJsonBody(request);
      if (confirmUserId !== purge[1]) throw new Error("Explicit retired-user confirmation is required");
      return send(response, 200, await withUserOperation(purge[1], () => purgeRetiredUser(purge[1])));
    }
    const backups = /^\/users\/([0-9a-f]{64})\/backups$/.exec(request.url ?? "");
    if (backups && request.method === "GET") {
      return send(response, 200, { snapshots: await withUserOperation(backups[1], () => listSnapshots({ userId: backups[1] })) });
    }
    if (backups && request.method === "POST") {
      return send(response, 200, await withUserOperation(backups[1], () => snapshotUser(backups[1])));
    }
    const restore = request.method === "POST" && /^\/users\/([0-9a-f]{64})\/restore$/.exec(request.url ?? "");
    if (restore) {
      const { name } = await readJsonBody(request);
      return send(response, 200, await withUserOperation(restore[1], () => restoreUser(restore[1], name)));
    }
    const settlement = request.method === "GET" && /^\/users\/([0-9a-f]{64})\/settlement-key$/.exec(request.url ?? "");
    if (settlement) {
      // Stopgap: Fiber settles force-closed channels to the node's own CKB key, so the KeyWay API sweeps
      // that key's funds to the user's address. Only the API holds this host's token.
      return send(response, 200, { key: await readSettlementKey(settlement[1]) });
    }
    const match = request.method === "POST" && /^\/users\/([0-9a-f]{64})$/.exec(request.url ?? "");
    if (!match) return send(response, 404, { error: "Not found" });
    // A call is given up once the API stops waiting for it, so a slow one can't keep the node busy.
    const gone = new AbortController();
    response.once("close", () => { if (!response.writableFinished) gone.abort(); });
    const upstream = await proxyUserRequest(match[1], await readBody(request, 1_048_576), gone.signal);
    response.writeHead(upstream.status, { "content-type": upstream.contentType });
    response.end(upstream.body);
  } catch (error) {
    logError(error);
    send(response, 502, { error: error instanceof Error ? error.message : "Managed node failed" });
  }
}

/**
 * Ready only while every node that may hold channels is running: one that is offline can't watch its channels.
 * Counts only, as the API may show this to anyone.
 */
export function readiness() {
  return { status: offline.size === 0 && !booting ? "ready" : "degraded", nodes: nodes.size, maxNodes: maxNodes(), offline: offline.size };
}

/**
 * Passes one JSON-RPC request to the user's node, starting it if needed. Only connecting a node or setting up a
 * channel may create one, and only a channel setup step holds it (see PROVISIONING and CHANNEL_SETUP).
 */
export function proxyUserRequest(userId, body, signal) {
  const method = rpcMethod(body);
  return withUserOperation(userId, async () => {
    // A request the API gave up on while it waited in the queue starts nothing.
    if (signal?.aborted) throw new Error("The request was abandoned");
    // One call at a time: a batch would carry methods the checks below never see.
    if (isBatch(body)) throw new Error("Batch requests aren't supported");
    const setup = CHANNEL_SETUP.has(method);
    // Signed funding goes to Fiber only for a channel the node lists as waiting for it. Its node is never stopped
    // to make room from before it is found until a minute after Fiber answers (see SUBMIT_PROTECTION_MS), and it
    // is marked and the channel recorded before the funding goes to Fiber, which passes it to the peer at once:
    // an answer may never come back. Any other submission is refused here, and so is one that can't be checked.
    const funding = method === "submit_signed_funding_tx";
    const fundingId = funding ? submittedChannelId(body) : undefined;
    let sent = false;
    let result;
    // While the call is in flight its protection doesn't run out.
    if (funding) submitting.set(userId, Infinity);
    try {
      const node = await ensureNode(userId, { provision: PROVISIONING.has(method) });
      if (funding) {
        if (!fundingId || !(await awaitingFunding(userId, node, fundingId))) {
          throw new Error("This channel isn't waiting for its funding");
        }
        // Nothing is recorded or sent for a submission the API gave up on while its node started or was checked.
        if (signal?.aborted) throw new Error("The request was abandoned");
        await markChannels(userId, true);
        await recordFundedChannel(userId, fundingId, fundingInputs(body));
        // A node stopped meanwhile never gets the funding.
        if (nodes.get(userId) !== node || node.stopping) {
          await unrecordFundedChannel(userId, fundingId).catch(logError);
          throw new Error("The hosted node stopped; try again");
        }
        sent = true;
      }
      const upstream = await fetch(`http://127.0.0.1:${node.port}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
        // Funding recorded for Fiber is always sent, even if the API stops waiting, so the record stays true.
        signal: signal && !sent ? AbortSignal.any([signal, AbortSignal.timeout(120_000)]) : AbortSignal.timeout(120_000),
      });
      result = {
        ok: upstream.ok,
        status: upstream.status,
        contentType: upstream.headers.get("content-type") ?? "application/json",
        body: Buffer.from(await upstream.arrayBuffer()),
        node,
      };
    } finally {
      // Protected for a minute after Fiber's answer too, as Fiber stores the channel's new state after answering.
      if (sent) submitting.set(userId, Date.now());
      else if (funding) submitting.delete(userId);
    }
    const { node } = result;
    delete result.node;
    const answer = result.ok ? rpcResult(result.body) : undefined;
    delete result.ok;
    if (answer && setup) hold(userId, node);
    // Funding Fiber refused in its checks before it installs or sends anything went nowhere: the protection and
    // the record go, and the marker follows the node's channels again. After any other error the peer may already
    // have it, so it stays recorded.
    if (sent && !answer && refusedBeforeSending(result.body)) {
      submitting.delete(userId);
      await unrecordFundedChannel(userId, fundingId).catch(logError);
      await checkChannels(userId, node).catch(logError);
    }
    // A channel holds funds once they are handed to Fiber: the user's signed funding (marked above), or the
    // node's own for open_channel. An external-funding open alone holds nothing.
    if (answer && method === "open_channel") await markChannels(userId, true);
    // A channel can also be opened to the node by a peer: it is marked once the node's channels show it.
    if (answer && method === "list_channels" && Array.isArray(answer.result?.channels) &&
      !(await hasChannelsMarker(userId).catch(() => false)) &&
      await holdsChannels(answer.result.channels, await fundingRecord(userId).catch(() => undefined))) {
      await markChannels(userId, true);
    }
    return result;
  });
}

function isBatch(body) {
  try { return Array.isArray(JSON.parse(body.toString("utf8"))); } catch { return false; }
}

function rpcMethod(body) {
  try {
    const { method } = JSON.parse(body.toString("utf8"));
    return typeof method === "string" ? method : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Whether Fiber 0.9.1 refused a funding submission in the checks it makes before installing the funding or
 * sending it to the peer (handle_submit_external_funding_tx, validate_external_funding_signed_tx), or refused
 * the request's parameters outright.
 */
function refusedBeforeSending(body) {
  let error;
  try { error = JSON.parse(body.toString("utf8"))?.error; } catch { return false; }
  if (!error) return false;
  if ([-32700, -32600, -32602].includes(error.code)) return true;
  // Including a channel Fiber no longer has (aborted meanwhile) or has closed, refused before it is reached.
  return /Expected channel in AWAITING_EXTERNAL_FUNDING-compatible state|Channel is not configured for external funding|Unsigned funding transaction not found|raw data mismatch|is not final for external funding|channel not found|is already closed/i.test(String(error.message));
}

/** A successful JSON-RPC answer, or undefined for an error or anything else. */
function rpcResult(body) {
  try {
    const answer = JSON.parse(body.toString("utf8"));
    return answer && typeof answer === "object" && !answer.error ? answer : undefined;
  } catch {
    return undefined;
  }
}

/**
 * A node that may hold channels keeps a marker in its data directory, so that after a restart the host starts
 * those nodes, and only those: any other node starts when its user next needs it.
 */
async function markChannels(userId, hasChannels) {
  const marker = join(managedDataDir(userId), CHANNELS_MARKER);
  if (hasChannels) { if (!(await fileExists(marker))) await writeFile(marker, "", { mode: 0o600 }); }
  else await rm(marker, { force: true });
}

async function hasChannelsMarker(userId) {
  return fileExists(join(managedDataDir(userId), CHANNELS_MARKER));
}

async function channelsChecked(userId) {
  return fileExists(join(managedDataDir(userId), CHECKED_MARKER));
}

/**
 * A marked node, or one never checked under the marker scheme (it may hold channels from before it). A user
 * without a node has none, and a node is recorded as checked when it is created (see startNode).
 */
async function mayHoldChannels(userId) {
  if (!(await fileExists(managedDataDir(userId)).catch(() => true))) return false;
  const [marked, checked] = await Promise.all([
    hasChannelsMarker(userId).catch(() => true),
    channelsChecked(userId).catch(() => false),
  ]);
  return marked || !checked;
}

async function fileExists(path) {
  try { await stat(path); return true; }
  catch (error) { if (error?.code === "ENOENT") return false; throw error; }
}

/** Marks a node by its current channels (marked if they can't be read) and records that it has been checked. */
async function checkChannels(userId, node) {
  let holds = true;
  try {
    holds = await holdsChannels(await nodeChannels(node), await fundingRecord(userId));
  } catch {
    // A node that stopped meanwhile is checked on its next start instead; one that still runs is marked.
    if (nodes.get(userId) !== node) return;
  }
  // A node handing over signed funding keeps its marker whatever its channels show yet.
  if (!holds && submittingNow(userId)) return;
  await markChannels(userId, holds);
  await writeFile(join(managedDataDir(userId), CHECKED_MARKER), "", { mode: 0o600 });
}

export async function withUserOperation(userId, operation) {
  // Busy time runs from when the queue last went busy after being idle for BUSY_IDLE_MS, so back-to-back requests
  // can't renew BUSY_PROTECTION_MS.
  if (!operations.has(userId) && !(Date.now() - (idleSince.get(userId) ?? -Infinity) < BUSY_IDLE_MS && busySince.has(userId))) {
    busySince.set(userId, Date.now());
  }
  idleSince.delete(userId);
  const previous = operations.get(userId) ?? Promise.resolve();
  const current = previous.catch(() => {}).then(operation);
  operations.set(userId, current);
  try {
    return await current;
  } finally {
    if (operations.get(userId) === current) {
      operations.delete(userId);
      idleSince.set(userId, Date.now());
    }
  }
}

/**
 * The user's node, started if it isn't running. `provision: false` refuses to create a node for a user who has
 * none. Every start checks the node's channels and marks it by them, so a node started on demand is never taken
 * for one from before markers.
 */
async function ensureNode(userId, { provision = true } = {}) {
  if (!USER_ID.test(userId)) throw new Error("Managed user ID is invalid");
  if (shuttingDown) throw new Error("Managed host is shutting down");
  if (await isRetired(userId)) throw new Error("Legacy Fiber node has been retired");
  const current = () => {
    const running = nodes.get(userId);
    if (running?.stopping) throw new Error("Fiber process is still stopping");
    if (running) return use(running);
    return starting.get(userId)?.then(use);
  };
  const existing = current();
  if (existing) return existing;
  if (!provision && !(await fileExists(managedDataDir(userId)))) throw new Error("This account has no hosted Fiber node yet");
  // Checked before any node is stopped to make room for one that can't start.
  try {
    await requireCleanRestore(managedDataDir(userId));
  } catch (error) {
    if (!shuttingDown && await mayHoldChannels(userId).catch(() => true)) superviseNode(userId);
    throw error;
  }
  const failed = failedStarts.get(userId);
  // A node whose last start failed doesn't stop other nodes again until it has run, or ten minutes have passed.
  const failing = failed && Date.now() - failed.at < 10 * 60_000;
  // Only a marked node may take the place of a held or busy one: a node merely never checked starts where there
  // is room, as most of those hold nothing.
  const priority = !failing && await hasChannelsMarker(userId).catch(() => true);
  // Looked up again after the waits above.
  const again = current();
  if (again) return again;
  if (shuttingDown) throw new Error("Managed host is shutting down");
  const full = new Set([...nodes.keys(), ...starting.keys()]).size >= maxNodes();
  if (full && !priority && Date.now() - noRoomAt < NO_ROOM_RETRY_MS) throw new RoomError("Managed node capacity is full");
  // A node whose last start failed takes no other node's place until it has run, or ten minutes have passed.
  if (full && failing) throw new RoomError("Managed node capacity is full");
  // A node with channels that found no room waits before scanning every node again.
  if (full && priority && Date.now() - (priorityNoRoomAt.get(userId) ?? -Infinity) < PRIORITY_NO_ROOM_RETRY_MS) {
    throw new RoomError("Managed node capacity is full");
  }
  const promise = (full ? makeRoom(userId, priority) : Promise.resolve())
    .then(() => startNode(userId))
    .then(async (node) => {
      forgetOffline(userId);
      failedStarts.delete(userId);
      priorityNoRoomAt.delete(userId);
      await checkChannels(userId, node).catch(logError);
      return node;
    }, async (error) => {
      if (!(error instanceof RoomError)) failedStart(userId);
      else if (priority) priorityNoRoomAt.set(userId, Date.now());
      // A node that may hold channels keeps being started until it runs; one that no longer may isn't offline.
      if (!shuttingDown && await mayHoldChannels(userId).catch(() => true)) superviseNode(userId);
      else forgetOffline(userId);
      throw error;
    })
    .finally(() => starting.delete(userId));
  starting.set(userId, promise);
  return promise.then(use);
}

function use(node) {
  node.lastUsed = ++uses;
  return node;
}

/** How many of a user's timestamps in `map` fall in the last `windowMs`; older ones are dropped. */
function recent(map, userId, windowMs) {
  const since = Date.now() - windowMs;
  const kept = (map.get(userId) ?? []).filter((at) => at > since);
  if (kept.length) map.set(userId, kept);
  else map.delete(userId);
  return kept.length;
}

function record(map, userId) {
  map.set(userId, [...(map.get(userId) ?? []), Date.now()]);
}

/**
 * Holds a node after a successful setup step for RECENT_USE_MS, up to MAX_HOLD_MS from the setup's first step.
 * A new setup is held only within the user's SETUPS_PER_HOUR and while at most half the host is held.
 */
function hold(userId, node) {
  const now = Date.now();
  if (node.heldUntil <= now) {
    const held = [...nodes.values()].filter((other) => other !== node && other.heldUntil > now).length;
    if (held >= Math.max(1, Math.floor(maxNodes() / 2)) || recent(setups, userId, 60 * 60_000) >= SETUPS_PER_HOUR) return;
    record(setups, userId);
    node.setupStartedAt = now;
  }
  node.heldUntil = Math.max(node.heldUntil, Math.min(now + RECENT_USE_MS, node.setupStartedAt + MAX_HOLD_MS));
}

class RoomError extends Error {}

/** Whether a user's node is handing signed funding to Fiber, or did so less than SUBMIT_PROTECTION_MS ago. */
function submittingNow(userId) {
  const since = submitting.get(userId);
  if (since === undefined) return false;
  if (Date.now() - since < SUBMIT_PROTECTION_MS) return true;
  submitting.delete(userId);
  return false;
}

/**
 * Counts a failed start (or a node dying soon after one). A node that may hold channels then loses its priority
 * until it has run, so a node that can't start doesn't stop another node on every attempt.
 */
function failedStart(userId) {
  const previous = failedStarts.get(userId);
  const ongoing = previous && Date.now() - previous.at < 10 * 60_000;
  failedStarts.set(userId, { count: ongoing ? previous.count + 1 : 1, since: ongoing ? previous.since : Date.now(), at: Date.now() });
}

async function startFundingRecord(userId) {
  const path = join(managedDataDir(userId), FUNDED_CHANNELS);
  if (await fileExists(path)) return;
  // Written whole and then moved into place, so a crash can't leave a record without its start.
  await writeFile(`${path}.new`, `since ${Date.now()}\n`, { mode: 0o600 });
  await rename(`${path}.new`, path);
}

/** The channel ID a submit_signed_funding_tx request names, lower-cased, if it names a valid one. */
function submittedChannelId(body) {
  let id;
  try { id = JSON.parse(body.toString("utf8"))?.params?.[0]?.channel_id; } catch {}
  return typeof id === "string" && /^0x[0-9a-f]{64}$/i.test(id) ? id.toLowerCase() : undefined;
}

/**
 * Whether the node lists the channel in a state Fiber takes signed funding in (negotiating, waiting for it, or
 * with only the peer's commitment signed), with no funding recorded for it yet.
 */
async function awaitingFunding(userId, node, id) {
  try {
    if ((await fundingRecord(userId))?.ids.has(id)) return false;
    const channel = (await nodeChannels(node))?.find((candidate) => String(candidate?.channel_id).toLowerCase() === id);
    if (!channel) return false;
    const flags = new Set(JSON.stringify(channel?.state?.state_flags ?? "").match(/\b[A-Z][A-Z0-9_]*\b/g) ?? []);
    const name = stateName(channel);
    return (name === "negotiatingfunding" && flags.has("AWAITING_EXTERNAL_FUNDING")) ||
      (name === "signingcommitment" && flags.has("THEIR_COMMITMENT_SIGNED_SENT") && !flags.has("OUR_COMMITMENT_SIGNED_SENT"));
  } catch {
    return false;
  }
}

/** The cells a submitted funding transaction spends, as "tx_hash:index". */
function fundingInputs(body) {
  let inputs;
  try { inputs = JSON.parse(body.toString("utf8"))?.params?.[0]?.signed_funding_tx?.inputs; } catch {}
  if (!Array.isArray(inputs)) return [];
  return inputs.map((input) => input?.previous_output)
    .filter((out) => /^0x[0-9a-f]{64}$/i.test(String(out?.tx_hash)) && /^0x[0-9a-f]+$/i.test(String(out?.index)))
    .map((out) => `${out.tx_hash.toLowerCase()}:${out.index.toLowerCase()}`)
    .slice(0, 64);
}

/** Appends a channel to the funding record, with the cells its funding spends: "<channel id> <cell>,<cell>". */
async function recordFundedChannel(userId, id, inputs = []) {
  await startFundingRecord(userId);
  await writeFile(join(managedDataDir(userId), FUNDED_CHANNELS), `${[id, inputs.join(",")].filter(Boolean).join(" ")}\n`, { flag: "a", mode: 0o600 });
}

async function unrecordFundedChannel(userId, id) {
  const path = join(managedDataDir(userId), FUNDED_CHANNELS);
  const lines = (await readFile(path, "utf8")).split("\n").filter((line) => line && line.split(" ")[0] !== id);
  // Replaced whole, so a crash part-way can't lose other channels from the record.
  await writeFile(`${path}.tmp`, `${lines.join("\n")}\n`, { mode: 0o600 });
  await rename(`${path}.tmp`, path);
}

/**
 * The node's funding record, `{ since, ids, inputs }` (inputs: channel ID to the cells its funding spends), or
 * undefined for a node from before it was kept.
 */
async function fundingRecord(userId) {
  let text;
  try { text = await readFile(join(managedDataDir(userId), FUNDED_CHANNELS), "utf8"); }
  catch (error) { if (error?.code === "ENOENT") return undefined; throw error; }
  const [first, ...lines] = text.split("\n").filter(Boolean);
  const since = Number(/^since (\d+)$/.exec(first ?? "")?.[1]);
  // A record without its start is judged as no record.
  if (!Number.isFinite(since)) return undefined;
  const inputs = new Map(lines.map((line) => {
    const [id, cells = ""] = line.split(" ");
    return [id.toLowerCase(), cells.split(",").filter(Boolean)];
  }));
  return { since, ids: new Set(inputs.keys()), inputs };
}

/** Whether a channel was created after the node's funding record began, so the record speaks for it. */
function recordCovers(record, channel) {
  const created = Number(channel?.created_at);
  return Boolean(record) && Number.isFinite(created) && created >= record.since;
}

/**
 * When the host is full, a new node takes the place of the least recently used one that holds no channels, so
 * accounts that never funded a channel can't hold the host's capacity. A node with channels is never stopped
 * this way, nor one handing its user's signed funding to Fiber (for up to a minute). Nor, unless the new node
 * may hold channels itself and must run to watch them, one held after a setup step or kept busy by requests for
 * less than BUSY_PROTECTION_MS.
 */
async function makeRoom(userId, priority = false) {
  const now = () => Date.now();
  const busy = (id) => operations.has(id) && now() - (busySince.get(id) ?? 0) < BUSY_PROTECTION_MS;
  const reusable = (id, node) => id !== userId && !node.stopping &&
    !submittingNow(id) &&
    (priority || (!busy(id) && now() >= Math.max(node.heldUntil, node.startedAt + RESIDENCY_MS)));
  const candidates = [...nodes.entries()]
    .filter(([id, node]) => reusable(id, node))
    .sort(([, left], [, right]) => left.lastUsed - right.lastUsed);
  for (const [id, node] of candidates) {
    let channels;
    try { channels = await nodeChannels(node); } catch { continue; }
    let record;
    try { record = await fundingRecord(id); } catch { continue; }
    const idle = !(await holdsChannels(channels, record));
    if (!idle) await markChannels(id, true).catch(logError);
    // Checked again after the wait, in case the node was stopped or picked up a request meanwhile.
    if (!idle || nodes.get(id) !== node || !reusable(id, node)) continue;
    // Stopping marks the node at once, so no request can pick it up in between; its marker goes only once
    // it has stopped.
    // A node that won't stop leaves no room; that is no failure of the node being admitted.
    try { await stopNode(id); } catch (error) { logError(error); continue; }
    await markChannels(id, false);
    return;
  }
  if (!priority) noRoomAt = Date.now();
  throw new RoomError("Managed node capacity is full");
}

/**
 * Starts the nodes that may hold channels after a restart, marked ones first: as many as fit together, then
 * the rest one at a time, each taking the place of a node found to hold none. Every other node starts on its
 * user's next request, so leftover nodes can't hold up the ones with channels. A node that fails to start is
 * retried until it runs (see superviseNode), and counts as offline meanwhile.
 */
export async function startKnownNodes(users) {
  const states = await Promise.all(users.map(async (userId) => ({
    marked: await hasChannelsMarker(userId).catch(() => true),
    checked: await channelsChecked(userId).catch(() => false),
  })));
  // Marked nodes, then nodes never checked under the marker scheme (they may hold channels from before it).
  const withChannels = [
    ...users.filter((_, index) => states[index].marked),
    ...users.filter((_, index) => !states[index].marked && !states[index].checked),
  ];
  for (const userId of withChannels) if (!offline.has(userId)) offline.set(userId, {});
  booting = false;
  await Promise.all(withChannels.slice(0, maxNodes()).map(restartNode));
  for (const userId of withChannels.slice(maxNodes())) await restartNode(userId);
}

/**
 * Finds and starts the nodes to run after a restart. Until they are known /readyz isn't ready, and if they can't
 * be listed, listing is tried again with the restart backoff.
 */
export async function bootKnownNodes(attempt = 0) {
  booting = true;
  try {
    await startKnownNodes(await existingUsers());
  } catch (error) {
    logError(error);
    if (shuttingDown) return;
    bootTimer = setTimeout(() => void bootKnownNodes(attempt + 1), Math.min(RESTART_MAX_MS, RESTART_BASE_MS * 2 ** attempt));
    bootTimer.unref?.();
  }
}

/** Schedules the next start of an offline node that may hold channels, backing off after each failure. */
function superviseNode(userId) {
  if (shuttingDown) return;
  const entry = offline.get(userId) ?? {};
  offline.set(userId, entry);
  if (entry.timer) return;
  const attempts = restarts.get(userId) ?? 0;
  restarts.set(userId, attempts + 1);
  const delay = Math.min(RESTART_MAX_MS, RESTART_BASE_MS * 2 ** attempts);
  entry.timer = setTimeout(() => {
    entry.timer = undefined;
    void restartNode(userId);
  }, delay);
  entry.timer.unref?.();
}

/** Starts an offline node unless it no longer needs to run: retired, or found to hold no channels. */
async function restartNode(userId) {
  try {
    await withUserOperation(userId, async () => {
      if (shuttingDown) return;
      if (nodes.has(userId) || await isRetired(userId) || !(await mayHoldChannels(userId))) {
        restarts.delete(userId);
        return forgetOffline(userId);
      }
      await ensureNode(userId, { provision: false });
    });
  } catch (error) {
    logError(error);
    // Whatever failed, an offline node is tried again (a failed start has already scheduled it).
    if (offline.has(userId) && !nodes.has(userId)) superviseNode(userId);
  }
}

function forgetOffline(userId) {
  clearTimeout(offline.get(userId)?.timer);
  offline.delete(userId);
}

export function runningUsers() {
  return [...nodes.keys()];
}

export async function shutdown() {
  shuttingDown = true;
  clearTimeout(bootTimer);
  for (const entry of offline.values()) clearTimeout(entry.timer);
  // Each running node is marked by its channels first, so one with a channel a peer opened, never listed, still
  // starts after the restart.
  // Bounded, so the nodes still stop within the platform's grace period.
  await Promise.race([
    Promise.all([...nodes.entries()].map(([userId, node]) => checkChannels(userId, node).catch(logError))),
    new Promise((resolve) => { const timer = setTimeout(resolve, 3_000); timer.unref?.(); }),
  ]);
  // A node still starting either stops before it spawns or stops itself once it is up (see startNode).
  await Promise.all([
    ...[...nodes.values()].map((node) => waitForExit(node.child).catch(logError)),
    ...[...starting.values()].map((pending) => pending.catch(() => {})),
  ]);
}

async function startNode(userId) {
  const port = await availablePort();
  const baseDir = managedDataDir(userId);
  await requireCleanRestore(baseDir);
  const created = !(await fileExists(baseDir));
  const ckbDir = join(baseDir, "ckb");
  await mkdir(ckbDir, { recursive: true });
  // A new node holds no channels, so it is checked from the start, even if its first start fails.
  if (created) await writeFile(join(baseDir, CHECKED_MARKER), "", { mode: 0o600 });
  // A node from before the funding record gets one now; channels created before it began are judged without it.
  await startFundingRecord(userId);
  await createCkbKey(join(ckbDir, "key"));
  // The host may have begun shutting down while this admission waited, for room or for the steps above.
  if (shuttingDown) throw new Error("Managed host is shutting down");
  const child = spawn(required("FNN_PATH", "/usr/local/bin/fnn"), [
    "-d", baseDir,
    "-c", required("FIBER_CONFIG_TEMPLATE", "/usr/local/share/fiber/config/testnet/config.yml"),
    "--fiber-listening-addr=/ip4/0.0.0.0/tcp/0",
    "--fiber-announce-listening-addr=false",
    `--rpc-listening-addr=127.0.0.1:${port}`,
    `--ckb-node-rpc-url=${process.env.CKB_NODE_RPC_URL ?? "https://testnet.ckbapp.dev/"}`,
  ], { env: process.env, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout.on("data", (chunk) => process.stdout.write(`[fnn:${userId.slice(0, 8)}] ${chunk}`));
  child.stderr.on("data", (chunk) => process.stderr.write(`[fnn:${userId.slice(0, 8)}] ${chunk}`));
  const node = { child, port, lastUsed: 0, startedAt: 0, heldUntil: 0, setupStartedAt: 0 };
  // A missing or unrunnable binary is reported here, and the start then fails in waitForRpc.
  child.once("error", logError);
  child.once("exit", (code, signal) => {
    const wasRunning = nodes.get(userId)?.child === child;
    if (wasRunning) nodes.delete(userId);
    console.error(`[managed-host] fnn ${userId.slice(0, 8)} exited code=${code} signal=${signal}`);
    if (wasRunning && Date.now() - node.startedAt >= RESTART_STABLE_MS) {
      restarts.delete(userId);
      failedStarts.delete(userId);
    // Dying soon after starting counts as a failed start, so a node that keeps doing it loses its priority.
    } else if (wasRunning && !node.stopping) failedStart(userId);
    // A node that exits unexpectedly may hold a channel it was never marked for, so it counts as unchecked again:
    // it is started again until it runs (see superviseNode), and counts as offline meanwhile.
    if (wasRunning && !node.stopping && !shuttingDown) {
      void rm(join(managedDataDir(userId), CHECKED_MARKER), { force: true }).catch(logError).then(() => superviseNode(userId));
    }
  });
  await waitForRpc(port, child);
  if (shuttingDown) {
    await waitForExit(child);
    throw new Error("Managed host is shutting down");
  }
  // A process that died as its RPC answered is not registered as running.
  if (child.exitCode !== null || child.signalCode !== null) throw new Error("Fiber node exited during startup");
  node.lastUsed = ++uses;
  node.startedAt = Date.now();
  nodes.set(userId, node);
  return node;
}

export async function createCkbKey(path) {
  try {
    await writeFile(path, randomBytes(32).toString("hex"), { flag: "wx", mode: 0o600 });
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
  }
}

async function waitForRpc(port, child) {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Fiber node exited during startup (${child.exitCode})`);
    try {
      const response = await fetch(`http://127.0.0.1:${port}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "node_info", params: [] }),
        signal: AbortSignal.timeout(2_000),
      });
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  // Stopped for good (escalating to SIGKILL), so a wedged process can't keep its database locked.
  await waitForExit(child).catch(logError);
  throw new Error("Fiber node startup timed out");
}

export async function snapshotUser(userId) {
  const wasRunning = await stopNodeForDatabase(userId);
  return completeDatabaseOperation(
    () => createSnapshot({ userId }),
    () => resumeNode(userId, wasRunning),
  );
}

export async function restoreUser(userId, name) {
  const wasRunning = await stopNodeForDatabase(userId);
  return completeDatabaseOperation(
    () => restoreSnapshot({ userId, name }),
    () => resumeNode(userId, wasRunning),
  );
}

/** Stops a node for a snapshot or restore; one that may hold channels counts as offline until it runs again. */
async function stopNodeForDatabase(userId) {
  const stopped = await stopNode(userId);
  if (stopped && await mayHoldChannels(userId).catch(() => true) && !offline.has(userId)) offline.set(userId, {});
  return stopped;
}

/** Starts a node again after a database operation, or has it started if it may now hold channels. */
async function resumeNode(userId, wasRunning) {
  try {
    if (wasRunning) return void await ensureNode(userId, { provision: false });
  } catch (error) {
    if (!shuttingDown && await mayHoldChannels(userId).catch(() => true)) superviseNode(userId);
    // A node restored without channels isn't offline, whatever stopped its start.
    else forgetOffline(userId);
    throw error;
  }
  if (!shuttingDown && await mayHoldChannels(userId).catch(() => true)) superviseNode(userId);
  else forgetOffline(userId);
}

export async function completeDatabaseOperation(operation, resume) {
  try {
    return await operation();
  } finally {
    await resume();
  }
}

async function stopNode(userId) {
  const pending = starting.get(userId);
  const node = nodes.get(userId) ?? (pending ? await pending.catch(() => undefined) : undefined);
  if (!node) return false;
  node.stopping = true;
  await waitForExit(node.child);
  if (nodes.get(userId) === node) nodes.delete(userId);
  return true;
}

export function waitForExit(child, timeout = 15_000) {
  return new Promise((resolve, reject) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    let deadline;
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      deadline = setTimeout(() => reject(new Error("Fiber process did not stop; database operation aborted")), 5_000);
    }, timeout);
    child.once("exit", () => {
      clearTimeout(timer);
      clearTimeout(deadline);
      resolve();
    });
    child.kill("SIGTERM");
  });
}

/**
 * The node's CKB key: plain hex until FNN first starts, then FNN's encrypted format (a version byte,
 * a 16-byte salt, a 12-byte nonce, then AES-256-GCM ciphertext under a scrypt key from the secret-key password).
 */
export async function readSettlementKey(userId, password = required("FIBER_SECRET_KEY_PASSWORD")) {
  const file = await readFile(join(managedDataDir(userId), "ckb", "key"));
  const text = file.toString("utf8").trim();
  if (/^[0-9a-f]{64}$/i.test(text)) return text.toLowerCase();
  if (file[0] !== 0 || file.length < 1 + 16 + 12 + 16) throw new Error("Unsupported node key format");
  const salt = file.subarray(1, 17);
  const nonce = file.subarray(17, 29);
  const sealed = file.subarray(29);
  const key = await new Promise((resolve, reject) => scrypt(password, salt, 32, { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 }, (error, derived) => error ? reject(error) : resolve(derived)));
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(sealed.subarray(sealed.length - 16));
  const plain = Buffer.concat([decipher.update(sealed.subarray(0, sealed.length - 16)), decipher.final()]);
  if (plain.length !== 32) throw new Error("Unsupported node key format");
  return plain.toString("hex");
}

export function managedDataDir(userId) {
  return join(required("KEYWAY_MANAGED_DATA_DIR", "/fiber/users"), userId);
}

export function managedBackupDir(userId) {
  return join(required("KEYWAY_MANAGED_BACKUP_DIR", "/fiber/backups"), userId);
}

function retiredPath(userId) {
  if (!USER_ID.test(userId)) throw new Error("Managed user ID is invalid");
  return join(required("KEYWAY_MANAGED_RETIRED_DIR", "/fiber/retired"), userId);
}

async function isRetired(userId) {
  try { await stat(retiredPath(userId)); return true; }
  catch (error) { if (error?.code === "ENOENT") return false; throw error; }
}

async function nodeChannels(node) {
  return (await nodeRpc(node, "list_channels", [{ include_closed: true }]))?.channels;
}

async function nodeRpc(node, method, params) {
  const response = await fetch(`http://127.0.0.1:${node.port}`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(15_000),
  });
  const result = await response.json();
  if (!response.ok || result.error) throw new Error("Could not verify channel closure");
  return result.result;
}

/**
 * Whether a channel is finished: closed and not waiting for its on-chain settlement. Fiber 0.9.1 reports a force
 * close as UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT (or _REMOTE) and drops WAITING_ONCHAIN_SETTLEMENT once
 * it has settled. Flags are read as whole names. Kept equal to channelFinished in
 * src/sdk/browser/settlement-sweep.ts by a test.
 */
export function channelFinished(channel) {
  if (stateName(channel) !== "closed") return false;
  const flags = new Set(JSON.stringify(channel?.state?.state_flags ?? "").match(/\b[A-Z][A-Z0-9_]*\b/g) ?? []);
  return !flags.has("WAITING_ONCHAIN_SETTLEMENT");
}

function stateName(channel) {
  return String(channel?.state?.state_name).replaceAll("_", "").toLowerCase();
}

/**
 * "finished", "unfunded" or "open". A channel is unfunded while Fiber can still abort its funding
 * (can_abort_funding_on_timeout: before our funding signatures are sent) and no signed funding for it was handed
 * to the node, as its funding record shows; Fiber aborts such an open if it stalls. Fiber passes submitted
 * funding straight to the peer, which may broadcast it at any time, so a submitted channel is open. Without a
 * record that covers the channel, only a channel still negotiating its funding counts as unfunded.
 */
function channelClass(channel, record) {
  if (channelFinished(channel)) return "finished";
  const covered = recordCovers(record, channel);
  // Funding handed to the node is with the peer, whatever state Fiber last stored.
  if (covered && record.ids.has(String(channel?.channel_id).toLowerCase())) return "open";
  const name = stateName(channel);
  if (name === "negotiatingfunding") return "unfunded";
  const flags = new Set(JSON.stringify(channel?.state?.state_flags ?? "").match(/\b[A-Z][A-Z0-9_]*\b/g) ?? []);
  const abortable = ["collaboratingfundingtx", "signingcommitment"].includes(name) ||
    (name === "awaitingtxsignatures" && !flags.has("OUR_TX_SIGNATURES_SENT"));
  return abortable && covered ? "unfunded" : "open";
}

/**
 * Whether a node must keep running for its channels: any channel that isn't finished or unfunded, except a
 * channel whose recorded funding can never confirm (see fundingDead).
 */
async function holdsChannels(channels, record) {
  if (!Array.isArray(channels)) return true;
  for (const channel of channels) {
    if (channelClass(channel, record) !== "open") continue;
    if (!(await fundingDead(channel, record))) return true;
  }
  return false;
}

// When each channel was first found unable ever to be funded, and when others were last found not so.
const deadFunding = new Map();
const DEAD_FUNDING_CONFIRM_MS = 60_000;
const liveFunding = new Map();
const UNSPENT_FUNDING_TTL_MS = 10 * 60_000;
const NOT_READY = ["negotiatingfunding", "collaboratingfundingtx", "signingcommitment", "awaitingtxsignatures", "awaitingchannelready"];

/**
 * Whether a channel not yet ready, whose funding the node was handed, can never be funded: a cell its funding
 * spends was spent by another transaction, and the funding itself isn't on chain or in the pool. Nothing of the
 * user's can be in such a channel. It stays in the funding record, so retirement still waits for it. If CKB
 * can't be asked, it counts as funded.
 */
async function fundingDead(channel, record) {
  const id = String(channel?.channel_id).toLowerCase();
  const cells = recordCovers(record, channel) ? record.inputs.get(id) : undefined;
  const outpoint = String(channel?.channel_outpoint ?? "");
  // The channel's state as Fiber reports it now comes first: a channel that has become ready is funded.
  if (!cells?.length || !NOT_READY.includes(stateName(channel)) || !/^0x[0-9a-f]{72}$/i.test(outpoint)) return false;
  // A recent "still live" answer is reused for ten minutes, so repeated checks don't flood CKB.
  if (Date.now() - (liveFunding.get(id) ?? -Infinity) < UNSPENT_FUNDING_TTL_MS) return false;
  try {
    // The funding's own status first: if CKB knows it, the channel is being funded. Then a few of its cells at once.
    const status = (await ckbRpc("get_transaction", [outpoint.slice(0, 66)]))?.tx_status?.status;
    const known = status !== "unknown" && status !== "rejected";
    const spent = !known && (await Promise.all(cells.slice(0, 4).map((cell) => {
      const [tx_hash, index] = cell.split(":");
      return ckbRpc("get_live_cell", [{ tx_hash, index }, false]).then((answer) => answer?.status === "dead");
    }))).includes(true);
    if (!spent) {
      deadFunding.delete(id);
      if (liveFunding.size >= 10_000) liveFunding.clear();
      liveFunding.set(id, Date.now());
      return false;
    }
    // Believed only when CKB says so twice, at least DEAD_FUNDING_CONFIRM_MS apart, so one inconsistent answer
    // (a load-balanced node, a reorg) can't free a node whose funding is landing.
    const firstSeen = deadFunding.get(id);
    if (firstSeen === undefined) {
      if (deadFunding.size >= 10_000) deadFunding.clear();
      deadFunding.set(id, Date.now());
      return false;
    }
    return Date.now() - firstSeen >= DEAD_FUNDING_CONFIRM_MS;
  } catch {
    return false;
  }
}

/** Retirement needs every channel finished. */
export function requireClosedChannels(channels) {
  if (!Array.isArray(channels) || !channels.every(channelFinished)) {
    throw new Error("Channel closure is incomplete; preserve the node database");
  }
}

/**
 * Retirement also needs nothing left on chain for the node: no CKB at its own key (where Fiber settles force
 * closes and the user's fee reserve sits) and no channel funding cell still live. A retired node can no longer
 * be swept, and purging it deletes its key.
 */
async function requireNothingOnChain(node, channels) {
  const info = await nodeRpc(node, "node_info", []);
  const lock = info?.default_funding_lock_script;
  if (!lock?.code_hash) throw new Error("Could not read the node's CKB lock; preserve the node database");
  const held = await ckbRpc("get_cells_capacity", [{ script: { code_hash: lock.code_hash, hash_type: lock.hash_type, args: lock.args }, script_type: "lock" }]);
  if (BigInt(held?.capacity ?? "0x0") > 0n) throw new Error("The node's CKB key still holds funds; sweep them before retiring");
  for (const channel of channels) {
    const outpoint = String(channel?.channel_outpoint ?? "");
    if (!/^0x[0-9a-f]{72}$/i.test(outpoint)) continue;
    const index = `0x${Buffer.from(outpoint.slice(66), "hex").readUInt32LE(0).toString(16)}`;
    const cell = await ckbRpc("get_live_cell", [{ tx_hash: outpoint.slice(0, 66), index }, false]);
    if (cell?.status === "live") throw new Error("A channel's funding is still on chain; preserve the node database");
  }
}

async function ckbRpc(method, params) {
  const response = await fetch(process.env.CKB_NODE_RPC_URL ?? "https://testnet.ckbapp.dev/", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(15_000),
  });
  const result = await response.json();
  if (!response.ok || result.error) throw new Error(`CKB ${method} failed`);
  return result.result;
}

export async function retireUser(userId) {
  if (await isRetired(userId)) return { retired: true, databasePreserved: true };
  await stat(managedDataDir(userId)); // Never provision a new identity for cleanup.
  const node = await ensureNode(userId);
  const channels = await nodeChannels(node);
  requireClosedChannels(channels);
  // Funding aborted after the user's signed funding was handed over may still be broadcast by the peer, and only
  // this node can co-sign it. For a node from before funding was recorded, any aborted funding that was built.
  const record = await fundingRecord(userId);
  // Fiber deletes a channel whose funding it aborts, so any channel whose signed funding the node was handed
  // must still be listed, and finished.
  for (const id of record?.ids ?? []) {
    const channel = channels.find((candidate) => String(candidate?.channel_id).toLowerCase() === id);
    if (!channel || !channelFinished(channel)) throw new Error("A channel's funding was aborted after it was signed; preserve the node database");
  }
  const abortedAfterFunding = (channel) => /\b(FUNDING_ABORTED|ABANDONED)\b/.test(JSON.stringify(channel?.state?.state_flags ?? "")) &&
    (recordCovers(record, channel) ? record.ids.has(String(channel?.channel_id).toLowerCase()) : Boolean(channel?.channel_outpoint));
  if (channels.some(abortedAfterFunding)) {
    throw new Error("A channel's funding was aborted after it was signed; preserve the node database");
  }
  await requireNothingOnChain(node, channels);
  await mkdir(required("KEYWAY_MANAGED_RETIRED_DIR", "/fiber/retired"), { recursive: true });
  await writeFile(retiredPath(userId), JSON.stringify({ retiredAt: new Date().toISOString() }), { flag: "wx", mode: 0o600 });
  await stopNode(userId);
  return { retired: true, databasePreserved: true };
}

export async function purgeRetiredUser(userId, roots = {}) {
  if (!USER_ID.test(userId)) throw new Error("Managed user ID is invalid");
  const marker = join(roots.retiredRoot ?? required("KEYWAY_MANAGED_RETIRED_DIR", "/fiber/retired"), userId);
  await stat(marker).catch(() => { throw new Error("Only a retired node may be purged"); });
  if (nodes.has(userId) || starting.has(userId)) throw new Error("Node is still running");
  await rm(roots.dataRoot ? join(roots.dataRoot, userId) : managedDataDir(userId), { recursive: true, force: true });
  await rm(roots.backupRoot ? join(roots.backupRoot, userId) : managedBackupDir(userId), { recursive: true, force: true });
  // Keep the tombstone so stale callers cannot recreate the obsolete identity.
  return { purged: true, userId };
}

export async function listSnapshots({ userId, root = managedBackupDir(userId) }) {
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
  const snapshots = [];
  for (const entry of entries.filter((candidate) => candidate.isFile() && /^snap-\d+\.json$/.test(candidate.name))) {
    const name = entry.name.slice(0, -5);
    const record = await readSnapshotRecord(root, name);
    if (!record) continue;
    snapshots.push({
      name,
      createdAt: record.createdAt,
      bytes: record.bytes,
      digest: record.digest,
    });
  }
  return snapshots.sort((left, right) => left.name.localeCompare(right.name));
}

export async function createSnapshot({
  userId,
  dataDir = managedDataDir(userId),
  root = managedBackupDir(userId),
  limitBytes = Number(process.env.KEYWAY_MANAGED_MAX_BACKUP_BYTES ?? 512 * 1024 * 1024),
  keep = Number(process.env.KEYWAY_MANAGED_BACKUP_GENERATIONS ?? 3),
  encryptionKey,
}) {
  const key = backupKey(encryptionKey);
  const bytes = await directoryBytes(dataDir);
  if (bytes > limitBytes) throw new Error("Managed Fiber data directory exceeds the backup size limit");
  const expected = await snapshotDigest(dataDir);
  const name = `snap-${Date.now()}`;
  await mkdir(root, { recursive: true });
  const target = join(root, `${name}.enc`);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const tar = spawn("tar", ["-C", dataDir, "-cf", "-", "."], { stdio: ["ignore", "pipe", "pipe"] });
  try {
    await Promise.all([pipeline(tar.stdout, cipher, createWriteStream(target, { mode: 0o600 })), tarResult(tar)]);
  } catch (error) {
    tar.kill();
    await rm(target, { force: true });
    throw error;
  }
  const createdAt = new Date().toISOString();
  await writeFile(join(root, `${name}.json`), JSON.stringify({ digest: expected, bytes, createdAt, format: 2, iv: iv.toString("hex"), tag: cipher.getAuthTag().toString("hex") }), { mode: 0o600 });
  for (const stale of (await listSnapshots({ userId, root })).slice(0, -keep)) {
    await rm(join(root, stale.name), { recursive: true, force: true });
    await rm(join(root, `${stale.name}.enc`), { force: true });
    await rm(join(root, `${stale.name}.json`), { force: true });
  }
  return { name, createdAt, bytes, digest: expected };
}

export async function restoreSnapshot({
  userId,
  dataDir = managedDataDir(userId),
  root = managedBackupDir(userId),
  name,
  encryptionKey,
}) {
  if (typeof name !== "string" || !SNAPSHOT.test(name)) throw new Error("A valid managed Fiber snapshot name is required");
  await requireCleanRestore(dataDir);
  const record = await readSnapshotRecord(root, name);
  if (!record) throw new Error("Managed Fiber snapshot metadata is missing");
  const expected = record.digest;
  const staging = `${dataDir}.restore`;
  await rm(staging, { recursive: true, force: true });
  await mkdir(staging, { recursive: true });
  try {
    if (record.format === 2) {
      const decipher = createDecipheriv("aes-256-gcm", backupKey(encryptionKey), Buffer.from(record.iv, "hex"));
      decipher.setAuthTag(Buffer.from(record.tag, "hex"));
      const scratch = await mkdtemp(`${dataDir}.archive-`);
      try {
        const archive = join(scratch, "snapshot.tar");
        // GCM authenticates at EOF; never feed unauthenticated plaintext to tar.
        await pipeline(createReadStream(join(root, `${name}.enc`)), decipher, createWriteStream(archive, { flags: "wx", mode: 0o600 }));
        const tar = spawn("tar", ["-C", staging, "-xf", archive], { stdio: ["ignore", "ignore", "pipe"] });
        await tarResult(tar);
      } finally {
        await rm(scratch, { recursive: true, force: true });
      }
    } else {
      await cp(join(root, name), staging, { recursive: true });
    }
    if (await snapshotDigest(staging) !== expected) throw new Error("Managed Fiber snapshot is corrupted");
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
  const previous = `${dataDir}.previous`;
  let hadPrevious = false;
  try {
    await rename(dataDir, previous);
    hadPrevious = true;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  try {
    await rename(staging, dataDir);
  } catch (error) {
    if (hadPrevious) await rename(previous, dataDir);
    throw error;
  }
  if (hadPrevious) await rm(previous, { recursive: true });
  return { restored: true, name, digest: expected };
}

export async function requireCleanRestore(dataDir) {
  try {
    await stat(`${dataDir}.previous`);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  // Do not start with stale channel state or create a new key after an interrupted swap.
  throw new Error("Managed Fiber restore was interrupted; operator recovery is required before startup");
}

async function readSnapshotRecord(root, name) {
  try {
    const record = JSON.parse(await readFile(join(root, `${name}.json`), "utf8"));
    return /^[0-9a-f]{64}$/.test(record?.digest) && typeof record?.bytes === "number" && typeof record?.createdAt === "string" && (record.format === undefined || record.format === 2 && /^[0-9a-f]{24}$/.test(record.iv) && /^[0-9a-f]{32}$/.test(record.tag))
      ? record
      : undefined;
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
}

function backupKey(override) {
  const configured = override ? undefined : required("KEYWAY_MANAGED_BACKUP_KEY");
  if (configured && !/^[0-9a-fA-F]{64}$/.test(configured)) throw new Error("KEYWAY_MANAGED_BACKUP_KEY must be 32 bytes (64 hex characters)");
  const key = override ?? Buffer.from(configured, "hex");
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error("KEYWAY_MANAGED_BACKUP_KEY must be 32 bytes (64 hex characters)");
  return key;
}

function tarResult(child) {
  return new Promise((resolve, reject) => {
    let stderr = "";
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.once("error", reject);
    child.once("close", (code) => code === 0 ? resolve() : reject(new Error(`tar failed: ${stderr.trim()}`)));
  });
}

export async function snapshotDigest(directory) {
  const hash = createHash("sha256");
  for (const relative of await filesIn(directory)) {
    hash.update(relative);
    hash.update("\0");
    hash.update(await readFile(join(directory, relative)));
  }
  return hash.digest("hex");
}

async function directoryBytes(directory) {
  let bytes = 0;
  for (const relative of await filesIn(directory)) bytes += (await stat(join(directory, relative))).size;
  return bytes;
}

async function filesIn(directory, prefix = "") {
  const files = [];
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of [...entries].sort((left, right) => left.name.localeCompare(right.name))) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...await filesIn(join(directory, entry.name), relative));
    else if (entry.isFile()) files.push(relative);
  }
  return files;
}

function maxNodes() {
  return Number(process.env.KEYWAY_MANAGED_MAX_NODES ?? 16);
}

async function readJsonBody(request, limit = 65_536) {
  const body = await readBody(request, limit);
  try {
    const parsed = JSON.parse(body.toString("utf8"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    throw new Error("Request body must be valid JSON");
  }
}

async function existingUsers() {
  try {
    const users = (await readdir(required("KEYWAY_MANAGED_DATA_DIR", "/fiber/users"), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory() && USER_ID.test(entry.name))
      .map((entry) => entry.name);
    // A user whose tombstone can't be read is listed: its node's own start checks again, and is retried.
    const retired = await Promise.all(users.map((userId) => isRetired(userId).catch(() => false)));
    return users.filter((_, index) => !retired[index]);
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
}

function availablePort() {
  return new Promise((resolve, reject) => {
    const server = createTcpServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => typeof address === "object" && address ? resolve(address.port) : reject(new Error("No port assigned")));
    });
  });
}

function readBody(request, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        request.destroy();
        reject(new Error("Request is too large"));
      } else chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function send(response, status, body) {
  if (response.headersSent) return;
  response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  response.end(JSON.stringify(body));
}

function required(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (!value) throw new Error(`Missing managed-host configuration: ${name}`);
  return value;
}

function logError(error) {
  console.error("[managed-host]", error);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) void main().catch((error) => {
  logError(error);
  process.exitCode = 1;
});

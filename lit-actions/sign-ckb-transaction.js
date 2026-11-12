// js_params: { mode, pkpId, ... } (see README.md)
// KeyWay's policy signer. It never signs a digest it is handed. For a transaction it fetches every input cell
// from CKB testnet itself, checks each against the transaction hash, works out which locks are the account's
// from the PKP's own key, refuses any change to the recovery list that breaks its rules, asks for a code it
// emailed itself for every recovery list change, and only then signs the sighash it computed.
//
// Modes:
//   identity     signs the fixed KeyWay identity digest, so the server can learn the PKP's public key.
//   message      signs CKB's "Nervos Message:" hash of a text message it hashes itself.
//   transaction  { transaction, enableTransactionHash?, email?, emailCode?, backups?, previousListRecord? } signs
//                the account's lock groups.
//   send-code    { transaction, enableTransactionHash?, email?, backups?, emailApiKey, appName } emails a code for
//                a recovery list change or a limited send and returns the ticket (and, when turning recovery or
//                send limits on, the email binding or fingerprint the transaction must carry).
//   plan         { publicKey, transaction } signs nothing and uses no key: whether the transaction needs a code
//                under the account's send limits, and the chain record it must carry (see "send limits" below).
// A recovery list change that needs a code also needs `email`, the account's address. The chain never holds it:
// turning recovery on records only a keyed fingerprint of it, and every later code goes only to an address whose
// fingerprint matches.
// A transaction that creates or changes the recovery list needs `backups`: [{ kind: "evm" | "joyid", id }], the
// 20-byte id (EVM address, or blake160 of the JoyID passkey's public key) of every backup on the list before and
// after. The on-chain record holds only salted auths, so the Action rebuilds each auth from its id, the account's
// salt and KeyWay's verifier, and refuses any listed auth that isn't one of these.

const RPC_URLS = ["https://testnet.ckb.dev/", "https://testnet.ckbapp.dev/"];
const EMAIL_API_URL = "https://api.resend.com/emails";
const EMAIL_FROM = "CKB KeyWay <security@auth.ckbkeyway.dev>";
const SECP256K1_CODE_HASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
// KeyWay's own testnet Omnilock, by data hash (src/sdk/browser/account-lock.ts KEYWAY_OMNILOCK.testnet).
const OMNILOCK_CODE_HASH = "0x6b29b6f10346b43c540e53806ba88ba0fe3a0c3a29d7448ef555840c8f8318fa";
// The official testnet Omnilock (CCC's KnownScript.OmniLock), by type: the same lock, so the same rules apply.
const OFFICIAL_OMNILOCK_CODE_HASH = "0xf329effd1c475a2978453c8600e1eaf0bc2087ee093c3ee64cc96ec6847752cb";
const JOYID_CODE_HASH = "0xd23761b364210735c19c60561d213fb3beae2fd6172743719eff6920e020baac";
// An indexer more than this many blocks behind its node's tip could miss a send-limit cell, so it isn't believed; nor is
// a node whose tip is older than this (its whole chain may have stalled behind the network's).
const MAX_INDEXER_LAG = 3n;
const MAX_TIP_AGE_MS = 10 * 60_000;
// Pages of one block's history (1024 transactions each) read for one lock; a block can't hold this many.
const MAX_HISTORY_PAGES = 4;
const TYPE_ID_CODE_HASH = "0x00000000000000000000000000000000000000000000000000545950455f4944";
// KeyWay's backup verifiers, version 3 with salted identities (src/sdk/browser/recovery-backups.ts).
const EVM_VERIFIER = "0x14715402af1d6cdb6036ac02d10c822e84349c289c938320c2f7e8bb6d54b86f";
const JOYID_VERIFIER = "0x01ac20c4c1a7e5e073a9369b452382970d7d493ad98169dbfa017df1351e2957";
const VERIFIERS = { evm: EVM_VERIFIER, joyid: JOYID_VERIFIER };
const MAX_BACKUPS = 8;
const SECP_WITNESS_LOCK = 65;
const OMNILOCK_WITNESS_LOCK = 85;
const BINDING_MAGIC = "4b574542"; // "KWEB"
const BINDING_VERSION = 2;
const BINDING_SIZE = 37;
const LIST_MAGIC = "4b57524c"; // "KWRL"
const LIST_VERSION = 3;
const AUTH_LENGTH = 21;
const CODE_TTL_MS = 10 * 60_000;
const MAX_MESSAGE_BYTES = 4096;
// The indexer's filters for plain cells (no type script, empty data) and for cells with a Type ID type.
const PLAIN_FILTER = { script_len_range: ["0x0", "0x1"], output_data_len_range: ["0x0", "0x1"] };
const TYPE_ID_FILTER = { script: { code_hash: TYPE_ID_CODE_HASH, hash_type: "type", args: "0x" } };

// ---------- bytes ----------

function hexToBytes(value, what) {
  if (typeof value !== "string" || !/^0x([0-9a-fA-F]{2})*$/.test(value)) throw new Error(`${what || "value"} must be 0x-prefixed hex`);
  const out = new Uint8Array((value.length - 2) / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(value.slice(2 + i * 2, 4 + i * 2), 16);
  return out;
}

function bytesToHex(bytes) {
  let out = "0x";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
}

function u32(value) {
  return Uint8Array.of(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
}

function u64(value) {
  let big = BigInt(value);
  if (big < 0n || big >= 1n << 64n) throw new Error("u64 out of range");
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) { out[i] = Number(big & 0xffn); big >>= 8n; }
  return out;
}

function readU32(bytes, at) {
  if (at + 4 > bytes.length) throw new Error("molecule data is truncated");
  return (bytes[at] | (bytes[at + 1] << 8) | (bytes[at + 2] << 16) | (bytes[at + 3] << 24)) >>> 0;
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

const utf8 = (text) => new TextEncoder().encode(text);

// ---------- blake2b-256, personalised "ckb-default-hash" ----------

const IV32 = [0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
  0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19];
const SIGMA = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
  11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
  9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
  12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
  6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
].map((x) => x * 2);
const CKB_PERSONAL = utf8("ckb-default-hash");

class Blake2b {
  constructor() {
    this.h = new Uint32Array(16);
    this.v = new Uint32Array(32);
    this.m = new Uint32Array(32);
    this.b = new Uint8Array(128);
    this.c = 0;
    this.t = 0;
    const param = new Uint8Array(64);
    param[0] = 32; param[2] = 1; param[3] = 1;
    param.set(CKB_PERSONAL, 48);
    for (let i = 0; i < 16; i++) this.h[i] = IV32[i] ^ readU32(param, i * 4);
  }

  update(bytes) {
    for (let i = 0; i < bytes.length; i++) {
      if (this.c === 128) { this.t += this.c; this.compress(false); this.c = 0; }
      this.b[this.c++] = bytes[i];
    }
    return this;
  }

  digest() {
    this.t += this.c;
    while (this.c < 128) this.b[this.c++] = 0;
    this.compress(true);
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = this.h[i >> 2] >>> (8 * (i & 3));
    return out;
  }

  compress(last) {
    const { v, m, h } = this;
    for (let i = 0; i < 16; i++) { v[i] = h[i]; v[i + 16] = IV32[i]; }
    v[24] ^= this.t;
    v[25] ^= Math.floor(this.t / 0x100000000);
    if (last) { v[28] = ~v[28]; v[29] = ~v[29]; }
    for (let i = 0; i < 32; i++) m[i] = readU32(this.b, i * 4);
    for (let i = 0; i < 12; i++) {
      const s = i * 16;
      g(v, m, 0, 8, 16, 24, SIGMA[s], SIGMA[s + 1]);
      g(v, m, 2, 10, 18, 26, SIGMA[s + 2], SIGMA[s + 3]);
      g(v, m, 4, 12, 20, 28, SIGMA[s + 4], SIGMA[s + 5]);
      g(v, m, 6, 14, 22, 30, SIGMA[s + 6], SIGMA[s + 7]);
      g(v, m, 0, 10, 20, 30, SIGMA[s + 8], SIGMA[s + 9]);
      g(v, m, 2, 12, 22, 24, SIGMA[s + 10], SIGMA[s + 11]);
      g(v, m, 4, 14, 16, 26, SIGMA[s + 12], SIGMA[s + 13]);
      g(v, m, 6, 8, 18, 28, SIGMA[s + 14], SIGMA[s + 15]);
    }
    for (let i = 0; i < 16; i++) h[i] = h[i] ^ v[i] ^ v[i + 16];
  }
}

function add64(v, a, b0, b1) {
  const lo = v[a] + b0;
  v[a + 1] = v[a + 1] + b1 + (lo >= 0x100000000 ? 1 : 0);
  v[a] = lo;
}

function g(v, m, a, b, c, d, ix, iy) {
  add64(v, a, v[b], v[b + 1]); add64(v, a, m[ix], m[ix + 1]);
  let x0 = v[d] ^ v[a]; let x1 = v[d + 1] ^ v[a + 1];
  v[d] = x1; v[d + 1] = x0;
  add64(v, c, v[d], v[d + 1]);
  x0 = v[b] ^ v[c]; x1 = v[b + 1] ^ v[c + 1];
  v[b] = (x0 >>> 24) ^ (x1 << 8); v[b + 1] = (x1 >>> 24) ^ (x0 << 8);
  add64(v, a, v[b], v[b + 1]); add64(v, a, m[iy], m[iy + 1]);
  x0 = v[d] ^ v[a]; x1 = v[d + 1] ^ v[a + 1];
  v[d] = (x0 >>> 16) ^ (x1 << 16); v[d + 1] = (x1 >>> 16) ^ (x0 << 16);
  add64(v, c, v[d], v[d + 1]);
  x0 = v[b] ^ v[c]; x1 = v[b + 1] ^ v[c + 1];
  v[b] = (x1 >>> 31) ^ (x0 << 1); v[b + 1] = (x0 >>> 31) ^ (x1 << 1);
}

function ckbHash(...parts) {
  const hasher = new Blake2b();
  for (const part of parts) hasher.update(typeof part === "number" ? Uint8Array.of(part) : part);
  return hasher.digest();
}

// ---------- molecule ----------

const HASH_TYPES = { data: 0, type: 1, data1: 2, data2: 4 };

function fixvec(items) { return concat(u32(items.length), ...items); }
function table(fields) {
  const header = 4 * (fields.length + 1);
  const offsets = [];
  let at = header;
  for (const field of fields) { offsets.push(at); at += field.length; }
  return concat(u32(at), ...offsets.map(u32), ...fields);
}
function dynvec(items) {
  if (items.length === 0) return u32(4);
  return table(items);
}
const molBytes = (bytes) => concat(u32(bytes.length), bytes);

function encodeScript(script) {
  return table([script.codeHash, Uint8Array.of(HASH_TYPES[script.hashType]), molBytes(script.args)]);
}
function encodeOutPoint(outPoint) { return concat(outPoint.txHash, u32(outPoint.index)); }
function encodeCellInput(input) { return concat(u64(input.since), encodeOutPoint(input.previousOutput)); }
function encodeCellOutput(output) {
  return table([u64(output.capacity), encodeScript(output.lock), output.type ? encodeScript(output.type) : new Uint8Array(0)]);
}

function rawTransactionHash(tx) {
  const raw = table([
    u32(tx.version),
    fixvec(tx.cellDeps.map((dep) => concat(encodeOutPoint(dep.outPoint), Uint8Array.of(dep.depType)))),
    fixvec(tx.headerDeps),
    fixvec(tx.inputs.map(encodeCellInput)),
    dynvec(tx.outputs.map(encodeCellOutput)),
    dynvec(tx.outputsData.map(molBytes)),
  ]);
  return ckbHash(raw);
}

const scriptHash = (script) => ckbHash(encodeScript(script));
const typeIdArgs = (input, index) => ckbHash(encodeCellInput(input), u64(index));

/** WitnessArgs { lock, input_type, output_type }, each optional; throws on anything else. */
function parseWitnessArgs(bytes) {
  if (bytes.length < 16) throw new Error("witness isn't WitnessArgs");
  const total = readU32(bytes, 0);
  const first = readU32(bytes, 4);
  if (total !== bytes.length || first !== 16) throw new Error("witness isn't WitnessArgs");
  const offsets = [readU32(bytes, 4), readU32(bytes, 8), readU32(bytes, 12), total];
  const fields = [];
  for (let i = 0; i < 3; i++) {
    if (offsets[i] > offsets[i + 1] || offsets[i + 1] > total) throw new Error("witness isn't WitnessArgs");
    const field = bytes.slice(offsets[i], offsets[i + 1]);
    if (field.length === 0) { fields.push(undefined); continue; }
    if (field.length < 4 || readU32(field, 0) !== field.length - 4) throw new Error("witness isn't WitnessArgs");
    fields.push(field.slice(4));
  }
  return { lock: fields[0], inputType: fields[1], outputType: fields[2] };
}

function encodeWitnessArgs(witness) {
  const opt = (field) => field === undefined ? new Uint8Array(0) : molBytes(field);
  return table([opt(witness.lock), opt(witness.inputType), opt(witness.outputType)]);
}

// ---------- transactions ----------

function parseScript(value, what) {
  if (!value || typeof value !== "object") throw new Error(`${what} is invalid`);
  const codeHash = hexToBytes(value.codeHash ?? value.code_hash, what);
  const hashType = value.hashType ?? value.hash_type;
  if (codeHash.length !== 32 || !Object.prototype.hasOwnProperty.call(HASH_TYPES, hashType)) throw new Error(`${what} is invalid`);
  return { codeHash, hashType, args: hexToBytes(value.args, what) };
}

function num(value, what) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{1,16}$/.test(value)) throw new Error(`${what} is invalid`);
  return BigInt(value);
}

/** Reads a transaction in CCC's JSON form or the RPC's. Inputs' cached cells, if any, are ignored. */
function parseTransaction(value) {
  if (!value || typeof value !== "object") throw new Error("A complete transaction is required");
  const list = (key, alt) => {
    const items = value[key] ?? value[alt];
    if (!Array.isArray(items)) throw new Error(`transaction ${key} is missing`);
    return items;
  };
  const outPoint = (item) => {
    const txHash = hexToBytes(item?.txHash ?? item?.tx_hash, "out point");
    if (txHash.length !== 32) throw new Error("out point is invalid");
    const index = Number(num(item.index, "out point index"));
    return { txHash, index };
  };
  const tx = {
    version: Number(num(value.version, "version")),
    cellDeps: list("cellDeps", "cell_deps").map((dep) => {
      const type = dep.depType ?? dep.dep_type;
      if (type !== "code" && type !== "depGroup" && type !== "dep_group") throw new Error("cell dep type is invalid");
      return { outPoint: outPoint(dep.outPoint ?? dep.out_point), depType: type === "code" ? 0 : 1 };
    }),
    headerDeps: list("headerDeps", "header_deps").map((hash) => {
      const bytes = hexToBytes(hash, "header dep");
      if (bytes.length !== 32) throw new Error("header dep is invalid");
      return bytes;
    }),
    inputs: list("inputs").map((input) => ({ previousOutput: outPoint(input.previousOutput ?? input.previous_output), since: num(input.since, "since") })),
    outputs: list("outputs").map((output, index) => ({
      capacity: num(output.capacity, "capacity"),
      lock: parseScript(output.lock, `output ${index} lock`),
      type: output.type ? parseScript(output.type, `output ${index} type`) : undefined,
    })),
    outputsData: list("outputsData", "outputs_data").map((data) => hexToBytes(data, "output data")),
    witnesses: list("witnesses").map((witness) => hexToBytes(witness, "witness")),
  };
  if (tx.outputs.length !== tx.outputsData.length) throw new Error("outputs and outputs data differ in length");
  return tx;
}

const sameScript = (a, b) => Boolean(a && b) && a.hashType === b.hashType && equalBytes(a.codeHash, b.codeHash) && equalBytes(a.args, b.args);

/** CKB's sighash-all for the lock group whose first input is `first`, exactly as CCC's getSignHashInfo hashes it. */
function sighash(tx, inputLocks, lock) {
  const hasher = new Blake2b().update(rawTransactionHash(tx));
  let first = -1;
  for (let i = 0; i < tx.witnesses.length; i++) {
    if (i < tx.inputs.length) {
      if (!sameScript(inputLocks[i], lock)) continue;
      if (first === -1) first = i;
    }
    if (first === -1) throw new Error("lock group has no input");
    hasher.update(u64(tx.witnesses[i].length)).update(tx.witnesses[i]);
  }
  if (first === -1) throw new Error("lock group has no witness");
  return { digest: hasher.digest(), first };
}

// ---------- chain ----------

/** Fetches transactions by hash in one batch call, and checks each against its hash. */
async function fetchTransactions(hashes, urls = RPC_URLS) {
  const unique = [...new Set(hashes)];
  if (unique.length === 0) return new Map();
  const body = JSON.stringify(unique.map((hash, id) => ({ id, jsonrpc: "2.0", method: "get_transaction", params: [hash] })));
  let lastError;
  for (const url of urls) {
    try {
      const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body, redirect: "error" });
      if (!response.ok) throw new Error(`CKB RPC returned HTTP ${response.status}`);
      const results = await response.json();
      if (!Array.isArray(results)) throw new Error("CKB RPC returned an invalid batch");
      const found = new Map();
      for (const result of results) {
        const hash = unique[result?.id];
        const view = result?.result;
        if (hash === undefined || !view?.transaction) continue;
        const tx = parseTransaction(view.transaction);
        if (bytesToHex(rawTransactionHash(tx)) !== hash) throw new Error("CKB RPC returned a transaction that doesn't match its hash");
        found.set(hash, { tx, status: view.tx_status?.status, blockHash: view.tx_status?.block_hash ?? undefined });
      }
      for (const hash of unique) if (!found.has(hash)) throw new Error(`Transaction ${hash} isn't on chain`);
      return found;
    } catch (error) {
      lastError = error;
      if (/doesn't match its hash/.test(error?.message ?? "")) throw error;
    }
  }
  throw lastError ?? new Error("CKB RPC is unavailable");
}

/** The indexer's search key for cells or history under exactly this lock, with an optional filter. */
function lockSearchKey(lock, filter) {
  return {
    script: { code_hash: bytesToHex(lock.codeHash), hash_type: lock.hashType, args: bytesToHex(lock.args) },
    script_type: "lock",
    // Exact: the indexer's default is prefix, which would also return cells under longer args that no key of this
    // account can spend, so anyone could plant one to block every check below.
    script_search_mode: "exact",
    ...(filter ? { filter } : {}),
  };
}

/**
 * Live cells under a lock, from the indexer, a page of 256 at a time, only those matching `filter` (and `keep`, when
 * given); refuses more than `maxCells` kept or more than `maxPages` pages. Large pages keep a run within Lit's limit
 * on outbound requests.
 */
async function indexerCells(lock, maxCells, filter, urls = RPC_URLS, { keep, maxPages = Infinity } = {}) {
  const searchKey = lockSearchKey(lock, filter);
  const method = "get_cells";
  const pageSize = 0x100;
  const cells = [];
  let cursor = null;
  for (let pages = 1; ; pages++) {
    if (pages > maxPages) throw new Error("This account has too many cells to check");
    const body = JSON.stringify({ id: 0, jsonrpc: "2.0", method, params: [searchKey, "asc", `0x${pageSize.toString(16)}`, ...(cursor ? [cursor] : [])] });
    let result;
    let lastError;
    for (const url of urls) {
      try {
        const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body, redirect: "error" });
        if (!response.ok) throw new Error(`CKB RPC returned HTTP ${response.status}`);
        result = (await response.json())?.result;
        if (!result || !Array.isArray(result.objects)) throw new Error(`CKB RPC returned an invalid ${method} page`);
        break;
      } catch (error) {
        result = undefined;
        lastError = error;
      }
    }
    if (!result) throw lastError ?? new Error("CKB RPC is unavailable");
    cells.push(...(keep ? result.objects.filter(keep) : result.objects));
    if (cells.length > maxCells) throw new Error("This account has too many cells to check");
    if (result.objects.length < pageSize || !result.last_cursor) return cells;
    cursor = result.last_cursor;
  }
}

/** One JSON-RPC batch, each call's result in order; any error or missing result fails the batch. */
async function rpcBatch(calls, urls = RPC_URLS) {
  const body = JSON.stringify(calls.map((call, id) => ({ id, jsonrpc: "2.0", ...call })));
  let lastError;
  for (const url of urls) {
    try {
      const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body, redirect: "error" });
      if (!response.ok) throw new Error(`CKB RPC returned HTTP ${response.status}`);
      const replies = await response.json();
      if (!Array.isArray(replies)) throw new Error("CKB RPC returned an invalid batch");
      const results = new Array(calls.length);
      for (const reply of replies) if (Number.isInteger(reply?.id) && reply.id >= 0 && reply.id < calls.length && reply.result) results[reply.id] = reply.result;
      // A sparse array's holes are skipped by some(), so every index is checked.
      for (let i = 0; i < calls.length; i++) if (results[i] === undefined) throw new Error("CKB RPC left a call in the batch unanswered");
      return results;
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError ?? new Error("CKB RPC is unavailable");
}

/**
 * Which of these transactions spent one of the key's cells (secp256k1 address or list lock) as input 0, from the
 * key's own lock history in just the blocks that hold them. Only the key can add inputs to that history, and
 * however long it grows, only these blocks are read.
 */
async function madeByKey(account, candidates, urls, options = {}) {
  const blocks = [...new Set(candidates.map(({ block }) => block))];
  const locks = options.locks ?? [account.secp, account.listLock];
  let pending = blocks.flatMap((block) => locks.map((lock) => ({ block, lock, cursor: undefined })));
  const made = new Set();
  // A block whose page of 1024 transactions is full is read on from its cursor; only after MAX_HISTORY_PAGES full pages
  // (more transactions than a block can hold) is it an error. 256 calls a batch keeps the run within Lit's request limit, with room for the code email.
  for (let round = 0; pending.length > 0; round++) {
    if (round >= MAX_HISTORY_PAGES) throw new Error("A block holds too much of this key's history to check");
    const next = [];
    for (let at = 0; at < pending.length; at += 256) {
      const slice = pending.slice(at, at + 256);
      // Grouped by transaction, so a page counts transactions, not cells: outsiders can't fill one by sending the key
      // thousands of cells in one transaction, and a block can't hold 4 pages of transactions.
      const calls = slice.map(({ block, lock, cursor }) => ({
        method: "get_transactions",
        params: [{ ...lockSearchKey(lock, { block_range: [`0x${block.toString(16)}`, `0x${(block + 1n).toString(16)}`] }), group_by_transaction: true }, "asc", "0x400", ...(cursor ? [cursor] : [])],
      }));
      (await rpcBatch(calls, urls)).forEach((result, i) => {
        if (!Array.isArray(result?.objects)) throw new Error("CKB RPC returned an invalid get_transactions page");
        for (const entry of result.objects) {
          if (!Array.isArray(entry?.cells)) throw new Error("CKB RPC returned an invalid get_transactions page");
          if (entry.cells.some((cell) => Array.isArray(cell) && cell[0] === "input" && (options.anyInput || num(cell[1], "io index") === 0n))) made.add(String(entry.tx_hash).toLowerCase());
        }
        if (result.objects.length >= 0x400) {
          if (typeof result.last_cursor !== "string") throw new Error("CKB RPC returned an invalid get_transactions page");
          next.push({ ...slice[i], cursor: result.last_cursor });
        }
      });
    }
    pending = next;
  }
  return made;
}

/**
 * Refuses a node whose indexer is behind its chain tip: its empty answer could hide a cell that is there. Returns the
 * block the indexer has reached.
 */
async function freshIndexer(urls) {
  const [indexer, tip] = await rpcBatch([{ method: "get_indexer_tip", params: [] }, { method: "get_tip_header", params: [] }], urls);
  const indexed = num(indexer?.block_number, "indexer tip");
  if (num(tip?.number, "tip block number") - indexed > MAX_INDEXER_LAG) throw new Error("CKB RPC's indexer is behind the chain");
  if (Date.now() - Number(num(tip?.timestamp, "tip timestamp")) > MAX_TIP_AGE_MS) throw new Error("CKB RPC's chain is behind the network");
  return indexed;
}

/**
 * The type hashes of the live recovery lists this key made, under its owner-only list lock. Anyone can send a
 * cell to that lock, so a cell only counts if the transaction that created it spent one of the account's own
 * cells as input 0, which needs this key's signature (an enable spends the secp256k1 cell there, a change the
 * list itself). That is read from the key's own lock history in the candidate's block, so nothing an outsider
 * made is ever downloaded, and a long history costs nothing: a fake list costs one small indexer query to rule
 * out, however large the transaction that made it. Which
 * cells are live, and the history, are the node's word; the indexer only follows committed blocks.
 */
async function liveLists(account, urls = RPC_URLS) {
  // The candidates and the history must come from the same node: history from a node behind the one that listed a
  // list could leave the list out. A node that fails retries the whole check on the next.
  let lastError;
  for (const url of urls) {
    try {
      return await liveListsAt(account, [url]);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError ?? new Error("CKB RPC is unavailable");
}

async function liveListsAt(account, urls) {
  // Only Type ID cells are asked for, so plain cells sent to the lock can't crowd out the check. Each fake list
  // locks its capacity under this key for good, so blocking with more than 1024 costs an attacker about 131k CKB.
  const objects = (await indexerCells(account.listLock, 1024, TYPE_ID_FILTER, urls)).map((object) => {
    const lock = parseScript(object?.output?.lock, "cell lock");
    const type = object?.output?.type ? parseScript(object.output.type, "cell type") : undefined;
    if (!sameScript(lock, account.listLock) || !isTypeId(type)) throw new Error("CKB RPC returned a cell that isn't under the recovery list lock");
    return { txHash: object?.out_point?.tx_hash, block: num(object?.block_number, "block number"), type };
  });
  if (objects.length === 0) return [];
  // Proof is input 0 spent from the key's own secp256k1 address or its owner-only list lock. An administrator-
  // mode Omnilock doesn't count: anyone can make one with this key's auth and their own list, and spend it with
  // their own backup. A failed lookup fails the whole check rather than leaving a list out.
  const made = await madeByKey(account, objects, urls);
  const hashes = [];
  for (const { txHash, type } of objects) {
    if (typeof txHash === "string" && made.has(txHash.toLowerCase())) hashes.push(bytesToHex(scriptHash(type)));
  }
  return [...new Set(hashes)];
}

const isPlain = (output, data) => !output.type && data.length === 0;

/**
 * The live plain cells at the key's secp256k1 address and the key's live lists, read in that order from one node.
 * An enable that commits at any point is then seen: if it commits after the first read, that read still shows the
 * plain cell it spends as input 0, which this enable must then spend too, so at most one of them can commit; if
 * before, its list is in the second read (a node's view only moves forward). Reading the two from different nodes
 * could pair a newer first read with an older second one, so a failing node retries both on the next.
 */
async function enableView(account) {
  let lastError;
  for (const url of RPC_URLS) {
    try {
      // Only plain cells are asked for, so typed cells sent to the address can't push the count over the limit.
      const plain = (await indexerCells(account.secp, 256, PLAIN_FILTER, [url])).filter((cell) => !cell?.output?.type && (cell?.output_data ?? "0x") === "0x");
      const lists = await liveLists(account, [url]);
      return { plain, lists };
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError ?? new Error("CKB RPC is unavailable");
}

async function inputCellsOf(tx) {
  const found = await fetchTransactions(tx.inputs.map((input) => bytesToHex(input.previousOutput.txHash)));
  return tx.inputs.map((input) => {
    const hash = bytesToHex(input.previousOutput.txHash);
    const { tx: previous, status, blockHash } = found.get(hash);
    const index = input.previousOutput.index;
    if (index >= previous.outputs.length) throw new Error("An input doesn't exist");
    return { output: previous.outputs[index], data: previous.outputsData[index], createdBy: previous, createdByHash: hash, createdStatus: status, createdBlockHash: blockHash, outputIndex: index };
  });
}

// ---------- the account ----------

async function accountOf(pkpId) {
  const privateKey = await Lit.Actions.getPrivateKey({ pkpId });
  const signingKey = new ethers.utils.SigningKey(privateKey);
  return accountFromKey(hexToBytes(signingKey.compressedPublicKey, "public key"), signingKey);
}

/** The account of a compressed public key. Without a signing key it can only plan, never sign. */
function accountFromKey(publicKey, signingKey) {
  if (publicKey.length !== 33 || (publicKey[0] !== 2 && publicKey[0] !== 3)) throw new Error("publicKey must be a compressed secp256k1 key");
  const blake160 = ckbHash(publicKey).slice(0, 20);
  return {
    signingKey,
    publicKey,
    blake160,
    secp: { codeHash: hexToBytes(SECP256K1_CODE_HASH), hashType: "type", args: blake160 },
    listLock: { codeHash: hexToBytes(OMNILOCK_CODE_HASH), hashType: "data1", args: concat([0x00], blake160, [0x00]) },
  };
}

/** "secp256k1", "omnilock" (the account's address in administrator mode), "list" (the AdminList's owner-only lock) or undefined. */
function lockKind(account, lock) {
  if (sameScript(lock, account.secp)) return "secp256k1";
  if (lock.hashType !== "data1" || bytesToHex(lock.codeHash) !== OMNILOCK_CODE_HASH) return undefined;
  const args = lock.args;
  if (args[0] !== 0x00 || !equalBytes(args.slice(1, 21), account.blake160)) return undefined;
  if (args.length === 22 && args[21] === 0x00) return "list";
  if (args.length === 54 && args[21] === 0x01) return "omnilock";
  return undefined;
}

/**
 * Whether a lock names this key (its blake160 or public key anywhere in the args) without being one of the account's
 * own shapes: anyone-can-pay, another Omnilock deployment or hash type, secp256k1 by data hash, and the like, which
 * the key's signature may unlock but whose cells nothing here counts. Decided from the lock alone, never from
 * witnesses, which other parties can change after the Action signs.
 */
function foreignKeyLock(account, lock) {
  if (lockKind(account, lock)) return false;
  const contains = (haystack, needle) => {
    for (let i = 0; i + needle.length <= haystack.length; i++) if (equalBytes(haystack.slice(i, i + needle.length), needle)) return true;
    return false;
  };
  return contains(lock.args, account.blake160) || contains(lock.args, account.publicKey);
}

/**
 * An Omnilock of this key in administrator mode (flag bit 0) that isn't the account's own shape: other flags
 * (anyone-can-pay, time lock, …) or the official Omnilock deployment. The named list's members could spend it
 * as well, and KeyWay never builds one, so no output may go to one.
 */
function strayAdminOmnilock(account, lock) {
  const omnilock = (lock.hashType === "data1" && bytesToHex(lock.codeHash) === OMNILOCK_CODE_HASH)
    || (lock.hashType === "type" && bytesToHex(lock.codeHash) === OFFICIAL_OMNILOCK_CODE_HASH);
  const args = lock.args;
  if (!omnilock || args.length < 22 || args[0] !== 0x00 || !equalBytes(args.slice(1, 21), account.blake160)) return false;
  return (args[21] & 0x01) === 0x01 && lockKind(account, lock) !== "omnilock";
}

/** The AdminList type hashes the account's administrator-mode Omnilock locks in this transaction name. */
function adminRefs(account, locks) {
  const refs = new Set();
  for (const lock of locks) if (lockKind(account, lock) === "omnilock") refs.add(bytesToHex(lock.args.slice(22)));
  return refs;
}

const isTypeId = (type) => Boolean(type) && type.hashType === "type" && bytesToHex(type.codeHash) === TYPE_ID_CODE_HASH;

// ---------- the recovery list ----------

/** AdminList data: RCData union item 0 (RCRule) with an SMT root and flags 0x02 (whitelist). */
function listRoot(data) {
  if (data.length !== 37 || readU32(data, 0) !== 0 || data[36] !== 0x02) throw new Error("The recovery list's data is malformed");
  return data.slice(4, 36);
}

/** A version 3 list record ("KWRL" ‖ 0x03 ‖ count ‖ 21-byte auths of 0xFD ‖ blake160(preimage)), as its auths. */
function parseListRecord(bytes) {
  if (!bytes || bytes.length < 6 || bytesToHex(bytes.slice(0, 4)) !== `0x${LIST_MAGIC}` || bytes[4] !== LIST_VERSION) throw new Error("The recovery list record is malformed");
  const count = bytes[5];
  if (count < 1 || count > MAX_BACKUPS || bytes.length !== 6 + count * AUTH_LENGTH) throw new Error("The recovery list record has the wrong number of backups");
  const auths = [];
  for (let at = 6; at < bytes.length; at += AUTH_LENGTH) {
    if (bytes[at] !== 0xfd) throw new Error("The recovery list record is malformed");
    auths.push(bytes.slice(at, at + AUTH_LENGTH));
  }
  if (new Set(auths.map(bytesToHex)).size !== auths.length) throw new Error("A backup is listed twice");
  return auths;
}

const blake160 = (...parts) => ckbHash(...parts).slice(0, 20);

/**
 * A backup's auth in the account with this salt (its AdminList type hash), as recovery-backups.ts builds it:
 * 0xFD ‖ blake160(verifier ‖ 0x02 (data1) ‖ 0x00 (cell dep) ‖ 8 zero bytes (whole cell) ‖ blake160(id ‖ salt)).
 */
function backupAuth(backup, salt) {
  const preimage = concat(hexToBytes(VERIFIERS[backup.kind]), [0x02, 0x00], new Uint8Array(8), blake160(backup.id, salt));
  return concat([0xfd], blake160(preimage));
}

/** The caller's `backups` param: KeyWay backup kinds with 20-byte ids, no duplicates. */
function parseBackups(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_BACKUPS + 1) throw new Error("backups is required for a recovery list change");
  const backups = value.map((entry) => {
    if (!entry || typeof entry !== "object" || (entry.kind !== "evm" && entry.kind !== "joyid")) throw new Error("A backup must be an EVM wallet or a JoyID passkey");
    const id = hexToBytes(entry.id, "backup id");
    if (id.length !== 20) throw new Error("A backup's id must be 20 bytes");
    return { kind: entry.kind, id };
  });
  if (new Set(backups.map((backup) => `${backup.kind}:${bytesToHex(backup.id)}`)).size !== backups.length) throw new Error("A backup is listed twice");
  return backups;
}

/**
 * Names every auth in `auths` by the backup whose salted auth it is. An auth no given backup produces (another
 * salt, an old or foreign verifier, an unknown backup) is refused, and so is a given backup that isn't listed.
 */
function resolveBackups(value, auths, salt) {
  const byAuth = new Map(parseBackups(value).map((backup) => [bytesToHex(backupAuth(backup, salt)), backup]));
  const wanted = new Set(auths.map(bytesToHex));
  const resolved = new Map();
  for (const auth of wanted) {
    const backup = byAuth.get(auth);
    if (!backup) throw new Error("The recovery list names a backup KeyWay doesn't support");
    resolved.set(auth, backup);
  }
  for (const auth of byAuth.keys()) if (!wanted.has(auth)) throw new Error("A backup given isn't on the recovery list");
  return resolved;
}

/** A backup as the user knows it: an EVM wallet's address, or a JoyID account's full CKB address. */
function describeBackup(backup) {
  if (backup.kind === "evm") return `EVM wallet ${bytesToHex(backup.id)}`;
  return `JoyID ${testnetAddress({ codeHash: hexToBytes(JOYID_CODE_HASH), hashType: "type", args: concat([0x00, 0x01], backup.id) })}`;
}

// Sparse Merkle tree root (nervosnetwork/sparse-merkle-tree 0.6.1, as src/sdk/browser/recovery-smt.ts).
const getBit = (key, i) => ((key[i >> 3] >> (i & 7)) & 1) === 1;
const isZero = (bytes) => bytes.every((b) => b === 0);
function setBit(key, i) { const out = key.slice(); out[i >> 3] |= 1 << (i & 7); return out; }
function parentPath(key, height) {
  if (height === 255) return new Uint8Array(32);
  const start = height + 1;
  const out = new Uint8Array(32);
  const startByte = start >> 3;
  out.set(key.slice(startByte), startByte);
  if (start & 7) out[startByte] &= (0xff << (start & 7)) & 0xff;
  return out;
}
const zeroValue = () => ({ kind: "value", value: new Uint8Array(32) });
const mergeIsZero = (value) => value.kind === "value" && isZero(value.value);
const mergeHash = (value) => value.kind === "value" ? value.value : ckbHash(2, value.baseNode, value.zeroBits, value.zeroCount);
function mergeWithZero(height, nodeKey, value, setRight) {
  if (value.kind === "value") return { kind: "zeros", baseNode: ckbHash(height, nodeKey, value.value), zeroBits: setRight ? setBit(new Uint8Array(32), height) : new Uint8Array(32), zeroCount: 1 };
  return { ...value, zeroBits: setRight ? setBit(value.zeroBits, height) : value.zeroBits, zeroCount: (value.zeroCount + 1) & 0xff };
}
function merge(height, nodeKey, lhs, rhs) {
  if (mergeIsZero(lhs) && mergeIsZero(rhs)) return zeroValue();
  if (mergeIsZero(lhs)) return mergeWithZero(height, nodeKey, rhs, true);
  if (mergeIsZero(rhs)) return mergeWithZero(height, nodeKey, lhs, false);
  return { kind: "value", value: ckbHash(1, height, nodeKey, mergeHash(lhs), mergeHash(rhs)) };
}

/** The whitelist root for these auths: each key is the 21-byte auth and 11 zero bytes, each value 0x01 ‖ 31 zeros. */
function whitelistRoot(auths) {
  const branches = new Map();
  const value = concat([0x01], new Uint8Array(31));
  let root = new Uint8Array(32);
  for (const auth of auths) {
    let currentKey = concat(auth, new Uint8Array(11));
    let node = { kind: "value", value };
    for (let height = 0; height <= 255; height++) {
      const parentKey = parentPath(currentKey, height);
      const branchKey = `${height}:${bytesToHex(parentKey)}`;
      const branch = branches.get(branchKey);
      const right = getBit(currentKey, height);
      const [left, rightNode] = branch ? (right ? [branch.left, node] : [node, branch.right]) : (right ? [zeroValue(), node] : [node, zeroValue()]);
      branches.set(branchKey, { left, right: rightNode });
      currentKey = parentKey;
      node = merge(height, parentKey, left, rightNode);
    }
    root = mergeHash(node);
  }
  return root;
}

/** The auths a list cell holds, from the record its creating transaction wrote, checked against its root. */
function listMembers(record, data) {
  const auths = parseListRecord(record);
  if (!equalBytes(whitelistRoot(auths), listRoot(data))) throw new Error("The recorded backups don't match the recovery list's root");
  return auths;
}

function recordAt(tx, index) {
  const witness = tx.witnesses[index];
  if (!witness || witness.length === 0) return undefined;
  try { return parseWitnessArgs(witness).outputType; } catch { return undefined; }
}

// ---------- the email binding ----------

/** "KWEB" ‖ 0x02 ‖ the 32-byte fingerprint of the account's email, BINDING_SIZE bytes. The email itself is never on chain. */
function encodeBinding(fingerprint) {
  const out = new Uint8Array(BINDING_SIZE);
  out.set(hexToBytes(`0x${BINDING_MAGIC}`), 0);
  out[4] = BINDING_VERSION;
  out.set(fingerprint, 5);
  return out;
}

function decodeBinding(bytes) {
  if (!bytes || bytes.length !== BINDING_SIZE || bytesToHex(bytes.slice(0, 4)) !== `0x${BINDING_MAGIC}` || bytes[4] !== BINDING_VERSION) throw new Error("The email binding is malformed");
  return bytes.slice(5);
}

function checkEmail(email) {
  if (typeof email !== "string" || email.length > 254 || !/^[^\s@<>",;]{1,64}@[A-Za-z0-9.-]{1,189}\.[A-Za-z]{2,63}$/.test(email)) throw new Error("A valid email address is required");
  return email;
}

/**
 * The fingerprint of an email for this account: HMAC-SHA256 under a key derived from the PKP's own private key.
 * Only an Action holding this PKP can compute it, so nobody can test guesses against the chain, the same email
 * gives unrelated fingerprints on different accounts, and it doesn't depend on this Action's CID, so a later
 * version of the Action still recognises it.
 */
async function emailFingerprint(pkpId, email) {
  const raw = String(await Lit.Actions.getPrivateKey({ pkpId }));
  const secret = hexToBytes(raw.startsWith("0x") ? raw : `0x${raw}`, "private key");
  if (secret.length !== 32) throw new Error("The PKP's private key has the wrong length");
  const material = concat(utf8("keyway-email-binding-key/v1"), secret);
  secret.fill(0);
  const keyBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", material));
  material.fill(0);
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  keyBytes.fill(0);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(`keyway-email-binding/v2|${pkpId.toLowerCase()}|${email.toLowerCase()}`)));
}

/** The address the server passed, if its fingerprint is `bound` (compared in constant time). */
async function emailMatching(pkpId, bound, email, refusal) {
  const given = await emailFingerprint(pkpId, checkEmail(email));
  let diff = bound.length ^ given.length;
  for (let i = 0; i < given.length; i++) diff |= bound[i] ^ given[i];
  if (diff !== 0) throw new Error(refusal);
  return email;
}

/** The address the server passed, if its fingerprint is the one bound on chain. */
async function emailMatchingBinding(pkpId, binding, email) {
  return emailMatching(pkpId, decodeBinding(binding), email, "This isn't the email address bound to this account's recovery");
}

/**
 * The email bound when this account turned recovery on, or undefined for an account that turned it on before
 * this Action existed. The enabling transaction is the only one that could spend the input its Type ID comes
 * from, and its witness 0 must carry a valid signature by this account's key over the binding.
 */
async function boundEmail(pkpId, account, listType, enableHash, email) {
  if (typeof enableHash !== "string" || !/^0x[0-9a-f]{64}$/.test(enableHash)) throw new Error("enableTransactionHash is required for a recovery list change");
  const enable = (await fetchTransactions([enableHash])).get(enableHash);
  if (enable.status !== "committed") throw new Error("The transaction that turned recovery on isn't committed");
  const tx = enable.tx;
  if (!sameScript(tx.outputs[0]?.type, listType) || !equalBytes(typeIdArgs(tx.inputs[0], 0), listType.args)) {
    throw new Error("enableTransactionHash isn't the transaction that made this recovery list");
  }
  const inputs = await inputCellsOf(tx);
  if (lockKind(account, inputs[0].output.lock) !== "secp256k1") throw new Error("This recovery list wasn't made from this account's own cell");
  const witness = parseWitnessArgs(tx.witnesses[0] ?? new Uint8Array(0));
  if (witness.inputType === undefined) return undefined;
  if (!witness.lock || witness.lock.length !== SECP_WITNESS_LOCK) throw new Error("The email binding isn't signed");
  const unsigned = { ...tx, witnesses: [encodeWitnessArgs({ ...witness, lock: new Uint8Array(SECP_WITNESS_LOCK) }), ...tx.witnesses.slice(1)] };
  const { digest } = sighash(unsigned, inputs.map((cell) => cell.output.lock), account.secp);
  const signature = witness.lock;
  const recovered = ethers.utils.recoverPublicKey(digest, { r: bytesToHex(signature.slice(0, 32)), s: bytesToHex(signature.slice(32, 64)), recoveryParam: signature[64] });
  if (!equalBytes(hexToBytes(ethers.utils.computePublicKey(recovered, true)), account.publicKey)) throw new Error("The email binding isn't signed by this account");
  return emailMatchingBinding(pkpId, witness.inputType, email);
}

// ---------- policy ----------

/**
 * Works out what a transaction does to the account and refuses anything outside the rules. The recovery list
 * (the AdminList) may only be created when turning recovery on, or changed by adding or removing exactly one
 * backup, never moved to another lock, given another Type ID, destroyed or duplicated.
 */
async function analyse(pkpId, params) {
  const tx = parseTransaction(params.transaction);
  if (tx.version !== 0) throw new Error("Only transaction version 0 is allowed");
  if (tx.inputs.length === 0 || tx.inputs.length > 256 || tx.outputs.length > 256) throw new Error("transaction size is out of range");
  const planning = params.mode === "plan";
  const account = planning ? accountFromKey(hexToBytes(params.publicKey, "publicKey")) : await accountOf(pkpId);
  const inputs = await inputCellsOf(tx);
  const inputLocks = inputs.map((cell) => cell.output.lock);
  const refs = adminRefs(account, [...inputLocks, ...tx.outputs.map((output) => output.lock)]);
  const outputRefs = adminRefs(account, tx.outputs.map((output) => output.lock));
  const referenced = (output) => isTypeId(output.type) && refs.has(bytesToHex(scriptHash(output.type)));
  // A plain cell someone sent to the list lock isn't a list; any output under that lock is treated as one.
  const listInputs = inputs.map((cell, index) => ({ ...cell, index }))
    .filter((cell) => (lockKind(account, cell.output.lock) === "list" && isTypeId(cell.output.type)) || referenced(cell.output));
  const listOutputs = tx.outputs.map((output, index) => ({ output, index })).filter(({ output }) => lockKind(account, output.lock) === "list" || referenced(output));

  if (tx.outputs.some((output) => strayAdminOmnilock(account, output.lock))) throw new Error("An output goes to an Omnilock of this key that KeyWay doesn't use");

  const groups = [];
  inputLocks.forEach((lock) => {
    const kind = lockKind(account, lock);
    if (kind && !groups.some((group) => sameScript(group.lock, lock))) groups.push({ lock, kind });
  });
  if (groups.length === 0) throw new Error("The transaction spends nothing of this account's");
  // Locks naming this key that KeyWay never uses: the key's signature may unlock them, and nothing below would count
  // what they hold, so they can't be spent here at all.
  if (inputLocks.some((lock) => foreignKeyLock(account, lock))) throw new Error("An input is locked to this key in a form KeyWay doesn't use");

  let op = { kind: "plain" };
  // Outside turning recovery on, the account's recovery address may only be the one naming its live list, so no
  // transaction can move funds to an address whose list someone else made.
  if (outputRefs.size > 0 && !(listInputs.length === 0 && listOutputs.length === 1)) {
    const lists = await liveLists(account);
    if (lists.length !== 1 || [...outputRefs].some((ref) => ref !== lists[0])) throw new Error("An output goes to an address with another recovery list");
  }
  if (listInputs.length > 1 || listOutputs.length > 1) throw new Error("A transaction may touch only one recovery list");
  if (listInputs.length === 0 && listOutputs.length === 1) {
    const { output, index } = listOutputs[0];
    if (index !== 0) throw new Error("The new recovery list must be output 0");
    if (!sameScript(output.lock, account.listLock)) throw new Error("The new recovery list must be locked to this account's key alone");
    if (!isTypeId(output.type) || !equalBytes(output.type.args, typeIdArgs(tx.inputs[0], 0))) throw new Error("The new recovery list's Type ID must come from input 0");
    if (lockKind(account, inputLocks[0]) !== "secp256k1") throw new Error("Input 0 must be this account's own cell");
    // A plain cell, so every enable spends at least one, and the rule below makes any two of them conflict.
    if (!isPlain(inputs[0].output, inputs[0].data)) throw new Error("Input 0 must be a plain CKB cell at this key's address");
    const typeHash = bytesToHex(scriptHash(output.type));
    for (const ref of refs) if (ref !== typeHash) throw new Error("An output goes to an address with another recovery list");
    const view = await enableView(account);
    // First wins: a key that already has a recovery list can never make a second one (and an address with it).
    if (view.lists.length > 0) throw new Error("Recovery is already on for this key");
    // Every live plain cell at the key's secp256k1 address must be spent, so two enables signed before either is
    // indexed spend the same cells and at most one can ever commit.
    const spending = new Set(tx.inputs.map((input) => `${bytesToHex(input.previousOutput.txHash)}:${input.previousOutput.index}`));
    for (const cell of view.plain) {
      const key = `${cell.out_point?.tx_hash}:${Number(num(cell.out_point?.index, "out point index"))}`;
      if (!spending.has(key)) throw new Error("Turning recovery on must spend every plain cell at this key's address");
    }
    const auths = listMembers(recordAt(tx, 0), tx.outputsData[0]);
    // Each listed auth must be a KeyWay backup salted with this list's type hash, the salt the verifiers use.
    const backups = resolveBackups(params.backups, auths, scriptHash(output.type));
    const witness = parseWitnessArgs(tx.witnesses[0] ?? new Uint8Array(0));
    op = { kind: "enable", members: auths.map((auth) => backups.get(bytesToHex(auth))), binding: witness.inputType };
  } else if (listInputs.length === 1) {
    const input = listInputs[0];
    if (listOutputs.length !== 1) throw new Error("A recovery list can't be destroyed");
    // Input 0, as liveLists proves a list by its creating transaction's input 0.
    if (input.index !== 0) throw new Error("The recovery list must be input 0");
    const { output, index } = listOutputs[0];
    if (!sameScript(input.output.lock, account.listLock)) throw new Error("This recovery list isn't locked to this account's key");
    if (!isTypeId(input.output.type) || !sameScript(output.type, input.output.type)) throw new Error("A recovery list's Type ID can't change");
    if (!sameScript(output.lock, input.output.lock)) throw new Error("A recovery list's lock can't change");
    if (output.capacity !== input.output.capacity) throw new Error("A recovery list's capacity can't change");
    const after = listMembers(recordAt(tx, index), tx.outputsData[index]);
    // The members before: the record the list's own transaction wrote, or for a list made before records
    // existed, the record the caller supplies; either must hash to the list's current root.
    const previous = recordAt(input.createdBy, input.outputIndex) ?? (typeof params.previousListRecord === "string" ? hexToBytes(params.previousListRecord, "previousListRecord") : undefined);
    if (!previous) throw new Error("The recovery list's current backups aren't recorded; previousListRecord is required");
    const before = listMembers(previous, input.data);
    const was = new Set(before.map(bytesToHex));
    const now = new Set(after.map(bytesToHex));
    const added = after.filter((auth) => !was.has(bytesToHex(auth)));
    const removed = before.filter((auth) => !now.has(bytesToHex(auth)));
    if (added.length + removed.length !== 1) throw new Error("A recovery list change must add or remove exactly one backup");
    // Every auth before and after must be a KeyWay backup under this list's salt; the change names the one that moves.
    const backups = resolveBackups(params.backups, [...new Map([...before, ...after].map((auth) => [bytesToHex(auth), auth])).values()], scriptHash(input.output.type));
    const change = added.length ? { kind: "add", backup: backups.get(bytesToHex(added[0])) } : { kind: "remove", backup: backups.get(bytesToHex(removed[0])) };
    // Planning only describes the transaction; the bound address is checked when the code is sent and signed.
    const email = planning ? undefined : await boundEmail(pkpId, account, input.output.type, params.enableTransactionHash, params.email);
    op = { ...change, members: after, email };
  }
  return { tx, account, inputs, inputLocks, groups, op, txHash: rawTransactionHash(tx) };
}

/** Whether the operation needs the emailed code, and the address it goes to. */
async function codeTarget(pkpId, analysis, params) {
  const { op } = analysis;
  if (op.kind === "plain") return undefined;
  if (op.kind === "enable") {
    // Turning recovery on moves everything to an address the backups can spend. On an account with send limits on,
    // that is a send past them, so its code may go only to the address the limits are bound to; otherwise whoever
    // runs this could name their own backup and their own inbox. Accounts without limits bind their address here.
    const live = await liveSettings(analysis.account);
    if (live.length > 1) throw new Error("This account has more than one send-limit cell");
    if (live.length === 1) await emailMatching(pkpId, parseSettings(live[0].data).fingerprint, params.email, "This isn't the email address bound to this account's send limits");
    if (params.mode === "send-code") return checkEmail(params.email);
    if (!op.binding) throw new Error("Turning recovery on must bind the account's email");
    // With limits on, the binding then matches them too, as params.email matches both.
    return emailMatchingBinding(pkpId, op.binding, params.email);
  }
  if (op.email) return op.email;
  // A list made before this Action existed has no binding. With send limits on, a backup change still needs the code
  // at the limits' address (a new backup could move everything); otherwise it keeps the server's checks and the shape
  // rules above.
  const live = await liveSettings(analysis.account);
  if (live.length > 1) throw new Error("This account has more than one send-limit cell");
  if (live.length === 1) return emailMatching(pkpId, parseSettings(live[0].data).fingerprint, params.email, "This isn't the email address bound to this account's send limits");
  return undefined;
}

// ---------- send limits ----------
//
// An account that turns limits on gets one send-limit cell: at its key's secp256k1 address, with a Type ID, holding
// "KWSL" ‖ 0x01 ‖ email fingerprint (32) ‖ flags (1) ‖ CKB amount (u64) ‖ n (1) ‖ n × (token type hash (32) ‖ amount
// (u128)). Every transaction that moves value out must spend it and create its successor (a "chained" send), so any
// two sends that could both commit descend one from the other. The input's witness carries the chain record:
// "KWSR" ‖ 0x01 ‖ count (1) ‖ entries of tx hash (32) ‖ commit time ms (u64, 0 if not known yet) ‖ CKB (u64) ‖
// k (1) ‖ k × (asset (32) ‖ amount (u128)). The last entry is the transaction itself, the others its ancestors in the
// chain that may still be within 24 hours. The 24-hour total is read from those, and past the amount the Action
// asks for the code it emails itself. See research/send-limits/README.md.

const SETTINGS_MAGIC = "4b57534c"; // "KWSL"
const SETTINGS_VERSION = 1;
const RECORD_MAGIC = "4b575352"; // "KWSR"
const RECORD_VERSION = 1;
const UNLIMITED = (1n << 64n) - 1n;
const MAX_LIMIT_TOKENS = 8;
const MAX_ENTRIES = 255;
const WINDOW_MS = 24 * 60 * 60_000;
// Planning keeps entries a little past the window, so one that expires between the preview and the signature is
// still allowed to be in the record (an entry may be dropped only once it is older than 24 hours).
const PLAN_MARGIN_MS = 30 * 60_000;
// A transaction that moves at most this much CKB out, and no tokens, needs no place in the chain: self-transfers,
// merging cells, the legacy sweep, recovery changes. At worst it burns this much as fee.
const EXEMPT_OUTFLOW = 100_000n;
const XUDT_CODE_HASHES = [
  "0x25c29dc317811a6f6f3985a7a9ebc4838bd388d19d0feeecf0bcd60f6c0975bb", // CCC's testnet xUDT
  "0x1142755a044bf2ee358cba9f2da187ce928c91cd4dc8692ded0337efa677d21a", // Stable++'s xUDT copy (RUSD)
  "0xc5e5dcf215925f7ef4dfaf5f4b4f105bc321c02776d6e7d52a1db3fcd9d011a4", // testnet sUDT
];
// The xUDT binary itself, referenced by its data hash (hash_type "data1"), as RGB++ and mainnet tokens do.
const XUDT_DATA1_HASH = "0x50bd8d6680b8b9cf98b73f3c08faf8b2a21914311954118ad6609be6e78a1b95";
const DAO_CODE_HASH = "0x82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e";

function readU64(bytes, at) {
  if (at + 8 > bytes.length) throw new Error("send-limit data is truncated");
  let value = 0n;
  for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(bytes[at + i]);
  return value;
}

function readU128(bytes, at) {
  return readU64(bytes, at) | (readU64(bytes, at + 8) << 64n);
}

function u128(value) {
  return concat(u64(value & ((1n << 64n) - 1n)), u64(value >> 64n));
}

const startsWith = (bytes, magic) => bytes.length >= 4 && bytesToHex(bytes.slice(0, 4)) === `0x${magic}`;

/** A send-limit cell's settings: { fingerprint, tokensUnlimited, ckb (UNLIMITED for none), tokens: Map(asset → amount) }. */
function parseSettings(data) {
  if (!startsWith(data, SETTINGS_MAGIC) || data.length < 47 || data[4] !== SETTINGS_VERSION) throw new Error("The send-limit cell's data is malformed");
  const flags = data[37];
  if (flags & ~0x01) throw new Error("The send-limit cell's data is malformed");
  const count = data[46];
  if (count > MAX_LIMIT_TOKENS || data.length !== 47 + count * 48) throw new Error("The send-limit cell's data is malformed");
  const tokens = new Map();
  for (let i = 0; i < count; i++) {
    const at = 47 + i * 48;
    const asset = bytesToHex(data.slice(at, at + 32));
    if (tokens.has(asset)) throw new Error("The send-limit cell's data is malformed");
    tokens.set(asset, readU128(data, at + 32));
  }
  return { fingerprint: data.slice(5, 37), tokensUnlimited: (flags & 0x01) === 0x01, ckb: readU64(data, 38), tokens };
}

const isSettingsShaped = (account, output, data) => sameScript(output.lock, account.secp) && isTypeId(output.type) && startsWith(data, SETTINGS_MAGIC);

/** How much of an asset may leave in 24 hours without the code; undefined means no limit. */
function allowance(settings, asset) {
  if (asset === "ckb") return settings.ckb === UNLIMITED ? undefined : settings.ckb;
  if (settings.tokens.has(asset)) return settings.tokens.get(asset);
  return settings.tokensUnlimited ? undefined : 0n;
}

/** Whether a settings change lets any asset (a token without an amount of its own included) send more. */
function weakens(before, after) {
  if (after.tokensUnlimited && !before.tokensUnlimited) return true;
  const assets = new Set(["ckb", ...before.tokens.keys(), ...after.tokens.keys()]);
  for (const asset of assets) {
    const was = allowance(before, asset);
    const now = allowance(after, asset);
    if (was !== undefined && (now === undefined || now > was)) return true;
  }
  return false;
}

const isUdt = (type) => (type.hashType === "type" && XUDT_CODE_HASHES.includes(bytesToHex(type.codeHash)))
  || (type.hashType === "data1" && bytesToHex(type.codeHash) === XUDT_DATA1_HASH);
const isDao = (type) => type.hashType === "type" && bytesToHex(type.codeHash) === DAO_CODE_HASH;
/**
 * Type scripts that never stop the account spending a cell of its own: Nervos DAO, Type ID, and a UDT without
 * extension scripts (args of just the owner's lock hash), which can always be burned.
 */
const keepsCkbFree = (type) => !type || isDao(type) || isTypeId(type) || (isUdt(type) && type.args.length === 32);

/**
 * What leaves the account: CKB over all of its locks (the fee included, change back excluded) and, per type script
 * hash, tokens (a UDT's 16-byte amount, any other type by cell). The send-limit cell, the recovery list and Nervos
 * DAO cells aren't tokens; their CKB counts like any other.
 *
 * Any other type script runs whenever its cell is spent, so whoever wrote it could keep the CKB put under it: CKB
 * the account gets back under such a script stays only as far as it already held that much under the same script.
 * A type whose amounts aren't read counts as leaving whenever one of the account's cells of it doesn't come back
 * unchanged, so a balance can't leave while an empty cell of it stays; such assets are returned in `perCell`.
 *
 * Two kinds of value appear in a transaction without leaving an input: the interest a Nervos DAO withdrawal of the
 * account's adds (counted as the account's CKB, so it leaves like the rest), and new supply of a UDT the account
 * issued (the account's own lock is its owner), which counts as leaving wherever it goes.
 */
function outflowOf(account, tx, inputs) {
  let ckb = 0n;
  const tokens = new Map();
  const heldUnder = new Map();
  const unread = new Map();
  const perCell = new Set();
  const count = (output, data, sign) => {
    const kind = lockKind(account, output.lock);
    if (!kind) return;
    const type = output.type;
    if (keepsCkbFree(type)) ckb += sign * output.capacity;
    else {
      // Inputs are counted first, so the outputs see everything the account held under the script.
      const hash = bytesToHex(scriptHash(type));
      const held = heldUnder.get(hash) ?? 0n;
      const amount = sign > 0n || output.capacity < held ? output.capacity : held;
      heldUnder.set(hash, held + sign * amount);
      ckb += sign * amount;
    }
    if (!type || isDao(type)) return;
    if (isTypeId(type) && (kind === "list" || isSettingsShaped(account, output, data))) return;
    const asset = bytesToHex(scriptHash(type));
    const amount = isUdt(type) && data.length >= 16 ? readU128(data, 0) : 1n;
    if (!(isUdt(type) && data.length >= 16)) perCell.add(asset);
    tokens.set(asset, (tokens.get(asset) ?? 0n) + sign * amount);
    if (!isUdt(type)) {
      const cells = unread.get(asset) ?? new Map();
      cells.set(bytesToHex(data), (cells.get(bytesToHex(data)) ?? 0n) + sign);
      unread.set(asset, cells);
    }
  };
  inputs.forEach((cell) => count(cell.output, cell.data, 1n));
  // A phase-2 DAO withdrawal (a DAO cell with its deposit block number as data) lets the outputs exceed the inputs by
  // the interest; that excess is the account's.
  if (inputs.some((cell) => lockKind(account, cell.output.lock) && cell.output.type && isDao(cell.output.type) && cell.data.some((byte) => byte !== 0))) {
    const excess = tx.outputs.reduce((sum, output) => sum + output.capacity, 0n) - inputs.reduce((sum, cell) => sum + cell.output.capacity, 0n);
    if (excess > 0n) ckb += excess;
  }
  tx.outputs.forEach((output, index) => count(output, tx.outputsData[index], -1n));
  for (const [asset, cells] of unread) {
    if ((tokens.get(asset) ?? 0n) <= 0n && [...cells.values()].some((left) => left > 0n)) tokens.set(asset, 1n);
  }
  // Minting: a UDT whose owner (args[0..32]) is the lock hash, or (xUDT's owner mode by type) the type hash, of one
  // of the account's inputs runs in owner mode, so its supply can grow. The growth counts as leaving, wherever it
  // goes; minting to the account itself nets out.
  const ownInputs = inputs.filter((cell) => lockKind(account, cell.output.lock));
  const ownLockHashes = new Set([
    ...ownInputs.map((cell) => bytesToHex(scriptHash(cell.output.lock))),
    ...ownInputs.filter((cell) => cell.output.type).map((cell) => bytesToHex(scriptHash(cell.output.type))),
  ]);
  const supply = new Map();
  const tally = (type, data, sign) => {
    if (!type || !isUdt(type) || type.args.length < 32 || !ownLockHashes.has(bytesToHex(type.args.slice(0, 32)))) return;
    const asset = bytesToHex(scriptHash(type));
    supply.set(asset, (supply.get(asset) ?? 0n) + sign * (data.length >= 16 ? readU128(data, 0) : 0n));
  };
  inputs.forEach((cell) => tally(cell.output.type, cell.data, -1n));
  tx.outputs.forEach((output, index) => tally(output.type, tx.outputsData[index], 1n));
  for (const [asset, minted] of supply) if (minted > 0n) tokens.set(asset, (tokens.get(asset) ?? 0n) + minted);
  const leaving = [...tokens].filter(([, amount]) => amount > 0n).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([asset, amount]) => ({ asset, amount }));
  return { ckb: ckb > 0n ? ckb : 0n, tokens: leaving, perCell };
}

// ---------- the chain record ----------

function encodeEntry(entry) {
  return concat(entry.hash, u64(entry.time), u64(entry.ckb), [entry.tokens.length], ...entry.tokens.map((token) => concat(hexToBytes(token.asset), u128(token.amount))));
}

function encodeRecord(entries) {
  if (entries.length > MAX_ENTRIES) throw new Error("More than 254 limited sends in 24 hours; wait for older ones to leave the window");
  return concat(hexToBytes(`0x${RECORD_MAGIC}`), [RECORD_VERSION, entries.length], ...entries.map(encodeEntry));
}

function parseRecord(bytes) {
  if (!startsWith(bytes, RECORD_MAGIC) || bytes.length < 6 || bytes[4] !== RECORD_VERSION) throw new Error("The send-limit record is malformed");
  const entries = [];
  let at = 6;
  for (let i = 0; i < bytes[5]; i++) {
    if (at + 49 > bytes.length) throw new Error("The send-limit record is malformed");
    const k = bytes[at + 48];
    const end = at + 49 + k * 48;
    if (end > bytes.length) throw new Error("The send-limit record is malformed");
    const tokens = [];
    for (let t = 0; t < k; t++) {
      const from = at + 49 + t * 48;
      tokens.push({ asset: bytesToHex(bytes.slice(from, from + 32)), amount: readU128(bytes, from + 32) });
    }
    entries.push({ hash: bytes.slice(at, at + 32), time: readU64(bytes, at + 32), ckb: readU64(bytes, at + 40), tokens, bytes: bytes.slice(at, end) });
    at = end;
  }
  if (at !== bytes.length) throw new Error("The send-limit record is malformed");
  return entries;
}

/** The record in a witness, if its input_type holds one. */
function recordIn(witness) {
  if (!witness || witness.length === 0) return undefined;
  let args;
  try { args = parseWitnessArgs(witness); } catch { return undefined; }
  return args.inputType && startsWith(args.inputType, RECORD_MAGIC) ? args.inputType : undefined;
}

/**
 * The entries the send-limit input's previous record holds, and a check (run alongside the time lookups) that the
 * input is one this key made: the transaction that created it either spent the previous send-limit cell (its
 * record sits on that input) or is a genesis whose input 0 was a plain cell at the key's secp256k1 address. Both
 * need the key's signature, and the Action checked each earlier step when it signed it.
 */
const NOT_MADE_BY_KEY = "The send-limit cell isn't one this account made";

/** The record-shaped witnesses on the inputs of the transaction that created a send-limit-shaped cell. */
function creatorRecords(created) {
  const records = [];
  created.witnesses.forEach((witness, index) => { const record = recordIn(witness); if (record && index < created.inputs.length) records.push({ index, record }); });
  return records;
}

const outPointKey = (outPoint) => `${bytesToHex(outPoint.txHash)}:${outPoint.index}`;

/**
 * The cells previousEntries reads for these send-limit-shaped inputs (each creator's input 0, or the inputs its
 * records sit on), in one batch, so a transaction destroying many look-alikes costs one request, not one each.
 */
async function creatorCells(shaped) {
  const wanted = shaped.flatMap(({ createdBy, output, outputIndex }) => [
    ...creatorRecords(createdBy).map(({ index }) => createdBy.inputs[index]),
    // Only a cell whose Type ID comes from its creator's input 0 can be a genesis, and needs that input read.
    ...(equalBytes(output.type.args, typeIdArgs(createdBy.inputs[0], outputIndex)) ? [createdBy.inputs[0]] : []),
  ]);
  const cells = wanted.length > 0 ? await inputCellsOf({ inputs: wanted }) : [];
  return new Map(wanted.map((input, i) => [outPointKey(input.previousOutput), cells[i]]));
}

async function previousEntries(account, input, known = new Map()) {
  const created = input.createdBy;
  const cellsOf = async (inputs) => {
    const missing = inputs.filter((one) => !known.has(outPointKey(one.previousOutput)));
    const fetched = missing.length > 0 ? await inputCellsOf({ inputs: missing }) : [];
    missing.forEach((one, i) => known.set(outPointKey(one.previousOutput), fetched[i]));
    return inputs.map((one) => known.get(outPointKey(one.previousOutput)));
  };
  // A chained cell's record is the one on the input that spent the previous send-limit cell. Witnesses of other
  // parties' inputs aren't covered by the account's signature, so anyone could add a record-shaped one there: only a
  // record on an input at the key's address with this cell's Type ID decides that the cell is chained.
  const records = creatorRecords(created);
  if (records.length > 0) {
    const cells = await cellsOf(records.map(({ index }) => created.inputs[index]));
    const own = records.filter((_, i) => sameScript(cells[i].output.lock, account.secp) && sameScript(cells[i].output.type, input.output.type));
    if (own.length > 1) throw new Error("The send-limit record is malformed");
    if (own.length === 1) {
      const entries = parseRecord(own[0].record);
      if (entries.length === 0 || bytesToHex(entries[entries.length - 1].hash) !== input.createdByHash) throw new Error("The send-limit record is malformed");
      return { entries, check: async () => undefined };
    }
  }
  // Otherwise only a genesis: its Type ID from input 0, which was a plain cell at the key's address.
  if (!equalBytes(input.output.type.args, typeIdArgs(created.inputs[0], input.outputIndex))) throw new Error(NOT_MADE_BY_KEY);
  const check = async () => {
    const [first] = await cellsOf([created.inputs[0]]);
    if (lockKind(account, first.output.lock) !== "secp256k1" || !isPlain(first.output, first.data)) throw new Error(NOT_MADE_BY_KEY);
  };
  return { entries: [], check };
}

/**
 * Of these send-limit-shaped inputs that failed the checks above, refuses any whose creator the key's own history
 * shows spent a cell at its address: a genuine cell a node misreported (say, with a witness changed, which the
 * transaction hash doesn't cover) must never pass for a look-alike that can be destroyed without the code.
 */
async function refuseOwnAsForeign(account, unproven) {
  if (unproven.length === 0) return;
  if (unproven.some((cell) => cell.createdStatus !== "committed" || typeof cell.createdBlockHash !== "string")) throw new Error("A send-limit-shaped input isn't committed yet");
  const blockHashes = [...new Set(unproven.map((cell) => cell.createdBlockHash))];
  // Everything from one node whose indexer has reached every creator's block, so a lagging node's empty history can't
  // read as "not the key's".
  let made;
  let lastError;
  for (const url of RPC_URLS) {
    try {
      const indexed = await freshIndexer([url]);
      const headers = await rpcBatch(blockHashes.map((hash) => ({ method: "get_header", params: [hash] })), [url]);
      const numbers = new Map(blockHashes.map((hash, i) => [hash, num(headers[i]?.number, "block number")]));
      if ([...numbers.values()].some((block) => block > indexed)) throw new Error("CKB RPC's indexer hasn't reached a send-limit-shaped input's block");
      made = await madeByKey(account, unproven.map((cell) => ({ block: numbers.get(cell.createdBlockHash) })), [url], { anyInput: true, locks: [account.secp] });
      break;
    } catch (error) {
      lastError = error;
    }
  }
  if (!made) throw lastError ?? new Error("CKB RPC is unavailable");
  if (unproven.some((cell) => made.has(cell.createdByHash.toLowerCase()))) throw new Error("A send-limit cell of this account's can't be read; try again later");
}

/**
 * The commit time (ms) of each entry: the record's own when it has one, otherwise the block timestamp of the entry's
 * transaction, or 0 while it is pending (or the node doesn't know it), which counts it as sent now.
 */
async function entryTimes(entries, input) {
  const times = new Map();
  const blocks = new Map();
  const unknown = [];
  for (const entry of entries) {
    const hash = bytesToHex(entry.hash);
    if (entry.time !== 0n) times.set(hash, Number(entry.time));
    else if (hash === input.createdByHash) {
      if (input.createdStatus === "committed" && input.createdBlockHash) blocks.set(hash, input.createdBlockHash);
      else times.set(hash, 0);
    } else unknown.push(hash);
  }
  if (unknown.length > 0) {
    const statuses = await rpcBatch(unknown.map((hash) => ({ method: "get_transaction", params: [hash, "0x1"] })));
    unknown.forEach((hash, i) => {
      const status = statuses[i]?.tx_status;
      if (status?.status === "committed" && typeof status.block_hash === "string") blocks.set(hash, status.block_hash);
      else times.set(hash, 0);
    });
  }
  if (blocks.size > 0) {
    const hashes = [...blocks.keys()];
    const headers = await rpcBatch(hashes.map((hash) => ({ method: "get_header", params: [blocks.get(hash)] })));
    hashes.forEach((hash, i) => {
      const time = Number(num(headers[i]?.timestamp, "block timestamp"));
      if (!(time > 0)) throw new Error("CKB RPC returned an invalid block timestamp");
      times.set(hash, time);
    });
  }
  return times;
}

/** Sums each asset over entries still in the window. */
function windowTotals(entries, times, now) {
  const totals = new Map([["ckb", 0n]]);
  for (const entry of entries) {
    const time = times.get(bytesToHex(entry.hash)) ?? 0;
    if (time !== 0 && now - time >= WINDOW_MS) continue;
    totals.set("ckb", totals.get("ckb") + entry.ckb);
    for (const token of entry.tokens) totals.set(token.asset, (totals.get(token.asset) ?? 0n) + token.amount);
  }
  return totals;
}

/** Whether, for any asset leaving, the window's total plus this transaction reaches its amount. */
function overAmount(settings, totals, flow) {
  const leaving = [...(flow.ckb > 0n ? [{ asset: "ckb", amount: flow.ckb }] : []), ...flow.tokens];
  return leaving.some(({ asset, amount }) => {
    const limit = allowance(settings, asset);
    // An asset counted per cell has no amount to compare: with a daily amount set, it always needs the code.
    return limit !== undefined && (flow.perCell?.has(asset) || (totals.get(asset) ?? 0n) + amount >= limit);
  });
}

/**
 * Checks the record a chained transaction carries: the previous entries it keeps are, in order and unchanged
 * (except a time filled in once its transaction committed), a subsequence of the previous record; every previous
 * entry younger than 24 hours is kept; and the last entry is this transaction with the outflow computed here.
 */
function checkRecord(given, previous, times, self, now) {
  const last = given[given.length - 1];
  if (!last || !equalBytes(last.bytes, encodeEntry(self))) throw new Error("The send-limit record doesn't match this transaction");
  let at = 0;
  for (const entry of given.slice(0, -1)) {
    while (at < previous.length && !equalBytes(previous[at].hash, entry.hash)) {
      const time = times.get(bytesToHex(previous[at].hash)) ?? 0;
      if (time === 0 || now - time < WINDOW_MS) throw new Error("The send-limit record leaves out a recent send");
      at++;
    }
    const before = previous[at];
    if (!before) throw new Error("The send-limit record holds a send that isn't in this account's chain");
    const filled = before.time === 0n && entry.time !== 0n;
    if (filled ? !equalBytes(entry.bytes, encodeEntry({ ...before, time: BigInt(times.get(bytesToHex(before.hash)) ?? -1) })) : !equalBytes(entry.bytes, before.bytes)) {
      throw new Error("The send-limit record changes an earlier send");
    }
    at++;
  }
  for (; at < previous.length; at++) {
    const time = times.get(bytesToHex(previous[at].hash)) ?? 0;
    if (time === 0 || now - time < WINDOW_MS) throw new Error("The send-limit record leaves out a recent send");
  }
}

/** The record planning writes: every previous entry not yet well past the window, with known times filled in. */
function plannedRecord(previous, times, self, now) {
  const kept = previous.filter((entry) => {
    const time = times.get(bytesToHex(entry.hash)) ?? 0;
    return time === 0 || now - time < WINDOW_MS + PLAN_MARGIN_MS;
  }).map((entry) => ({ ...entry, time: BigInt(times.get(bytesToHex(entry.hash)) ?? 0) }));
  return encodeRecord([...kept, self]);
}

/** The live send-limit cells this key made at its secp256k1 address, as the indexer shows them. */
async function liveSettingsAt(account, urls) {
  // "No send limits" is only believed from an indexer that has caught up with its chain.
  await freshIndexer(urls);
  // Anyone can plant Type ID cells here. Only send-limit-shaped ones are asked for, up to a number of pages that keeps
  // the run within Lit's limit on outbound requests; none count until proven the key's own below, so planted ones
  // can't use up a cap on how many are read.
  const filter = { ...TYPE_ID_FILTER, output_data: `0x${SETTINGS_MAGIC}`, output_data_filter_mode: "prefix" };
  const keep = (object) => typeof object?.output_data === "string" && object.output_data.toLowerCase().startsWith(`0x${SETTINGS_MAGIC}`);
  const candidates = (await indexerCells(account.secp, Infinity, filter, urls, { keep, maxPages: 16 })).map((object) => {
    const lock = parseScript(object?.output?.lock, "cell lock");
    const type = object?.output?.type ? parseScript(object.output.type, "cell type") : undefined;
    const data = hexToBytes(object?.output_data ?? "0x", "cell data");
    if (!sameScript(lock, account.secp) || !isTypeId(type)) throw new Error("CKB RPC returned a cell that isn't at this key's address");
    return { txHash: object?.out_point?.tx_hash, index: object?.out_point?.index, block: num(object?.block_number, "block number"), data };
  }).filter((cell) => startsWith(cell.data, SETTINGS_MAGIC));
  if (candidates.length === 0) return [];
  // Anyone can put such a cell here; it counts only if the transaction that made it spent a cell at this key's
  // secp256k1 address (any input), which needs the key's signature. Every genuine one does: a genesis spends a plain
  // cell there, and a chained change spends the previous send-limit cell there.
  const made = await madeByKey(account, candidates, urls, { anyInput: true, locks: [account.secp] });
  return candidates.filter((cell) => typeof cell.txHash === "string" && made.has(cell.txHash.toLowerCase()));
}

async function liveSettings(account) {
  let lastError;
  for (const url of RPC_URLS) {
    try { return await liveSettingsAt(account, [url]); } catch (error) { lastError = error; }
  }
  throw lastError ?? new Error("CKB RPC is unavailable");
}

/**
 * For a genesis: the oldest live plain cell at the key's secp256k1 address, then the live send-limit cells, from
 * one node. A genesis that commits between the two reads still shows its input 0 in the first (so this one must
 * spend the same cell), and one that commits before is in the second.
 */
async function genesisView(account) {
  let lastError;
  for (const url of RPC_URLS) {
    try {
      const body = JSON.stringify({ id: 0, jsonrpc: "2.0", method: "get_cells", params: [lockSearchKey(account.secp, PLAIN_FILTER), "asc", "0x1"] });
      const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body, redirect: "error" });
      if (!response.ok) throw new Error(`CKB RPC returned HTTP ${response.status}`);
      const result = (await response.json())?.result;
      if (!result || !Array.isArray(result.objects)) throw new Error("CKB RPC returned an invalid get_cells page");
      const oldest = result.objects[0];
      const settings = await liveSettingsAt(account, [url]);
      return { oldest, settings };
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError ?? new Error("CKB RPC is unavailable");
}

/** The transaction's hash with the genesis output's fingerprint zeroed: what a genesis code is for. */
function genesisCodeHash(tx) {
  const data = tx.outputsData[0].slice();
  data.fill(0, 5, 37);
  return rawTransactionHash({ ...tx, outputsData: [data, ...tx.outputsData.slice(1)] });
}

/**
 * Applies the send limits. Returns { kind, flow, needsCode, settings?, totals?, record? } where kind is "exempt",
 * "legacy" (no send-limit cell), "chained", "unchained" or "genesis". When not planning, a chained transaction's
 * record is checked here.
 */
async function limitAnalysis(analysis, params) {
  const { tx, account, inputs, op } = analysis;
  const planning = params.mode === "plan";
  const flow = outflowOf(account, tx, inputs);
  const exempt = flow.ckb <= EXEMPT_OUTFLOW && flow.tokens.length === 0;
  // A send-limit-shaped input counts only if the transaction that made it shows it is the key's own; a look-alike
  // someone planted at the address is an ordinary Type ID cell, so it can be destroyed like any other.
  const settingsInputs = [];
  const shaped = inputs.map((cell, index) => ({ ...cell, index })).filter((cell) => isSettingsShaped(account, cell.output, cell.data));
  const known = await creatorCells(shaped);
  const unproven = [];
  for (const cell of shaped) {
    try {
      const previous = await previousEntries(account, cell, known);
      await previous.check();
      settingsInputs.push({ ...cell, previous });
    } catch (error) {
      if (error?.message !== NOT_MADE_BY_KEY) throw error;
      unproven.push(cell);
    }
  }
  await refuseOwnAsForeign(account, unproven);
  if (settingsInputs.length > 1) throw new Error("A transaction may spend only one send-limit cell");
  const input = settingsInputs[0];
  const settingsOutputs = tx.outputs.map((output, index) => ({ output, data: tx.outputsData[index], index }))
    .filter(({ output, data }) => isSettingsShaped(account, output, data) || (input && sameScript(output.type, input.output.type)));
  if (settingsOutputs.length > 1) throw new Error("A transaction may create only one send-limit cell");
  // A record may only sit on the send-limit input, so the next transaction finds exactly one.
  tx.witnesses.forEach((witness, index) => {
    if (recordIn(witness) && index !== input?.index) throw new Error("A send-limit record is only allowed on the send-limit input");
  });

  if (input) {
    if (op.kind !== "plain") throw new Error("A recovery change can't also spend the send-limit cell");
    const output = settingsOutputs[0];
    if (!output) throw new Error("The send-limit cell can't be destroyed");
    if (!sameScript(output.output.lock, account.secp) || !sameScript(output.output.type, input.output.type)) throw new Error("The send-limit cell's lock and Type ID can't change");
    const before = parseSettings(input.data);
    const after = parseSettings(output.data);
    if (!equalBytes(before.fingerprint, after.fingerprint)) throw new Error("The email bound to send limits can't change");
    const previous = input.previous.entries;
    const times = await entryTimes(previous, input);
    const now = Date.now();
    const totals = windowTotals(previous, times, now);
    const self = { hash: analysis.txHash, time: 0n, ckb: flow.ckb, tokens: flow.tokens };
    const weakening = weakens(before, after);
    const result = { kind: "chained", flow, settings: before, next: after, totals, weakening, inputIndex: input.index,
      // A change that moves nothing but its fee doesn't count against the amount: lowering it always applies at once.
      needsCode: weakening || (!(flow.ckb <= EXEMPT_OUTFLOW && flow.tokens.length === 0) && overAmount(before, totals, flow)) };
    if (planning) return { ...result, record: plannedRecord(previous, times, self, now) };
    const record = recordIn(tx.witnesses[input.index]);
    if (!record) throw new Error("The send-limit input carries no record");
    // Every entry the record keeps must have a known time if it claims one; filled-in times were looked up above.
    checkRecord(parseRecord(record), previous, times, self, now);
    return result;
  }

  if (settingsOutputs.length === 1) {
    const { output, data, index } = settingsOutputs[0];
    if (op.kind !== "plain") throw new Error("A recovery change can't also turn send limits on");
    if (index !== 0) throw new Error("The new send-limit cell must be output 0");
    if (!sameScript(output.lock, account.secp) || !isTypeId(output.type) || !equalBytes(output.type.args, typeIdArgs(tx.inputs[0], 0))) throw new Error("The new send-limit cell must be at this key's address with its Type ID from input 0");
    if (lockKind(account, inputs[0].output.lock) !== "secp256k1" || !isPlain(inputs[0].output, inputs[0].data)) throw new Error("Input 0 must be a plain CKB cell at this key's address");
    if (!exempt) throw new Error("Turning send limits on can't also send value out of the account");
    const settings = parseSettings(data);
    const view = await genesisView(account);
    if (view.settings.length > 0) throw new Error("Send limits are already on for this account");
    const oldest = view.oldest;
    if (!oldest || oldest.out_point?.tx_hash !== bytesToHex(tx.inputs[0].previousOutput.txHash) || Number(num(oldest.out_point?.index, "out point index")) !== tx.inputs[0].previousOutput.index) {
      throw new Error("Turning send limits on must spend the oldest plain cell at this key's address as input 0");
    }
    return { kind: "genesis", flow, settings, next: settings, needsCode: true, codeHash: genesisCodeHash(tx) };
  }

  if (exempt) return { kind: "exempt", flow, needsCode: false };
  if (op.kind !== "plain") throw new Error("A recovery change can't send value out of the account");
  const live = await liveSettings(account);
  if (live.length === 0) return { kind: "legacy", flow, needsCode: false };
  if (live.length > 1) throw new Error("This account has more than one send-limit cell");
  // A transaction that doesn't chain on the cell (a Fiber channel funding, whose inputs Fiber chooses) can't be
  // counted against the others, so it always needs the code.
  return { kind: "unchained", flow, settings: parseSettings(live[0].data), needsCode: true };
}

function formatCkb(shannons) {
  const whole = shannons / 100_000_000n;
  const fraction = (shannons % 100_000_000n).toString().padStart(8, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

const shortAsset = (asset) => `${asset.slice(0, 10)}…${asset.slice(-6)}`;

function describeAllowance(settings, asset) {
  const limit = allowance(settings, asset);
  if (limit === undefined) return "no limit";
  if (limit === 0n) return "a code for every transfer";
  return asset === "ckb" ? `${formatCkb(limit)} CKB a day` : `${limit} a day`;
}

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

/** The script's full CKB testnet address: bech32m of 0x00 ‖ code hash ‖ hash type ‖ args (CKB RFC 0021). */
function testnetAddress(script) {
  const words = [];
  let acc = 0;
  let bits = 0;
  for (const byte of concat([0x00], script.codeHash, [HASH_TYPES[script.hashType]], script.args)) {
    acc = ((acc << 8) | byte) & 0x1fff;
    bits += 8;
    while (bits >= 5) { bits -= 5; words.push((acc >>> bits) & 31); }
  }
  if (bits > 0) words.push((acc << (5 - bits)) & 31);
  const hrp = "ckt";
  let check = 1;
  for (const value of [...[...hrp].map((c) => c.charCodeAt(0) >>> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31), ...words, 0, 0, 0, 0, 0, 0]) {
    const top = check >>> 25;
    check = ((check & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) check ^= BECH32_GENERATOR[i];
  }
  check ^= 0x2bc830a3; // bech32m
  for (let i = 0; i < 6; i++) words.push((check >>> (5 * (5 - i))) & 31);
  return `${hrp}1${words.map((word) => BECH32_CHARSET[word]).join("")}`;
}

const FIBER_FUNDING_CODE_HASH = "0x6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c";
const MAX_RECIPIENT_LINES = 8;

/**
 * Where the outputs that leave the account go, one line per lock with its full address, the largest first, so a
 * page that swaps the recipient can't send an email that reads like the one the user expects.
 */
function recipientLines(account, tx) {
  const byLock = new Map();
  tx.outputs.forEach((output, index) => {
    if (lockKind(account, output.lock)) return;
    const key = bytesToHex(scriptHash(output.lock));
    const entry = byLock.get(key) ?? { lock: output.lock, ckb: 0n, tokens: new Map() };
    entry.ckb += output.capacity;
    if (output.type) {
      const asset = bytesToHex(scriptHash(output.type));
      const data = tx.outputsData[index];
      entry.tokens.set(asset, (entry.tokens.get(asset) ?? 0n) + (isUdt(output.type) && data.length >= 16 ? readU128(data, 0) : 1n));
    }
    byLock.set(key, entry);
  });
  const entries = [...byLock.values()].sort((a, b) => (a.ckb > b.ckb ? -1 : a.ckb < b.ckb ? 1 : 0));
  const lines = entries.slice(0, MAX_RECIPIENT_LINES).map(({ lock, ckb, tokens }) => {
    const address = testnetAddress(lock);
    const fiber = lock.hashType === "type" && bytesToHex(lock.codeHash) === FIBER_FUNDING_CODE_HASH;
    const amounts = [`${formatCkb(ckb)} CKB`, ...[...tokens].map(([asset, amount]) => `${amount} of token ${shortAsset(asset)}`)];
    return `To ${fiber ? `a Fiber channel (${address})` : address}: ${amounts.join(", ")}`;
  });
  const rest = entries.slice(MAX_RECIPIENT_LINES);
  if (rest.length > 0) lines.push(`And ${rest.length} more recipients: ${formatCkb(rest.reduce((sum, { ckb }) => sum + ckb, 0n))} CKB in all`);
  return lines;
}

function limitLines(limits, analysis) {
  const { flow, settings, next, totals } = limits;
  if (limits.kind === "genesis") {
    return ["Turn on daily send limits", `CKB: ${describeAllowance(next, "ckb")}`, ...[...next.tokens.keys()].map((asset) => `Token ${shortAsset(asset)}: ${describeAllowance(next, asset)}`), `Other tokens: ${next.tokensUnlimited ? "no limit" : "a code for every transfer"}`];
  }
  const lines = [limits.weakening && flow.ckb <= EXEMPT_OUTFLOW && flow.tokens.length === 0 ? "Change your daily send limits" : "Confirm a send"];
  if (flow.ckb > 0n) lines.push(`Sending ${formatCkb(flow.ckb)} CKB, network fee included`);
  for (const token of flow.tokens) lines.push(`Sending ${token.amount} of token ${shortAsset(token.asset)}`);
  lines.push(...recipientLines(analysis.account, analysis.tx));
  if (limits.kind === "unchained") lines.push("This transaction (such as opening a Fiber channel) can't count toward your daily amount, so it always needs a code");
  if (totals) lines.push(`Already sent in the last 24 hours: ${formatCkb(totals.get("ckb") ?? 0n)} CKB`);
  lines.push(`Your daily amount: ${describeAllowance(settings, "ckb")}`);
  if (limits.weakening) {
    lines.push(`New daily amount: ${describeAllowance(next, "ckb")}`);
    for (const asset of new Set([...settings.tokens.keys(), ...next.tokens.keys()])) lines.push(`Token ${shortAsset(asset)}: ${describeAllowance(settings, asset)} → ${describeAllowance(next, asset)}`);
    if (next.tokensUnlimited !== settings.tokensUnlimited) lines.push(`Other tokens: ${next.tokensUnlimited ? "no limit" : "a code for every transfer"}`);
  }
  return lines;
}

/** The email a send-limit code goes to: one whose fingerprint is bound in the send-limit cell (or, at genesis, the one being bound). */
async function limitEmail(pkpId, limits, params) {
  if (limits.kind === "genesis" && params.mode === "send-code") return checkEmail(params.email);
  const bound = limits.kind === "genesis" ? limits.next.fingerprint : limits.settings.fingerprint;
  return emailMatching(pkpId, bound, params.email, "This isn't the email address bound to this account's send limits");
}

// ---------- codes ----------

/** HMAC-SHA256 under this Action's own key, which only this Action (this CID) can use. */
async function actionMac(message) {
  const actionKey = hexToBytes(await Lit.Actions.getLitActionPrivateKey(), "action key");
  const key = await crypto.subtle.importKey("raw", actionKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  actionKey.fill(0);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(message)));
}

async function codeFor(pkpId, txHash, email, ticket) {
  const mac = await actionMac(`keyway-lit-email-code/v1|${pkpId.toLowerCase()}|${bytesToHex(txHash)}|${email.toLowerCase()}|${ticket}`);
  let value = 0n;
  for (let i = 0; i < 8; i++) value = (value << 8n) | BigInt(mac[i]);
  return (value % 100_000_000n).toString().padStart(8, "0");
}

/**
 * A ticket is v2.<expiry ms>.<16 random bytes>.<tag>, the tag a MAC under the Action's key over the ticket and what
 * the code is for. Only send-code, which also emails the code, can issue one, so every window for guessing a code
 * is an email the user sees, and it closes when the ticket expires.
 */
async function ticketTag(pkpId, codeHash, email, body) {
  return bytesToHex(await actionMac(`keyway-lit-ticket/v2|${pkpId.toLowerCase()}|${bytesToHex(codeHash)}|${email.toLowerCase()}|${body}`)).slice(2);
}

async function issueTicket(pkpId, codeHash, email) {
  const body = `v2.${Date.now() + CODE_TTL_MS}.${bytesToHex(crypto.getRandomValues(new Uint8Array(16))).slice(2)}`;
  return `${body}.${await ticketTag(pkpId, codeHash, email, body)}`;
}

async function parseTicket(pkpId, codeHash, email, ticket) {
  const match = typeof ticket === "string" ? /^(v2\.(\d{13})\.[0-9a-f]{32})\.([0-9a-f]{64})$/.exec(ticket) : null;
  if (!match) throw new Error("The email code ticket is invalid");
  const expected = await ticketTag(pkpId, codeHash, email, match[1]);
  let diff = 0;
  for (let i = 0; i < 64; i++) diff |= expected.charCodeAt(i) ^ match[3].charCodeAt(i);
  if (diff !== 0) throw new Error("The email code ticket is invalid");
  const expiresAt = Number(match[2]);
  const now = Date.now();
  if (expiresAt <= now) throw new Error("The email code has expired. Request a new one");
  // A minute's slack for clock differences between the Lit nodes that issued and check the ticket.
  if (expiresAt > now + CODE_TTL_MS + 60_000) throw new Error("The email code ticket is invalid");
  return expiresAt;
}

function requireCodeShape(emailCode) {
  if (!emailCode || typeof emailCode.code !== "string" || !/^\d{8}$/.test(emailCode.code)) throw new Error("Enter the eight-digit code from your email");
}

async function verifyCode(pkpId, codeHash, email, emailCode) {
  requireCodeShape(emailCode);
  await parseTicket(pkpId, codeHash, email, emailCode.ticket);
  const expected = await codeFor(pkpId, codeHash, email, emailCode.ticket);
  let diff = 0;
  for (let i = 0; i < 8; i++) diff |= expected.charCodeAt(i) ^ emailCode.code.charCodeAt(i);
  if (diff !== 0) throw new Error("That email code isn't right");
}

function emailLines(op) {
  if (op.kind === "enable") {
    return ["Turn on account recovery", ...op.members.map((entry) => `Backup: ${describeBackup(entry)}`), "Each backup will be able to move everything in your account without KeyWay."];
  }
  if (op.kind === "add") return ["Add a recovery backup", `Adding: ${describeBackup(op.backup)}`, "This backup will be able to move everything in your account without KeyWay.", `Backups after this change: ${op.members.length}`];
  return ["Remove a recovery backup", `Removing: ${describeBackup(op.backup)}`, `Backups after this change: ${op.members.length}`];
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

async function sendCode(pkpId, codeHash, email, emailLinesFor, params) {
  if (typeof params.emailApiKey !== "string" || !/^re_[A-Za-z0-9_]{8,128}$/.test(params.emailApiKey)) throw new Error("emailApiKey is required");
  const appName = typeof params.appName === "string" && /^[A-Za-z0-9 .'-]{1,40}$/.test(params.appName) ? params.appName : "CKB KeyWay";
  const ticket = await issueTicket(pkpId, codeHash, email);
  const code = await codeFor(pkpId, codeHash, email, ticket);
  const lines = [...emailLinesFor, `Transaction ${bytesToHex(codeHash).slice(0, 12)}…`, "Network CKB testnet"];
  const heading = lines[0];
  const text = `${heading} in ${appName}\n\n${lines.slice(1).join("\n")}\n\nYour confirmation code is ${code}\n\nThis code expires in 10 minutes. Only enter it if you started this change. It was made and sent by KeyWay's Lit Action, so KeyWay's server never sees it.\n\nSecured by CKB KeyWay`;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${escapeHtml(heading)}</title></head><body style="font-family:Arial,Helvetica,sans-serif;color:#111827;background:#f3f4f6;padding:32px 16px"><div style="max-width:560px;margin:0 auto;background:#fff;border-radius:16px;padding:32px 24px"><p style="color:#6b7280;font-size:14px;margin:0 0 12px">${escapeHtml(appName)}</p><h1 style="font-size:22px;font-weight:500;margin:0 0 16px">${escapeHtml(heading)}</h1>${lines.slice(1).map((line) => `<p style="font-size:14px;margin:6px 0;border-top:1px solid #e5e7eb;padding-top:6px">${escapeHtml(line)}</p>`).join("")}<p style="font-size:14px;margin:24px 0 8px">Your confirmation code</p><p style="font-family:monospace;font-size:36px;font-weight:700;letter-spacing:6px;margin:0">${code}</p><p style="font-size:14px;margin:20px 0 0">This code expires in 10 minutes. Only enter it if you started this change.</p></div></body></html>`;
  const response = await fetch(EMAIL_API_URL, {
    method: "POST",
    headers: { Authorization: `Bearer ${params.emailApiKey}`, "Content-Type": "application/json", "Idempotency-Key": `keyway-lit-code/${ticket}` },
    body: JSON.stringify({ from: EMAIL_FROM, to: [email], subject: `${heading} in ${appName}`, text, html }),
    redirect: "error",
  });
  if (!response.ok) throw new Error(`The code email couldn't be sent (HTTP ${response.status})`);
  return ticket;
}

// ---------- signing ----------

function signDigest(account, digest) {
  const signature = account.signingKey.signDigest(bytesToHex(digest));
  return { r: signature.r, s: signature.s, recoveryParam: signature.recoveryParam };
}

function signGroups(analysis) {
  const { tx, inputLocks, groups, account } = analysis;
  const signed = groups.map(({ lock, kind }) => {
    const { digest, first } = sighash(tx, inputLocks, lock);
    // The group's first witness must hold an all-zero lock at its final length, so the digest is the one the chain checks.
    const witness = parseWitnessArgs(tx.witnesses[first]);
    const length = kind === "secp256k1" ? SECP_WITNESS_LOCK : OMNILOCK_WITNESS_LOCK;
    if (!witness.lock || witness.lock.length !== length || !isZero(witness.lock)) throw new Error("A signing witness isn't prepared");
    return { lock, digest, first };
  });
  return signed.map(({ lock, digest, first }) => ({ lockHash: bytesToHex(scriptHash(lock)), witnessIndex: first, ...signDigest(account, digest) }));
}

/** Limit kinds whose code goes to the address bound in the send-limit cell. */
const LIMITED = ["chained", "unchained", "genesis"];

/** What planning tells the server: the kind, whether a code is needed, the outflow, the totals and the record. */
function planResult(analysis, limits) {
  const totals = limits.totals ? Object.fromEntries([...limits.totals].map(([asset, amount]) => [asset, amount.toString()])) : undefined;
  return {
    transactionHash: bytesToHex(analysis.txHash),
    operation: analysis.op.kind,
    limits: limits.kind,
    needsCode: limits.needsCode,
    outflow: { ckb: limits.flow.ckb.toString(), tokens: limits.flow.tokens.map(({ asset, amount }) => ({ asset, amount: amount.toString() })) },
    ...(totals ? { totals } : {}),
    ...(limits.record ? { record: bytesToHex(limits.record), recordIndex: limits.inputIndex } : {}),
  };
}

async function main(params) {
  const { mode, pkpId } = params ?? {};
  if (typeof pkpId !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(pkpId)) throw new Error("pkpId must be a 20-byte EVM address");

  if (mode === "identity") {
    const account = await accountOf(pkpId);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8("CKB KeyWay identity v1")));
    return signDigest(account, digest);
  }
  if (mode === "message") {
    if (typeof params.message !== "string" || !params.message.trim()) throw new Error("A message to sign is required");
    if (utf8(params.message).length > MAX_MESSAGE_BYTES) throw new Error("Messages can be at most 4 KB");
    const account = await accountOf(pkpId);
    return signDigest(account, ckbHash(utf8(`Nervos Message:${params.message}`)));
  }
  if (mode === "plan") {
    // No key is used: the server runs this to learn, from the same rules, whether a code is needed and which record
    // the transaction must carry. Lit checks both again when it signs.
    const analysis = await analyse(pkpId, params);
    const limits = await limitAnalysis(analysis, params);
    return planResult(analysis, limits);
  }
  if (mode === "send-code") {
    const analysis = await analyse(pkpId, params);
    const recoveryEmail = await codeTarget(pkpId, analysis, params);
    const limits = await limitAnalysis(analysis, params);
    let target;
    if (recoveryEmail) target = { email: recoveryEmail, lines: emailLines(analysis.op), codeHash: analysis.txHash };
    else if (LIMITED.includes(limits.kind)) target = { email: await limitEmail(pkpId, limits, params), lines: limitLines(limits, analysis), codeHash: limits.codeHash ?? analysis.txHash };
    else throw new Error("This transaction doesn't need an email code");
    const ticket = await sendCode(pkpId, target.codeHash, target.email, target.lines, params);
    const result = { ticket, sentTo: target.email, transactionHash: bytesToHex(analysis.txHash) };
    if (analysis.op.kind === "enable") {
      result.binding = bytesToHex(encodeBinding(await emailFingerprint(pkpId, target.email)));
    }
    // A genesis carries the fingerprint in the cell's data; the code is for the transaction with that field zeroed.
    if (limits.kind === "genesis") result.fingerprint = bytesToHex(await emailFingerprint(pkpId, target.email));
    return result;
  }
  if (mode === "transaction") {
    const analysis = await analyse(pkpId, params);
    const recoveryEmail = await codeTarget(pkpId, analysis, params);
    const limits = await limitAnalysis(analysis, params);
    if (recoveryEmail) await verifyCode(pkpId, analysis.txHash, recoveryEmail, params.emailCode);
    else if (limits.needsCode || (LIMITED.includes(limits.kind) && params.emailCode !== undefined)) {
      requireCodeShape(params.emailCode);
      await verifyCode(pkpId, limits.codeHash ?? analysis.txHash, await limitEmail(pkpId, limits, params), params.emailCode);
    }
    return { transactionHash: bytesToHex(analysis.txHash), operation: analysis.op.kind, limits: limits.kind, signatures: signGroups(analysis) };
  }
  throw new Error("mode must be identity, message, transaction, send-code or plan");
}

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
//                a recovery list change and returns the ticket (and, when turning recovery on, the email binding
//                the transaction must carry).
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
        found.set(hash, { tx, status: view.tx_status?.status });
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
 * Live cells under a lock, from the indexer, a page of 256 at a time, only those matching `filter`; refuses more
 * than `maxCells`. Large pages keep a run within Lit's limit on outbound requests.
 */
async function indexerCells(lock, maxCells, filter, urls = RPC_URLS) {
  const searchKey = lockSearchKey(lock, filter);
  const method = "get_cells";
  const pageSize = 0x100;
  const cells = [];
  let cursor = null;
  for (;;) {
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
    cells.push(...result.objects);
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
async function madeByKey(account, candidates, urls) {
  const blocks = [...new Set(candidates.map(({ block }) => block))];
  const calls = blocks.flatMap((block) => [account.secp, account.listLock].map((lock) => ({
    method: "get_transactions",
    params: [lockSearchKey(lock, { block_range: [`0x${block.toString(16)}`, `0x${(block + 1n).toString(16)}`] }), "asc", "0x400"],
  })));
  const made = new Set();
  // 256 calls a batch: at most 1024 candidates take 8 requests, so the whole run stays well within Lit's request
  // limit, with room for the code email.
  for (let at = 0; at < calls.length; at += 256) {
    for (const result of await rpcBatch(calls.slice(at, at + 256), urls)) {
      if (!Array.isArray(result?.objects)) throw new Error("CKB RPC returned an invalid get_transactions page");
      // A full page can't be read past here; outsiders can only fill it by giving this key 1024 cells in one block.
      if (result.objects.length >= 0x400) throw new Error("A block holds too much of this key's history to check");
      for (const entry of result.objects) {
        if (entry?.io_type === "input" && num(entry.io_index, "io index") === 0n) made.add(String(entry.tx_hash).toLowerCase());
      }
    }
  }
  return made;
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
    const previous = found.get(bytesToHex(input.previousOutput.txHash)).tx;
    const index = input.previousOutput.index;
    if (index >= previous.outputs.length) throw new Error("An input doesn't exist");
    return { output: previous.outputs[index], data: previous.outputsData[index], createdBy: previous, outputIndex: index };
  });
}

// ---------- the account ----------

async function accountOf(pkpId) {
  const privateKey = await Lit.Actions.getPrivateKey({ pkpId });
  const signingKey = new ethers.utils.SigningKey(privateKey);
  const publicKey = hexToBytes(signingKey.compressedPublicKey, "public key");
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

function describeBackup(backup) {
  const id = bytesToHex(backup.id);
  return backup.kind === "evm" ? `EVM wallet ${id}` : `JoyID passkey (key id ${id})`;
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

/** The address the server passed, if its fingerprint is the one bound on chain. */
async function emailMatchingBinding(pkpId, binding, email) {
  const bound = decodeBinding(binding);
  const given = await emailFingerprint(pkpId, checkEmail(email));
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= bound[i] ^ given[i];
  if (diff !== 0) throw new Error("This isn't the email address bound to this account's recovery");
  return email;
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
  const account = await accountOf(pkpId);
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
    const email = await boundEmail(pkpId, account, input.output.type, params.enableTransactionHash, params.email);
    op = { ...change, members: after, email };
  }
  return { tx, account, inputLocks, groups, op, txHash: rawTransactionHash(tx) };
}

/** Whether the operation needs the emailed code, and the address it goes to. */
async function codeTarget(pkpId, analysis, params) {
  const { op } = analysis;
  if (op.kind === "plain") return undefined;
  if (op.kind === "enable") {
    if (params.mode === "send-code") return checkEmail(params.email);
    if (!op.binding) throw new Error("Turning recovery on must bind the account's email");
    return emailMatchingBinding(pkpId, op.binding, params.email);
  }
  // A list made before this Action existed has no binding; it keeps the server's checks and the shape rules above.
  return op.email;
}

// ---------- codes ----------

async function codeFor(pkpId, txHash, email, ticket) {
  const actionKey = hexToBytes(await Lit.Actions.getLitActionPrivateKey(), "action key");
  const key = await crypto.subtle.importKey("raw", actionKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  actionKey.fill(0);
  const message = utf8(`keyway-lit-email-code/v1|${pkpId.toLowerCase()}|${bytesToHex(txHash)}|${email.toLowerCase()}|${ticket}`);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  let value = 0n;
  for (let i = 0; i < 8; i++) value = (value << 8n) | BigInt(mac[i]);
  return (value % 100_000_000n).toString().padStart(8, "0");
}

function parseTicket(ticket) {
  const match = typeof ticket === "string" ? /^v1\.(\d{13})\.([0-9a-f]{32})$/.exec(ticket) : null;
  if (!match) throw new Error("The email code ticket is invalid");
  const expiresAt = Number(match[1]);
  const now = Date.now();
  if (expiresAt <= now) throw new Error("The email code has expired. Request a new one");
  // A minute's slack for clock differences between the Lit nodes that issued and check the ticket.
  if (expiresAt > now + CODE_TTL_MS + 60_000) throw new Error("The email code ticket is invalid");
  return expiresAt;
}

async function verifyCode(pkpId, analysis, email, emailCode) {
  if (!emailCode || typeof emailCode.code !== "string" || !/^\d{8}$/.test(emailCode.code)) throw new Error("Enter the eight-digit code from your email");
  parseTicket(emailCode.ticket);
  const expected = await codeFor(pkpId, analysis.txHash, email, emailCode.ticket);
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

async function sendCode(pkpId, analysis, email, params) {
  if (typeof params.emailApiKey !== "string" || !/^re_[A-Za-z0-9_]{8,128}$/.test(params.emailApiKey)) throw new Error("emailApiKey is required");
  const appName = typeof params.appName === "string" && /^[A-Za-z0-9 .'-]{1,40}$/.test(params.appName) ? params.appName : "CKB KeyWay";
  const random = crypto.getRandomValues(new Uint8Array(16));
  const ticket = `v1.${Date.now() + CODE_TTL_MS}.${bytesToHex(random).slice(2)}`;
  const code = await codeFor(pkpId, analysis.txHash, email, ticket);
  const lines = [...emailLines(analysis.op), `Transaction ${bytesToHex(analysis.txHash).slice(0, 12)}…`, "Network CKB testnet"];
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
  return groups.map(({ lock, kind }) => {
    const { digest, first } = sighash(tx, inputLocks, lock);
    // The group's first witness must hold an all-zero lock at its final length, so the digest is the one the chain checks.
    const witness = parseWitnessArgs(tx.witnesses[first]);
    const length = kind === "secp256k1" ? SECP_WITNESS_LOCK : OMNILOCK_WITNESS_LOCK;
    if (!witness.lock || witness.lock.length !== length || !isZero(witness.lock)) throw new Error("A signing witness isn't prepared");
    return { lockHash: bytesToHex(scriptHash(lock)), witnessIndex: first, ...signDigest(account, digest) };
  });
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
  if (mode === "send-code") {
    const analysis = await analyse(pkpId, params);
    const email = await codeTarget(pkpId, analysis, params);
    if (!email) throw new Error("This transaction doesn't need an email code");
    const ticket = await sendCode(pkpId, analysis, email, params);
    const result = { ticket, sentTo: email, transactionHash: bytesToHex(analysis.txHash) };
    if (analysis.op.kind === "enable") {
      result.binding = bytesToHex(encodeBinding(await emailFingerprint(pkpId, email)));
    }
    return result;
  }
  if (mode === "transaction") {
    const analysis = await analyse(pkpId, params);
    const email = await codeTarget(pkpId, analysis, params);
    if (email) await verifyCode(pkpId, analysis, email, params.emailCode);
    return { transactionHash: bytesToHex(analysis.txHash), operation: analysis.op.kind, signatures: signGroups(analysis) };
  }
  throw new Error("mode must be identity, message, transaction or send-code");
}

// js_params: { mode, pkpId, ... } (see README.md)
// KeyWay's policy signer. It never signs a digest it is handed. For a transaction it fetches every input cell
// from CKB testnet itself, checks each against the transaction hash, works out which locks are the account's
// from the PKP's own key, refuses any change to the recovery list that breaks its rules, asks for a code it
// emailed itself for every recovery list change, and only then signs the sighash it computed.
//
// Modes:
//   identity     signs the fixed KeyWay identity digest, so the server can learn the PKP's public key.
//   message      signs CKB's "Nervos Message:" hash of a text message it hashes itself.
//   transaction  { transaction, enableTransactionHash?, emailCode? } signs the account's lock groups.
//   send-code    { transaction, enableTransactionHash?, email?, emailApiKey, appName } emails a code for a
//                recovery list change and returns the ticket (and, when turning recovery on, the encrypted
//                email binding the transaction must carry).

const RPC_URLS = ["https://testnet.ckb.dev/", "https://testnet.ckbapp.dev/"];
const EMAIL_API_URL = "https://api.resend.com/emails";
const EMAIL_FROM = "CKB KeyWay <security@auth.ckbkeyway.dev>";
const SECP256K1_CODE_HASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
// KeyWay's own testnet Omnilock, by data hash (src/sdk/browser/account-lock.ts KEYWAY_OMNILOCK.testnet).
const OMNILOCK_CODE_HASH = "0x6b29b6f10346b43c540e53806ba88ba0fe3a0c3a29d7448ef555840c8f8318fa";
const TYPE_ID_CODE_HASH = "0x00000000000000000000000000000000000000000000000000545950455f4944";
// KeyWay's backup verifiers (src/sdk/browser/recovery-backups.ts).
const EVM_VERIFIER = "0x33bd1c699b633d685a6f60f6b0ca16fe8bb896f81323926ca6e0671bf8ab3c88";
const JOYID_VERIFIER = "0xf1185da23bf04b638010038b40ec64b587654db5cb98eb39f0373ad8919bcd89";
const MAX_BACKUPS = 8;
const SECP_WITNESS_LOCK = 65;
const OMNILOCK_WITNESS_LOCK = 85;
const BINDING_MAGIC = "4b574542"; // "KWEB"
const BINDING_SIZE = 1024;
const LIST_MAGIC = "4b57524c"; // "KWRL"
const CODE_TTL_MS = 10 * 60_000;
const MAX_MESSAGE_BYTES = 4096;

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
  if (codeHash.length !== 32 || !(hashType in HASH_TYPES)) throw new Error(`${what} is invalid`);
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
async function fetchTransactions(hashes) {
  const unique = [...new Set(hashes)];
  if (unique.length === 0) return new Map();
  const body = JSON.stringify(unique.map((hash, id) => ({ id, jsonrpc: "2.0", method: "get_transaction", params: [hash] })));
  let lastError;
  for (const url of RPC_URLS) {
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

/**
 * Live cells under a lock, from the indexer, a page of 64 at a time; refuses more than `maxCells`. With `typeId`,
 * only cells whose type is a Type ID are returned.
 */
async function indexerCells(lock, maxCells, typeId = false) {
  const searchKey = {
    script: { code_hash: bytesToHex(lock.codeHash), hash_type: lock.hashType, args: bytesToHex(lock.args) },
    script_type: "lock",
    ...(typeId ? { filter: { script: { code_hash: TYPE_ID_CODE_HASH, hash_type: "type", args: "0x" } } } : {}),
  };
  const cells = [];
  let cursor = null;
  for (;;) {
    const body = JSON.stringify({ id: 0, jsonrpc: "2.0", method: "get_cells", params: [searchKey, "asc", "0x40", ...(cursor ? [cursor] : [])] });
    let result;
    let lastError;
    for (const url of RPC_URLS) {
      try {
        const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body, redirect: "error" });
        if (!response.ok) throw new Error(`CKB RPC returned HTTP ${response.status}`);
        result = (await response.json())?.result;
        if (!result || !Array.isArray(result.objects)) throw new Error("CKB RPC returned an invalid cell list");
        break;
      } catch (error) {
        result = undefined;
        lastError = error;
      }
    }
    if (!result) throw lastError ?? new Error("CKB RPC is unavailable");
    cells.push(...result.objects);
    if (cells.length > maxCells) throw new Error("This account has too many cells to check");
    if (result.objects.length < 0x40 || !result.last_cursor) return cells;
    cursor = result.last_cursor;
  }
}

/**
 * The type hashes of the live recovery lists this key made, under its owner-only list lock. Anyone can send a
 * cell to that lock, so a cell only counts if the transaction that created it spent one of the account's own
 * cells, which needs this key's signature. Each cell is checked against that transaction; that it is still live
 * is the node's word.
 */
async function liveLists(account) {
  // Only Type ID cells are asked for, so plain cells sent to the lock can't crowd out the check. Each fake list
  // locks its capacity under this key for good, so blocking with more than 1024 costs an attacker about 129k CKB.
  const objects = (await indexerCells(account.listLock, 1024, true)).filter((object) => isTypeId(object?.output?.type ? parseScript(object.output.type, "cell type") : undefined));
  // Two batched lookups in all, whatever the number of cells: the creating transactions, then their inputs.
  const created = await fetchTransactions(objects.map((object) => object?.out_point?.tx_hash));
  const spentFrom = await fetchTransactions([...created.values()].flatMap(({ tx }) => tx.inputs.map((input) => bytesToHex(input.previousOutput.txHash))));
  const hashes = [];
  for (const object of objects) {
    const creation = created.get(object.out_point.tx_hash);
    // After a reorganisation the node may still list a cell whose transaction is back in the pool; refuse until it
    // settles rather than decide on it either way.
    if (creation.status !== "committed") throw new Error("A recovery list transaction isn't committed yet. Try again in a minute");
    const tx = creation.tx;
    const output = tx.outputs[Number(num(object.out_point.index, "out point index"))];
    if (!output || !sameScript(output.lock, account.listLock) || !isTypeId(output.type)) throw new Error("CKB RPC returned a cell that isn't under the recovery list lock");
    // Proof is a spend from the key's own secp256k1 address or its owner-only list lock. An administrator-mode
    // Omnilock doesn't count: anyone can make one with this key's auth and their own list, and spend it with
    // their own backup. A failed lookup fails the whole check rather than leaving a list out.
    const proven = tx.inputs.some((input) => {
      const previous = spentFrom.get(bytesToHex(input.previousOutput.txHash)).tx;
      const cell = previous.outputs[input.previousOutput.index];
      if (!cell) throw new Error("An input doesn't exist");
      return ["secp256k1", "list"].includes(lockKind(account, cell.lock));
    });
    if (proven) hashes.push(bytesToHex(scriptHash(output.type)));
  }
  return [...new Set(hashes)];
}

async function inputCellsOf(tx) {
  const found = await fetchTransactions(tx.inputs.map((input) => bytesToHex(input.previousOutput.txHash)));
  return tx.inputs.map((input) => {
    const previous = found.get(bytesToHex(input.previousOutput.txHash)).tx;
    const index = input.previousOutput.index;
    if (index >= previous.outputs.length) throw new Error("An input doesn't exist");
    return { output: previous.outputs[index], data: previous.outputsData[index], createdBy: previous, index };
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

/** A version 2 list record ("KWRL" ‖ 0x02 ‖ count ‖ entries of 0xFD ‖ 62-byte preimage), as each entry's preimage. */
function parseListRecord(bytes) {
  if (!bytes || bytes.length < 6 || bytesToHex(bytes.slice(0, 4)) !== `0x${LIST_MAGIC}` || bytes[4] !== 2) throw new Error("The recovery list record is malformed");
  const count = bytes[5];
  if (count < 1 || count > MAX_BACKUPS || bytes.length !== 6 + count * 63) throw new Error("The recovery list record has the wrong number of backups");
  const entries = [];
  for (let i = 0; i < count; i++) {
    const at = 6 + i * 63;
    if (bytes[at] !== 0xfd) throw new Error("The recovery list record is malformed");
    const preimage = bytes.slice(at + 1, at + 63);
    const verifier = bytesToHex(preimage.slice(0, 32));
    // The verifier by data hash (data1), from cell dep 0 with the whole cell; then the backup's 20-byte id.
    if ((verifier !== EVM_VERIFIER && verifier !== JOYID_VERIFIER) || preimage[32] !== 0x02 || preimage[33] !== 0x00 || preimage.slice(34, 42).some((b) => b !== 0)) {
      throw new Error("The recovery list names a backup KeyWay doesn't support");
    }
    entries.push(preimage);
  }
  const keys = entries.map(bytesToHex);
  if (new Set(keys).size !== keys.length) throw new Error("A backup is listed twice");
  return entries;
}

const authOf = (preimage) => concat([0xfd], ckbHash(preimage).slice(0, 20));

function describeBackup(preimage) {
  const id = bytesToHex(preimage.slice(42));
  return bytesToHex(preimage.slice(0, 32)) === EVM_VERIFIER ? `EVM wallet ${id}` : `JoyID passkey (key id ${id})`;
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

/** The whitelist root for these preimages: each key is the 21-byte auth and 11 zero bytes, each value 0x01 ‖ 31 zeros. */
function whitelistRoot(preimages) {
  const branches = new Map();
  const value = concat([0x01], new Uint8Array(31));
  let root = new Uint8Array(32);
  for (const preimage of preimages) {
    let currentKey = concat(authOf(preimage), new Uint8Array(11));
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

/** The members a list cell holds, from the record its creating transaction wrote, checked against its root. */
function listMembers(record, data) {
  const entries = parseListRecord(record);
  if (!equalBytes(whitelistRoot(entries), listRoot(data))) throw new Error("The recorded backups don't match the recovery list's root");
  return entries;
}

function recordAt(tx, index) {
  const witness = tx.witnesses[index];
  if (!witness || witness.length === 0) return undefined;
  try { return parseWitnessArgs(witness).outputType; } catch { return undefined; }
}

// ---------- the email binding ----------

/** "KWEB" ‖ 0x01 ‖ u16 length ‖ the PKP-encrypted email ‖ zero padding, BINDING_SIZE bytes in all. */
function encodeBinding(ciphertext) {
  const bytes = utf8(ciphertext);
  if (bytes.length > BINDING_SIZE - 7) throw new Error("The encrypted email is too long");
  const out = new Uint8Array(BINDING_SIZE);
  out.set(hexToBytes(`0x${BINDING_MAGIC}`), 0);
  out[4] = 1; out[5] = bytes.length & 0xff; out[6] = bytes.length >> 8;
  out.set(bytes, 7);
  return out;
}

function decodeBinding(bytes) {
  if (!bytes || bytes.length !== BINDING_SIZE || bytesToHex(bytes.slice(0, 4)) !== `0x${BINDING_MAGIC}` || bytes[4] !== 1) throw new Error("The email binding is malformed");
  const length = bytes[5] | (bytes[6] << 8);
  if (length === 0 || 7 + length > BINDING_SIZE || bytes.slice(7 + length).some((b) => b !== 0)) throw new Error("The email binding is malformed");
  return new TextDecoder().decode(bytes.slice(7, 7 + length));
}

function checkEmail(email) {
  if (typeof email !== "string" || email.length > 254 || !/^[^\s@<>",;]{1,64}@[A-Za-z0-9.-]{1,189}\.[A-Za-z]{2,63}$/.test(email)) throw new Error("A valid email address is required");
  return email;
}

async function emailFromBinding(pkpId, binding) {
  const plaintext = await Lit.Actions.Decrypt({ pkpId, ciphertext: decodeBinding(binding) });
  let parsed;
  try { parsed = JSON.parse(plaintext); } catch { throw new Error("The email binding is malformed"); }
  if (parsed?.v !== 1 || parsed.purpose !== "keyway-email-binding") throw new Error("The email binding is malformed");
  return checkEmail(parsed.email);
}

/**
 * The email bound when this account turned recovery on, or undefined for an account that turned it on before
 * this Action existed. The enabling transaction is the only one that could spend the input its Type ID comes
 * from, and its witness 0 must carry a valid signature by this account's key over the binding.
 */
async function boundEmail(pkpId, account, listType, enableHash) {
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
  return emailFromBinding(pkpId, witness.inputType);
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
    const typeHash = bytesToHex(scriptHash(output.type));
    for (const ref of refs) if (ref !== typeHash) throw new Error("An output goes to an address with another recovery list");
    // First wins: a key that already has a recovery list can never make a second one (and an address with it).
    if ((await liveLists(account)).length > 0) throw new Error("Recovery is already on for this key");
    // Every live plain cell at the key's secp256k1 address must be spent, so two enables signed before either is
    // indexed spend the same cells and at most one can ever commit.
    const spending = new Set(tx.inputs.map((input) => `${bytesToHex(input.previousOutput.txHash)}:${input.previousOutput.index}`));
    for (const cell of await indexerCells(account.secp, 256)) {
      if (cell?.output?.type || (cell?.output_data ?? "0x") !== "0x") continue;
      const key = `${cell.out_point?.tx_hash}:${Number(num(cell.out_point?.index, "out point index"))}`;
      if (!spending.has(key)) throw new Error("Turning recovery on must spend every plain cell at this key's address");
    }
    const members = listMembers(recordAt(tx, 0), tx.outputsData[0]);
    const witness = parseWitnessArgs(tx.witnesses[0] ?? new Uint8Array(0));
    op = { kind: "enable", members, binding: witness.inputType };
  } else if (listInputs.length === 1) {
    const input = listInputs[0];
    if (listOutputs.length !== 1) throw new Error("A recovery list can't be destroyed");
    const { output, index } = listOutputs[0];
    if (!sameScript(input.output.lock, account.listLock)) throw new Error("This recovery list isn't locked to this account's key");
    if (!isTypeId(input.output.type) || !sameScript(output.type, input.output.type)) throw new Error("A recovery list's Type ID can't change");
    if (!sameScript(output.lock, input.output.lock)) throw new Error("A recovery list's lock can't change");
    if (output.capacity !== input.output.capacity) throw new Error("A recovery list's capacity can't change");
    const after = listMembers(recordAt(tx, index), tx.outputsData[index]);
    // The members before: the record the list's own transaction wrote, or for a list made before records
    // existed, the record the caller supplies; either must hash to the list's current root.
    const previous = recordAt(input.createdBy, input.index) ?? (typeof params.previousListRecord === "string" ? hexToBytes(params.previousListRecord, "previousListRecord") : undefined);
    if (!previous) throw new Error("The recovery list's current backups aren't recorded; previousListRecord is required");
    const before = listMembers(previous, input.data);
    const was = new Set(before.map(bytesToHex));
    const now = new Set(after.map(bytesToHex));
    const added = after.filter((entry) => !was.has(bytesToHex(entry)));
    const removed = before.filter((entry) => !now.has(bytesToHex(entry)));
    if (added.length + removed.length !== 1) throw new Error("A recovery list change must add or remove exactly one backup");
    const change = added.length ? { kind: "add", backup: added[0] } : { kind: "remove", backup: removed[0] };
    const email = await boundEmail(pkpId, account, input.output.type, params.enableTransactionHash);
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
    return emailFromBinding(pkpId, op.binding);
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
      const ciphertext = await Lit.Actions.Encrypt({ pkpId, message: JSON.stringify({ v: 1, purpose: "keyway-email-binding", email }) });
      result.binding = bytesToHex(encodeBinding(ciphertext));
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

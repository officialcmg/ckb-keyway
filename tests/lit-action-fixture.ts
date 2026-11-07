// A fake Lit runtime for the policy Action (lit-actions/sign-ckb-transaction.js): the Lit global, ethers v5's
// SigningKey, a CKB RPC answering get_transaction batches from known transactions, and an email API that records
// what it was asked to send. The Action's source runs unchanged.
import assert from "node:assert/strict";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { loadLitAction } from "../src/server/lit-actions.ts";

const hex = (bytes: Uint8Array) => ccc.hexFrom(bytes);

export const fakeEthers = {
  utils: {
    SigningKey: class {
      readonly compressedPublicKey: string;
      constructor(readonly key: string) { this.compressedPublicKey = hex(secp256k1.getPublicKey(ccc.bytesFrom(key), true)); }
      signDigest(digest: string) {
        const signature = secp256k1.sign(ccc.bytesFrom(digest), ccc.bytesFrom(this.key), { prehash: false, format: "recovered" } as never) as Uint8Array;
        return { r: hex(signature.slice(1, 33)), s: hex(signature.slice(33, 65)), recoveryParam: signature[0] };
      }
    },
    recoverPublicKey(digest: Uint8Array, signature: { r: string; s: string; recoveryParam: number }) {
      const bytes = Uint8Array.from([signature.recoveryParam, ...ccc.bytesFrom(signature.r), ...ccc.bytesFrom(signature.s)]);
      return hex(secp256k1.recoverPublicKey(bytes, digest, { prehash: false }));
    },
    computePublicKey(key: string, compressed: boolean) {
      return hex(secp256k1.Point.fromBytes(ccc.bytesFrom(key)).toBytes(compressed));
    },
  },
};

export type SentEmail = { to: string[]; text: string; from: string; key: string };

export type ActionModule = {
  main: (params: Record<string, unknown>) => Promise<unknown>;
  ckbHash: (...parts: Uint8Array[]) => Uint8Array;
  whitelistRoot: (auths: Uint8Array[]) => Uint8Array;
  parseListRecord: (record: Uint8Array) => Uint8Array[];
  listMembers: (record: Uint8Array, data: Uint8Array) => Uint8Array[];
  backupAuth: (backup: { kind: string; id: Uint8Array }, salt: Uint8Array) => Uint8Array;
  rawTransactionHash: (tx: unknown) => Uint8Array;
  parseTransaction: (tx: unknown) => unknown;
};

/**
 * A Lit runtime for one PKP. `lookup` answers the chain: a known transaction and its status, or undefined.
 * Encryption is a reversible stand-in, as only the Action and Lit ever see the plaintext.
 */
export function fakeLit(options: {
  privateKey: Uint8Array;
  pkpId: string;
  actionKey?: Uint8Array;
  lookup: (hash: string) => { tx: ccc.Transaction; status: string } | undefined;
  /** Every transaction the chain has, for the indexer's live cells and lock histories. */
  transactions: () => ccc.Transaction[];
  /** RPC methods whose calls fail with HTTP 500, as an unreachable node would. */
  failing?: (method: string) => boolean;
}) {
  /** Every transaction hash the Action fetched with get_transaction. */
  const fetched: string[] = [];
  /** How many history entries each get_transactions call returned. */
  const historyReads: number[] = [];
  // Hashing is the fixture's main cost with large transactions, so each transaction is hashed once.
  const hashes = new WeakMap<ccc.Transaction, string>();
  const hashOf = (tx: ccc.Transaction) => { let hash = hashes.get(tx); if (!hash) { hash = tx.hash(); hashes.set(tx, hash); } return hash; };
  const actionKey = options.actionKey ?? secp256k1.utils.randomSecretKey();
  const emails: SentEmail[] = [];
  const script = (s: ccc.Script) => ({ code_hash: s.codeHash, hash_type: s.hashType, args: s.args });
  const rpcTx = (tx: ccc.Transaction) => ({
    version: "0x0",
    cell_deps: tx.cellDeps.map((dep) => ({ out_point: { tx_hash: dep.outPoint.txHash, index: ccc.numToHex(dep.outPoint.index) }, dep_type: dep.depType === "depGroup" ? "dep_group" : "code" })),
    header_deps: tx.headerDeps,
    inputs: tx.inputs.map((input) => ({ previous_output: { tx_hash: input.previousOutput.txHash, index: ccc.numToHex(input.previousOutput.index) }, since: ccc.numToHex(input.since) })),
    outputs: tx.outputs.map((output) => ({ capacity: ccc.numToHex(output.capacity), lock: script(output.lock), type: output.type ? script(output.type) : null })),
    outputs_data: tx.outputsData,
    witnesses: tx.witnesses,
  });
  const fetch = async (url: string, init: { body: string; headers: Record<string, string> }) => {
    if (url === "https://api.resend.com/emails") {
      const body = JSON.parse(init.body);
      emails.push({ to: body.to, text: body.text, from: body.from, key: init.headers.Authorization });
      return new Response(JSON.stringify({ id: "email" }), { status: 200 });
    }
    assert.ok(["https://testnet.ckb.dev/", "https://testnet.ckbapp.dev/"].includes(url), url);
    const parsed = JSON.parse(init.body);
    const methods = Array.isArray(parsed) ? parsed.map((call: { method: string }) => call.method) : [parsed.method];
    if (options.failing && methods.some(options.failing)) return new Response("node unavailable", { status: 500 });
    // Each transaction is in its own block, numbered by its place in `transactions()`.
    const history = (key: { script: { code_hash: string; hash_type: string; args: string }; script_search_mode?: string; filter?: { block_range?: [string, string] } }) => {
      const { script: wanted, script_search_mode: mode, filter } = key;
      const matches = (lock: ccc.Script) => lock.codeHash === wanted.code_hash && lock.hashType === wanted.hash_type && (mode === "exact" ? lock.args === wanted.args : lock.args.startsWith(wanted.args));
      const all = options.transactions();
      const byHash = new Map(all.map((tx) => [hashOf(tx), tx]));
      const [from, to] = filter?.block_range ? filter.block_range.map(Number) : [0, Infinity];
      const objects = all.flatMap((tx, block) => block < from || block >= to ? [] : [
        ...tx.inputs.flatMap((input, index) => {
          const previous = byHash.get(input.previousOutput.txHash)?.outputs[Number(input.previousOutput.index)];
          return previous && matches(previous.lock) ? [{ tx_hash: hashOf(tx), io_type: "input", io_index: ccc.numToHex(index), block_number: ccc.numToHex(block) }] : [];
        }),
        ...tx.outputs.flatMap((output, index) => matches(output.lock) ? [{ tx_hash: hashOf(tx), io_type: "output", io_index: ccc.numToHex(index), block_number: ccc.numToHex(block) }] : []),
      ]);
      historyReads.push(objects.length);
      return { objects, last_cursor: "0x" };
    };
    if (Array.isArray(parsed) && parsed.every((call: { method: string }) => call.method === "get_transactions")) {
      return new Response(JSON.stringify(parsed.map((call: { id: number; params: [Parameters<typeof history>[0]] }) => ({ id: call.id, jsonrpc: "2.0", result: history(call.params[0]) }))), { status: 200 });
    }
    if (!Array.isArray(parsed) && parsed.method === "get_transactions") {
      return new Response(JSON.stringify({ id: parsed.id, jsonrpc: "2.0", result: history(parsed.params[0]) }), { status: 200 });
    }
    if (!Array.isArray(parsed) && parsed.method === "get_cells") {
      const [{ script: wanted, filter, script_search_mode: mode }] = parsed.params as [{ script: { code_hash: string; hash_type: string; args: string }; script_search_mode?: string; filter?: { script?: { code_hash: string; hash_type: string; args: string }; script_len_range?: [string, string]; output_data_len_range?: [string, string] } }];
      // As ckb-indexer: with a lock search, script_len_range is the type script's length, 0 with no type.
      const inRange = (range: [string, string] | undefined, length: number) => !range || (length >= Number(range[0]) && length < Number(range[1]));
      const typeLength = (output: ccc.CellOutput) => output.type ? output.type.toBytes().length : 0;
      // As ckb-indexer: the lock's args match by prefix unless the request asks for "exact".
      const argsMatch = (args: string) => mode === "exact" ? args === wanted.args : args.startsWith(wanted.args);
      const typeFilter = filter?.script;
      const all = options.transactions();
      const spent = new Set(all.flatMap((tx) => tx.inputs.map((input) => `${input.previousOutput.txHash}:${input.previousOutput.index}`)));
      const objects = all.flatMap((tx, block) => tx.outputs.map((output, index) => ({ tx, output, index, block })))
        .filter(({ tx, output, index }) => !spent.has(`${hashOf(tx)}:${index}`) && output.lock.codeHash === wanted.code_hash && output.lock.hashType === wanted.hash_type && argsMatch(output.lock.args)
          && (!typeFilter || (output.type?.codeHash === typeFilter.code_hash && output.type.hashType === typeFilter.hash_type && output.type.args.startsWith(typeFilter.args)))
          && inRange(filter?.script_len_range, typeLength(output)) && inRange(filter?.output_data_len_range, ccc.bytesFrom(tx.outputsData[index]).length))
        .map(({ tx, output, index, block }) => ({ block_number: ccc.numToHex(block), out_point: { tx_hash: hashOf(tx), index: ccc.numToHex(index) }, output: { capacity: ccc.numToHex(output.capacity), lock: script(output.lock), type: output.type ? script(output.type) : null }, output_data: tx.outputsData[index] }));
      return new Response(JSON.stringify({ id: parsed.id, jsonrpc: "2.0", result: { objects, last_cursor: "0x" } }), { status: 200 });
    }
    const calls = parsed as Array<{ id: number; params: [string] }>;
    return new Response(JSON.stringify(calls.map(({ id, params: [hash] }) => {
      fetched.push(hash);
      const found = options.lookup(hash);
      return { id, jsonrpc: "2.0", result: found ? { transaction: rpcTx(found.tx), tx_status: { status: found.status } } : null };
    })), { status: 200 });
  };
  const Lit = {
    Actions: {
      getPrivateKey: async ({ pkpId }: { pkpId: string }) => { assert.equal(pkpId, options.pkpId); return hex(options.privateKey); },
      getLitActionPrivateKey: async () => hex(actionKey),
      Encrypt: async ({ pkpId, message }: { pkpId: string; message: string }) => { assert.equal(pkpId, options.pkpId); return `enc:${Buffer.from(message).toString("base64")}`; },
      Decrypt: async ({ pkpId, ciphertext }: { pkpId: string; ciphertext: string }) => {
        assert.equal(pkpId, options.pkpId);
        if (!ciphertext.startsWith("enc:")) throw new Error("decryption failed");
        return Buffer.from(ciphertext.slice(4), "base64").toString();
      },
    },
  };
  const load = async (): Promise<ActionModule> => {
    const source = await loadLitAction("sign-ckb-transaction");
    return new Function("Lit", "ethers", "fetch", `${source}\nreturn { main, ckbHash, whitelistRoot, rawTransactionHash, parseTransaction, parseListRecord, listMembers, backupAuth, resolveBackups };`)(Lit, fakeEthers, fetch) as ActionModule;
  };
  /** Runs the Action the way `runLitAction` would. */
  const runner = async () => {
    const action = await load();
    return async (_config: unknown, params: Record<string, unknown>) => action.main(params);
  };
  return { emails, fetch, Lit, load, runner, fetched, historyReads };
}

/** The code in the last email the Action sent. */
export const litCodeIn = (email: SentEmail) => /Your confirmation code is (\d{8})/.exec(email.text)![1];

// Reads what happened to a channel's funding cell from CKB RPC alone: the transaction that spent it and everything
// downstream of that, each with its block, block time (UTC), epoch, the inputs' `since` and its outputs.
//
//   node research/e2e/trace-close.mjs <funding tx hash>:<index> [<another>...]
//
// A cell still unspent is printed as LIVE; that is what remains to be claimed.
const RPC = process.env.CKB_RPC ?? "https://testnet.ckb.dev/";
async function rpc(method, params) {
  for (let attempt = 0; ; attempt++) {
    try {
      const response = await fetch(RPC, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: 1, jsonrpc: "2.0", method, params }), signal: AbortSignal.timeout(30_000) });
      const body = await response.json();
      if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
      return body.result;
    } catch (error) {
      if (attempt >= 4) throw error;
      await new Promise((r) => setTimeout(r, 3000 * (attempt + 1)));
    }
  }
}
/** An epoch as "number + index/length", from the header's packed field. */
export function epochOf(packed) {
  const value = BigInt(packed);
  return { number: value & 0xffffffn, index: (value >> 24n) & 0xffffn, length: (value >> 40n) & 0xffffn };
}
const showEpoch = ({ number, index, length }) => `${number} ${index}/${length}`;
/** A `since` in words: only the relative epoch form (what the commitment lock uses) is spelled out. */
export function sinceOf(packed) {
  const value = BigInt(packed);
  if (value === 0n) return "none";
  if (value >> 56n === 0xa0n) return `relative epoch ${showEpoch(epochOf(value & 0x00ffffffffffffffn))} (${packed})`;
  return packed;
}
const ckb = (capacity) => `${(Number(BigInt(capacity)) / 1e8).toFixed(8)} CKB`;
const lockOf = (lock) => `${lock.code_hash.slice(0, 10)}…/${lock.args.length > 46 ? `${lock.args.slice(0, 22)}…(${(lock.args.length - 2) / 2} bytes)` : lock.args}`;

async function spenderOf(txHash, index, lock) {
  const live = await rpc("get_live_cell", [{ tx_hash: txHash, index: `0x${index.toString(16)}` }, false]);
  if (live.status === "live") return undefined;
  let cursor = null;
  for (let page = 0; page < 20; page++) {
    const result = await rpc("get_transactions", [{ script: lock, script_type: "lock", script_search_mode: "exact" }, "desc", "0x64", cursor]);
    for (const item of result.objects) {
      if (item.io_type !== "input") continue;
      const tx = (await rpc("get_transaction", [item.tx_hash])).transaction;
      if (tx.inputs.some((input) => input.previous_output.tx_hash === txHash && Number(input.previous_output.index) === index)) return item.tx_hash;
    }
    if (result.objects.length < 100) break;
    cursor = result.last_cursor;
  }
  return "unknown";
}

async function describe(hash, depth, seen) {
  const pad = "  ".repeat(depth);
  const found = await rpc("get_transaction", [hash]);
  if (found?.tx_status?.status !== "committed") { console.log(`${pad}${hash} ${found?.tx_status?.status ?? "unknown"}`); return; }
  const header = await rpc("get_header", [found.tx_status.block_hash]);
  const time = new Date(Number(BigInt(header.timestamp))).toISOString().replace("T", " ").slice(0, 19);
  console.log(`${pad}${hash}`);
  console.log(`${pad}  block ${BigInt(header.number)}, ${time} UTC, epoch ${showEpoch(epochOf(header.epoch))}`);
  for (const input of found.transaction.inputs) console.log(`${pad}  in  ${input.previous_output.tx_hash}:${Number(input.previous_output.index)} since ${sinceOf(input.since)}`);
  const next = [];
  for (const [index, output] of found.transaction.outputs.entries()) {
    const by = await spenderOf(hash, index, output.lock);
    console.log(`${pad}  out ${index}: ${ckb(output.capacity)} to ${lockOf(output.lock)} ${by ? `spent by ${by}` : "LIVE"}`);
    if (by && by !== "unknown" && !seen.has(by)) { seen.add(by); next.push(by); }
  }
  for (const by of next) await describe(by, depth + 1, seen);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  for (const outpoint of process.argv.slice(2)) {
    const [hash, index] = outpoint.split(":");
    const funding = (await rpc("get_transaction", [hash])).transaction;
    console.log(`funding ${hash}:${index} (${ckb(funding.outputs[Number(index)].capacity)})`);
    const by = await spenderOf(hash, Number(index), funding.outputs[Number(index)].lock);
    if (!by) console.log("  LIVE: the channel's funding is unspent");
    else if (by === "unknown") console.log("  spent, spender not found");
    else await describe(by, 1, new Set([by]));
  }
}

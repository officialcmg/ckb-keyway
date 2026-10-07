export {};

const url = process.env.CKB_NODE_RPC_URL ?? "https://testnet.ckbapp.dev/";
let id = 0;
async function rpc(method: string, params: unknown[]) {
  const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }), signal: AbortSignal.timeout(15_000) });
  const body = await response.json();
  if (!response.ok || body.error) throw new Error(`Settlement RPC failed: ${method}`);
  return body.result;
}
for (const outpoint of process.argv.slice(2)) {
  if (!/^0x[0-9a-f]{72}$/.test(outpoint)) throw new Error("Funding outpoint must contain a transaction hash and little-endian output index");
  const hash = outpoint.slice(0, 66);
  const index = Buffer.from(outpoint.slice(66), "hex").readUInt32LE();
  const funding = await rpc("get_transaction", [hash]);
  const lock = funding?.transaction?.outputs?.[index]?.lock;
  if (!lock) throw new Error("Funding output is unavailable");
  const transactions = await rpc("get_transactions", [{ script: lock, script_type: "lock", script_search_mode: "exact", group_by_transaction: true }, "desc", "0x64"]);
  let closing;
  for (const item of transactions.objects ?? []) {
    const transaction = await rpc("get_transaction", [item.tx_hash]);
    if (transaction.transaction?.inputs?.some((input: { previous_output: { tx_hash: string; index: string } }) => input.previous_output.tx_hash === hash && Number(BigInt(input.previous_output.index)) === index)) {
      closing = transaction;
      break;
    }
  }
  if (!closing || closing.tx_status.status !== "committed") throw new Error("No committed funding-spend transaction found; preserve channel state");
  const tip = BigInt(await rpc("get_tip_block_number", []));
  const block = await rpc("get_header", [closing.tx_status.block_hash]);
  console.log(JSON.stringify({ fundingOutpoint: outpoint, closingTransaction: closing.transaction.hash, status: closing.tx_status.status, confirmations: Number(tip - BigInt(block.number) + 1n), outputs: closing.transaction.outputs.map((output: { capacity: string; lock: unknown }) => ({ capacity: output.capacity, lock: output.lock })) }));
}

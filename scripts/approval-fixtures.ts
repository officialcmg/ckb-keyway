// Writes the fixtures contracts/tests checks KeyWay's verifiers against (deterministic: npx tsx
// scripts/approval-fixtures.ts):
// - tests/fixtures/approval-text-cases.json: random scripts and amounts with the full address CCC produces and
//   the approval text the SDK builds (null when it is too long);
// - tests/fixtures/approval-transaction-cases.json: random transactions spending an account's cells (plain and
//   token cells, some of them someone else's), with the text the SDK's `rescueApproval` reads from them, or null
//   when it refuses them as not a rescue: among them token cells changed, left out, moved twice, taken from
//   someone else, or made under a type script the account didn't hold.
import { writeFileSync } from "node:fs";
import * as ccc from "@ckb-ccc/core";
import { recoveryApprovalText, rescueApproval } from "../src/sdk/browser/recovery-approval.ts";

let seed = 0x4b57;
const random = () => { seed = (seed * 1103515245 + 12345) % 2 ** 31; return seed / 2 ** 31; };
const bytes = (length: number) => Uint8Array.from({ length }, () => Math.floor(random() * 256));
const pick = <T>(values: T[]) => values[Math.floor(random() * values.length)];
const bigRandom = (max: bigint) => BigInt(Math.floor(random() * 2 ** 31)) * BigInt(Math.floor(random() * 2 ** 31)) % max;

const networks = [{ name: "testnet", client: new ccc.ClientPublicTestnet() }, { name: "mainnet", client: new ccc.ClientPublicMainnet() }] as const;
const hashTypes: Record<ccc.HashType, number> = { data: 0, type: 1, data1: 2, data2: 4 };
const cases = [];
for (let index = 0; index < 400; index++) {
  const network = pick([...networks]);
  const hashType = pick(Object.keys(hashTypes) as ccc.HashType[]);
  const argsLength = index < 20 ? [0, 1, 20, 22, 32, 54, 64, 100, 120, 150][index % 10] : pick([0, 20, 20, 21, 32, 54, 54, Math.floor(random() * 130), 160 + Math.floor(random() * 100)]);
  const destination = ccc.Script.from({ codeHash: bytes(32), hashType, args: bytes(argsLength) });
  const ckb = pick([1n, 100_000_000n, 6_100_000_000n, bigRandom(10n ** 18n), 33_600_000_000n * 100_000_000n, bigRandom(10n ** 12n)]);
  const fee = pick([0n, 1n, 765n, 1_000n, bigRandom(10n ** 9n), 100_000_000n]);
  const tokenCells = pick([0, 0, 1, 2, Math.floor(random() * 120)]);
  const sighash = ccc.hexFrom(bytes(32));
  let text: string | null;
  try { text = recoveryApprovalText(network.client, { destination, ckb, tokenCells, fee }, sighash); } catch { text = null; }
  cases.push({
    network: network.name,
    codeHash: destination.codeHash, hashType: hashTypes[hashType], args: destination.args,
    address: ccc.Address.fromScript(destination, network.client).toString(),
    ckb: ckb.toString(), fee: fee.toString(), tokenCells, sighash, text,
  });
}
writeFileSync(new URL("../tests/fixtures/approval-text-cases.json", import.meta.url), JSON.stringify(cases, null, 1) + "\n");
console.log(cases.length, "text cases,", cases.filter((value) => value.text === null).length, "too long");

// The account's lock in the tests' mock transactions runs a stand-in binary whose data is 0x00 (data1). Its args
// have a KeyWay account's shape, auth ‖ 0x01 (administrator mode) ‖ AdminList type hash (the verifiers' salt).
const accountArgs = bytes(54);
accountArgs[21] = 0x01;
const account = ccc.Script.from({ codeHash: ccc.hashCkb("0x00"), hashType: "data1", args: accountArgs });
const randomScript = (argsLength = Math.floor(random() * 60)) => ccc.Script.from({ codeHash: bytes(32), hashType: pick(Object.keys(hashTypes) as ccc.HashType[]), args: bytes(argsLength) });
const json = (script: ccc.Script) => ({ codeHash: script.codeHash, hashType: script.hashType, args: script.args });
const transactions = [];
type Cell = { lock: ccc.Script; type?: ccc.Script; data: ccc.Hex; capacity: bigint };
for (let index = 0; index < 160; index++) {
  const network = pick([...networks]);
  const destination = randomScript();
  // The account's token cells, which an honest rescue moves to the destination one to one, unchanged.
  const tokenInputs: Cell[] = Array.from({ length: Math.floor(random() * 4) }, () => ({
    lock: account, type: randomScript(32), data: ccc.hexFrom(bytes(16)), capacity: 20_000_000_000n + bigRandom(10n ** 11n),
  }));
  // Sometimes two of them are identical (same type script and data): each must still move once.
  if (tokenInputs.length > 1 && random() < 0.15) tokenInputs[1] = { ...tokenInputs[0] };
  let moved = tokenInputs.map((cell) => ({ ...cell, lock: destination }));
  // What a builder might try behind the same "N token cells" text instead.
  const roll = random();
  if (roll < 0.06 && moved.length > 0) moved[0] = { ...moved[0], data: ccc.hexFrom(bytes(16)) }; // a token cell changed (burned in part)
  else if (roll < 0.12 && moved.length > 0) moved = moved.slice(1); // a token cell left out (burned)
  else if (roll < 0.18) moved.push({ lock: destination, type: randomScript(32), data: ccc.hexFrom(bytes(8)), capacity: 20_000_000_000n }); // CKB under a type script the account didn't hold
  else if (roll < 0.22 && moved.length > 0) moved[0] = { ...moved[0], type: randomScript(32) }; // the same data under another type script
  else if (roll < 0.26 && moved.length > 0) moved.push({ ...moved[0] }); // one token cell moved twice
  const plain = Array.from({ length: Math.floor(random() * 3) }, (): Cell => {
    const other = random();
    return { lock: other < 0.04 ? account : other < 0.08 ? randomScript() : destination, data: random() < 0.05 ? ccc.hexFrom(bytes(4)) : "0x", capacity: 6_100_000_000n + bigRandom(10n ** 13n) };
  });
  const outputs = [...moved, ...plain].sort(() => random() - 0.5);
  if (outputs.length === 0) outputs.push({ lock: destination, data: "0x", capacity: 6_100_000_000n + bigRandom(10n ** 13n) });
  const outputTotal = outputs.reduce((sum, output) => sum + output.capacity, 0n);
  const tokenTotal = tokenInputs.reduce((sum, cell) => sum + cell.capacity, 0n);
  const extra = random() < 0.05 ? -1n : pick([0n, 765n, bigRandom(10n ** 8n)]);
  // Plain inputs: the first pays for the outputs; others may be the account's or someone else's, sometimes with a
  // type script of their own (someone else's token cell isn't the account's to move).
  const plainInputs: Cell[] = Array.from({ length: 1 + Math.floor(random() * 3) }, (_, at) => {
    const foreign = at > 0 && random() >= 0.8;
    const typed = foreign && random() < 0.5;
    return { lock: foreign ? randomScript(20) : account, type: typed ? randomScript(32) : undefined, data: typed ? ccc.hexFrom(bytes(16)) : "0x", capacity: at === 0 ? 0n : 6_100_000_000n + bigRandom(10n ** 11n) };
  });
  const first = outputTotal + extra - tokenTotal;
  plainInputs[0].capacity = first > 0n ? first : 1n;
  // A token cell moved from someone else's input rather than the account's.
  if (random() < 0.05 && tokenInputs.length > 0) tokenInputs[0] = { ...tokenInputs[0], lock: randomScript(20) };
  const inputs = [...tokenInputs, ...plainInputs].sort(() => random() - 0.5);
  const transaction = ccc.Transaction.from({
    inputs: inputs.map((_, at) => ({ previousOutput: { txHash: ccc.hexFrom(ccc.numBeToBytes(at + 0x100, 32)), index: 0 } })),
    outputs: outputs.map(({ lock, type, capacity }) => ({ lock, type, capacity })),
    outputsData: outputs.map(({ data }) => data),
  });
  const sighash = ccc.hexFrom(bytes(32));
  let text: string | null;
  try {
    text = recoveryApprovalText(network.client, rescueApproval(transaction, account, inputs.map(({ lock, type, data, capacity }) => ({ cellOutput: { lock, type, capacity }, outputData: data }))), sighash);
  } catch { text = null; }
  transactions.push({
    network: network.name, account: json(account), sighash, text,
    inputs: inputs.map(({ lock, type, data, capacity }) => ({ lock: json(lock), type: type ? json(type) : null, data, capacity: capacity.toString() })),
    // The capacities as the transaction holds them: CCC raises one below its cell's occupied size.
    outputs: outputs.map(({ lock, type, data }, at) => ({ lock: json(lock), type: type ? json(type) : null, data, capacity: transaction.outputs[at].capacity.toString() })),
  });
}
writeFileSync(new URL("../tests/fixtures/approval-transaction-cases.json", import.meta.url), JSON.stringify(transactions, null, 1) + "\n");
console.log(transactions.length, "transaction cases,", transactions.filter((value) => value.text === null).length, "refused");
process.exit(0);

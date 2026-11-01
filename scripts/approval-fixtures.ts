// Writes the fixtures contracts/tests checks KeyWay's verifiers against (deterministic: npx tsx
// scripts/approval-fixtures.ts):
// - tests/fixtures/approval-text-cases.json: random scripts and amounts with the full address CCC produces and
//   the approval text the SDK builds (null when it is too long);
// - tests/fixtures/approval-transaction-cases.json: random transactions spending an account's cells, with the
//   text the SDK's `rescueApproval` reads from them, or null when it refuses them as not a rescue.
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

// The account's lock in the tests' mock transactions runs a stand-in binary whose data is 0x00 (data1).
const account = ccc.Script.from({ codeHash: ccc.hashCkb("0x00"), hashType: "data1", args: bytes(54) });
const randomScript = (argsLength = Math.floor(random() * 60)) => ccc.Script.from({ codeHash: bytes(32), hashType: pick(Object.keys(hashTypes) as ccc.HashType[]), args: bytes(argsLength) });
const json = (script: ccc.Script) => ({ codeHash: script.codeHash, hashType: script.hashType, args: script.args });
const transactions = [];
for (let index = 0; index < 120; index++) {
  const network = pick([...networks]);
  const destination = randomScript();
  const outputs = Array.from({ length: 1 + Math.floor(random() * 6) }, () => {
    const roll = random();
    const lock = roll < 0.04 ? account : roll < 0.08 ? randomScript() : destination;
    const typed = random() < 0.4;
    return {
      lock, type: typed ? randomScript(32) : undefined,
      data: typed ? ccc.hexFrom(bytes(16)) : random() < 0.05 ? ccc.hexFrom(bytes(4)) : "0x",
      capacity: 6_100_000_000n + bigRandom(10n ** 13n),
    };
  });
  const outputTotal = outputs.reduce((sum, output) => sum + output.capacity, 0n);
  const inputCount = 1 + Math.floor(random() * 4);
  const extra = random() < 0.05 ? -1n : pick([0n, 765n, bigRandom(10n ** 8n)]);
  const inputs = Array.from({ length: inputCount }, (_, at) => ({
    lock: at === 0 || random() < 0.8 ? account : randomScript(20),
    capacity: at === 0 ? outputTotal + extra : 6_100_000_000n + bigRandom(10n ** 11n),
  }));
  const inputTotal = inputs.reduce((sum, input) => sum + input.capacity, 0n);
  const transaction = ccc.Transaction.from({ outputs: outputs.map(({ lock, type, capacity }) => ({ lock, type, capacity })), outputsData: outputs.map(({ data }) => data) });
  const sighash = ccc.hexFrom(bytes(32));
  let text: string | null;
  try { text = recoveryApprovalText(network.client, rescueApproval(transaction, account, inputTotal), sighash); } catch { text = null; }
  transactions.push({
    network: network.name, account: json(account), sighash, text,
    inputs: inputs.map(({ lock, capacity }) => ({ lock: json(lock), capacity: capacity.toString() })),
    outputs: outputs.map(({ lock, type, data, capacity }) => ({ lock: json(lock), type: type ? json(type) : null, data, capacity: capacity.toString() })),
  });
}
writeFileSync(new URL("../tests/fixtures/approval-transaction-cases.json", import.meta.url), JSON.stringify(transactions, null, 1) + "\n");
console.log(transactions.length, "transaction cases,", transactions.filter((value) => value.text === null).length, "refused");
process.exit(0);

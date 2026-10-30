import * as ccc from "@ckb-ccc/core";
import { knownOmnilock, keywayOmnilock, type OmnilockDeployment } from "../sdk/browser/account-lock";
import type { EthereumProvider } from "../sdk/browser/account-recovery";
import { describeBackup, normalizeEvmAddress } from "../sdk/browser/recovery-backups";
import { recoveryListFrom, type RecoveryListEntry } from "../sdk/browser/recovery-list";
import { prepareRecoverySpend, prepareRecoveryWitness, signRecoverySpendWithEvm, signRecoverySpendWithJoyId, type RecoverySpend } from "../sdk/browser/recovery-spend";
import { addTokenCellDeps } from "../sdk/browser/settlement-sweep";
import { formatAsset, hasPlainTokenArgs, isXudtCompatible } from "../sdk/browser/tokens";

/**
 * The rescue: moving everything out of a KeyWay account with recovery on, signed by one of its backups, with
 * nothing but a public CKB node. No KeyWay API, database, Lit or secret is involved, so it works if KeyWay is
 * gone. Everything it needs is on chain: the address names the AdminList by its type hash, the AdminList cell
 * holds the list's SMT root, and the transaction that last wrote the list records its members, which rebuild the
 * backup's proof.
 *
 * The node is trusted only for which cells exist (a dead cell just makes the transaction fail): every cell is
 * read from the transaction that created it, after checking that transaction's hash against the cell's out point,
 * so the node can't change a cell's capacity, lock, type or data. The backup signs a readable text naming the
 * destination, the CKB, the token cells and the fee, which the chain rebuilds from the transaction.
 *
 * The flow: `openRescueAccount` (address → list, balance), `rescueEntryForEvm` / `rescueEntryForJoyId` (the
 * connected backup must be on the list), `planRescue` (destination → one unsigned transaction, what it moves and
 * the text the backup will sign), `signRescueWithEvm` / `signRescueWithJoyId` (one signature), `sendRescue`.
 */
export type RescueNetwork = "testnet" | "mainnet";

export const RESCUE_NETWORKS: Record<RescueNetwork, { label: string; rpcUrl: string; addressPrefix: string }> = {
  testnet: { label: "CKB testnet", rpcUrl: "https://testnet.ckb.dev/", addressPrefix: "ckt" },
  // Prepared but not yet run against mainnet: KeyWay's recovery is on testnet only so far.
  mainnet: { label: "CKB mainnet", rpcUrl: "https://mainnet.ckb.dev/", addressPrefix: "ckb" },
};

/** A refusal the page shows as it is. */
export class RescueError extends Error {
  constructor(
    readonly code: "network" | "rpc" | "not-keyway" | "recovery-off" | "list-missing" | "not-backup" | "no-wallet" | "destination" | "empty" | "short" | "blocked",
    message: string,
    /** For "blocked": the cell the node blamed, which the page leaves out of the next try. */
    readonly cell?: ccc.OutPoint,
  ) {
    super(message);
    this.name = "RescueError";
  }
}

const FEE_RATE = 1500n;
/** Inputs per rescue; anything beyond moves with a second rescue. */
export const MAX_RESCUE_CELLS = 100;
const OMNILOCK_ARGS_LENGTH = 54;
const ADMIN_MODE = 0x01;
const TYPE_ID_CODE_HASH = "0x00000000000000000000000000000000000000000000000000545950455f4944";

export function rescueClient(network: RescueNetwork, rpcUrl?: string): ccc.Client {
  const url = rpcUrl?.trim() || RESCUE_NETWORKS[network].rpcUrl;
  if (!/^https:\/\/[^\s]+$/.test(url) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/[^\s]*)?$/.test(url)) {
    throw new RescueError("rpc", "The node URL must start with https://");
  }
  return network === "mainnet" ? new ccc.ClientPublicMainnet({ url }) : new ccc.ClientPublicTestnet({ url });
}

/**
 * What a KeyWay address with recovery on says about itself: its Omnilock lock (KeyWay's pinned Omnilock, by data
 * hash), the AdminList's type hash, and the AdminList's owner-only lock, where KeyWay keeps the list.
 */
export type KeyWayAddress = { address: string; lock: ccc.Script; omnilock: OmnilockDeployment; adminListTypeHash: ccc.Hex; adminListLock: ccc.Script };

/** Reads a KeyWay recovery address, refusing anything else with a reason the user can act on. */
export async function parseKeyWayAddress(client: ccc.Client, input: string): Promise<KeyWayAddress> {
  const address = input.trim();
  const prefix = /^(ck[bt])1/.exec(address)?.[1];
  if (!prefix) throw new RescueError("not-keyway", "That isn't a CKB address. KeyWay addresses start with ckt1 on testnet and ckb1 on mainnet");
  if (prefix !== client.addressPrefix) {
    throw new RescueError("network", `That address is on ${prefix === "ckb" ? "CKB mainnet" : "CKB testnet"}. Switch the network above`);
  }
  let lock: ccc.Script;
  try {
    lock = (await ccc.Address.fromString(address, client)).script;
  } catch {
    throw new RescueError("not-keyway", "That address isn't valid. Check it and try again");
  }
  const secp = await client.getKnownScript(ccc.KnownScript.Secp256k1Blake160);
  if (lock.codeHash === secp.codeHash && lock.hashType === secp.hashType) {
    throw new RescueError("recovery-off", "This address doesn't have recovery on. Turning recovery on gives a KeyWay account a new address; enter that one");
  }
  const omnilock = knownOmnilock(lock.codeHash, lock.hashType);
  if (!omnilock || omnilock !== keywayOmnilock(client)) {
    throw new RescueError("not-keyway", "This isn't a KeyWay address. Enter the address your KeyWay account shows, or the one in the email sent when you turned recovery on");
  }
  const args = ccc.bytesFrom(lock.args);
  if (args.length !== OMNILOCK_ARGS_LENGTH || args[0] !== 0x00 || args[21] !== ADMIN_MODE) {
    throw new RescueError("recovery-off", "This address doesn't have a recovery list, so backups can't move its funds");
  }
  const adminListLock = ccc.Script.from({ codeHash: lock.codeHash, hashType: lock.hashType, args: ccc.bytesConcat(args.slice(0, 21), [0x00]) });
  return { address, lock, omnilock, adminListTypeHash: ccc.hexFrom(args.slice(22)), adminListLock };
}

export type RescueToken = { typeHash: ccc.Hex; amount: bigint; amountText: string; cells: number };

/** An account as the chain shows it, ready to rescue. */
export type RescueAccount = KeyWayAddress & {
  /** The live AdminList cell, read from the transaction that created it. It stays where it is. */
  adminList: ccc.Cell;
  entries: RecoveryListEntry[];
  /** Each member's SMT proof against the list's root, by auth. */
  proofs: Record<string, ccc.Hex>;
  /** Plain CKB and token cells a rescue moves, oldest first, each read from the transaction that created it. */
  movable: ccc.Cell[];
  /** CKB in plain cells. */
  ckb: bigint;
  /** CKB held by token cells, which moves with them. */
  tokenCkb: bigint;
  tokens: RescueToken[];
  /** Cells a rescue leaves alone: other contracts' cells (Nervos DAO, NFTs), tokens with extensions, cells with data. */
  other: ccc.Cell[];
  /** Movable cells beyond MAX_RESCUE_CELLS, for a second rescue. */
  later: number;
};

/**
 * Reads a cell from the transaction that created it, checking that transaction's hash, so what the page builds
 * on is what the chain holds at that out point, whatever the node says about the cell itself.
 */
export async function verifiedCell(client: ccc.Client, outPoint: ccc.OutPointLike, transactions = new Map<string, ccc.Transaction>()): Promise<ccc.Cell> {
  const { txHash, index } = ccc.OutPoint.from(outPoint);
  let transaction = transactions.get(txHash);
  if (!transaction) {
    const found = await client.getTransaction(txHash);
    if (!found || found.transaction.hash() !== txHash) throw new RescueError("rpc", `The CKB node returned a transaction that doesn't match ${txHash.slice(0, 12)}…, so its cells can't be trusted. Try another node`);
    transaction = found.transaction;
    transactions.set(txHash, transaction);
  }
  const cellOutput = transaction.outputs[Number(index)];
  if (!cellOutput) throw new RescueError("rpc", "The CKB node listed a cell that doesn't exist. Try another node");
  return ccc.Cell.from({ outPoint: { txHash, index }, cellOutput, outputData: transaction.outputsData[Number(index)] ?? "0x" });
}

/**
 * Finds the account's AdminList by the type hash its address names, under the list's owner-only lock (where
 * KeyWay keeps it), rebuilds the backup list from chain data (refusing a record that doesn't hash to the cell's
 * root) and reads the balance. Every cell comes from its creating transaction, checked by hash.
 */
export async function openRescueAccount(client: ccc.Client, input: string, exclude: ccc.OutPoint[] = []): Promise<RescueAccount> {
  const account = await parseKeyWayAddress(client, input);
  const [xudt, sudt] = await Promise.all([client.getKnownScript(ccc.KnownScript.XUdt), client.getKnownScript(ccc.KnownScript.SUdt)]);
  const transactions = new Map<string, ccc.Transaction>();
  const isList = (cell: ccc.Cell) => {
    const type = cell.cellOutput.type;
    return Boolean(type && type.codeHash === TYPE_ID_CODE_HASH && type.hashType === "type" && type.hash() === account.adminListTypeHash);
  };
  const cells: ccc.Cell[] = [];
  let adminListOutPoint: ccc.OutPoint | undefined;
  try {
    for await (const listed of client.findCellsByLock(account.adminListLock, undefined, true)) {
      const cell = await verifiedCell(client, listed.outPoint, transactions);
      if (cell.cellOutput.lock.eq(account.adminListLock) && isList(cell)) adminListOutPoint = cell.outPoint;
    }
    for await (const listed of client.findCellsByLock(account.lock, undefined, true)) {
      if (exclude.some((outPoint) => outPoint.eq(listed.outPoint))) continue;
      const cell = await verifiedCell(client, listed.outPoint, transactions);
      // A cell the node lists under the account but the chain locks otherwise isn't the account's.
      if (!cell.cellOutput.lock.eq(account.lock)) continue;
      if (isList(cell)) adminListOutPoint ??= cell.outPoint;
      else cells.push(cell);
    }
  } catch (error) {
    if (error instanceof RescueError) throw error;
    throw new RescueError("rpc", `The CKB node didn't answer: ${error instanceof Error ? error.message.slice(0, 120) : "unknown error"}`);
  }
  if (!adminListOutPoint) {
    throw new RescueError("list-missing", "This address's recovery list isn't on chain. Without it no backup can move the funds");
  }
  let list;
  try {
    list = await recoveryListFrom(client, adminListOutPoint);
  } catch (error) {
    throw new RescueError("list-missing", `The recovery list couldn't be read from the chain: ${error instanceof Error ? error.message : "unknown error"}`);
  }
  cells.sort((a, b) => outPointKey(a).localeCompare(outPointKey(b)));
  const kinds = cells.map((cell) => rescueCellKind(cell, xudt, sudt));
  const allMovable = cells.filter((_, index) => kinds[index] !== "other");
  const movable = allMovable.slice(0, MAX_RESCUE_CELLS);
  const tokens = new Map<ccc.Hex, RescueToken>();
  for (const cell of movable) {
    if (!cell.cellOutput.type) continue;
    const typeHash = cell.cellOutput.type.hash();
    const token = tokens.get(typeHash) ?? { typeHash, amount: 0n, amountText: "", cells: 0 };
    token.amount += ccc.numLeFromBytes(ccc.bytesFrom(cell.outputData).slice(0, 16));
    token.cells += 1;
    token.amountText = formatAsset(token.amount, typeHash);
    tokens.set(typeHash, token);
  }
  const sum = (list: ccc.Cell[]) => list.reduce((total, cell) => total + cell.cellOutput.capacity, 0n);
  return {
    ...account,
    adminList: list.cell,
    entries: list.entries,
    proofs: list.proofs,
    movable,
    ckb: sum(movable.filter((cell) => !cell.cellOutput.type)),
    tokenCkb: sum(movable.filter((cell) => cell.cellOutput.type)),
    tokens: [...tokens.values()],
    other: cells.filter((_, index) => kinds[index] === "other"),
    later: allMovable.length - movable.length,
  };
}

/**
 * Plain CKB, a standard token (xUDT without extension flags, sUDT, or xUDT-compatible such as RUSD) with its
 * amount, or anything else.
 */
export function rescueCellKind(cell: { cellOutput: ccc.CellOutput; outputData: ccc.Hex }, xudt: ccc.ScriptInfo, sudt: ccc.ScriptInfo): "plain" | "token" | "other" {
  const type = cell.cellOutput.type;
  if (!type) return cell.outputData === "0x" ? "plain" : "other";
  const matches = (known: ccc.ScriptInfo) => type.codeHash === known.codeHash && type.hashType === known.hashType;
  return (matches(xudt) || matches(sudt) || isXudtCompatible(type)) && hasPlainTokenArgs(type) && ccc.bytesFrom(cell.outputData).length >= 16 ? "token" : "other";
}

/** The list entry for an EVM wallet's accounts, or a refusal naming the backups that are on the list. */
export function rescueEntryForEvm(account: Pick<RescueAccount, "entries">, addresses: string[]): RecoveryListEntry {
  const wanted = new Set(addresses.map((address) => normalizeEvmAddress(address)));
  const entry = account.entries.find(({ backup }) => backup.kind === "evm" && wanted.has(normalizeEvmAddress(backup.address)));
  if (!entry) throw notBackup(account, addresses.length === 1 ? `EVM wallet ${addresses[0]}` : "None of this EVM wallet's accounts");
  return entry;
}

/** The list entry for a JoyID address, or a refusal. */
export function rescueEntryForJoyId(account: Pick<RescueAccount, "entries">, address: string): RecoveryListEntry {
  const entry = account.entries.find(({ backup }) => backup.kind === "joyid" && backup.address === address);
  if (!entry) throw notBackup(account, `JoyID ${address}`);
  return entry;
}

function notBackup(account: Pick<RescueAccount, "entries">, who: string): RescueError {
  const listed = account.entries.map(({ backup }) => describeBackup(backup)).join(", ");
  return new RescueError("not-backup", `${who} isn't a backup of this account. Its backups are: ${listed}`);
}

/** Asks an EIP-1193 wallet for its accounts and returns the one on the list. */
export async function connectEvmBackup(account: Pick<RescueAccount, "entries">, ethereum: EthereumProvider | undefined): Promise<RecoveryListEntry> {
  if (!ethereum) throw new RescueError("no-wallet", "No EVM wallet found in this browser. Open this page in a browser with your EVM wallet, or in the wallet's own browser");
  const accounts = await ethereum.request({ method: "eth_requestAccounts" });
  if (!Array.isArray(accounts) || accounts.length === 0 || accounts.some((value) => typeof value !== "string")) {
    throw new RescueError("no-wallet", "The EVM wallet didn't share an account");
  }
  return rescueEntryForEvm(account, accounts as string[]);
}

/** The one transaction a rescue sends, what it moves, and the text the backup signs. */
export type RescuePlan = {
  transaction: ccc.Transaction;
  entry: RecoveryListEntry;
  destination: string;
  /** What the backup's wallet shows and signs; the chain rebuilds it from the transaction. */
  approvalText: string;
  /** Plain CKB that arrives at the destination. */
  ckb: bigint;
  /** Token cells that arrive at the destination, with the CKB each holds. */
  tokens: Array<RescueToken & { capacity: bigint }>;
  fee: bigint;
};

/**
 * Builds the rescue: every movable cell (up to MAX_RESCUE_CELLS) to `destination`. Token cells move one to one
 * with their data, each at exactly the capacity it needs at the destination's lock; the rest of the CKB, less
 * the fee, goes into one plain cell. When that would be smaller than a plain cell can be, it joins the first
 * token cell instead. The AdminList is only a cell dep and stays where it is. The fee is sized with the
 * backup's witness at its final length, so the backup signs once.
 */
export async function planRescue(client: ccc.Client, account: RescueAccount, entry: RecoveryListEntry, destinationInput: string): Promise<RescuePlan> {
  const destination = destinationInput.trim();
  const prefix = /^(ck[bt])1/.exec(destination)?.[1];
  if (!prefix) throw new RescueError("destination", "Enter the CKB address to send everything to");
  if (prefix !== client.addressPrefix) throw new RescueError("destination", `That address is on ${prefix === "ckb" ? "CKB mainnet" : "CKB testnet"}, not ${client.addressPrefix === "ckb" ? "CKB mainnet" : "CKB testnet"}`);
  let lock: ccc.Script;
  try {
    lock = (await ccc.Address.fromString(destination, client)).script;
  } catch {
    throw new RescueError("destination", "That destination address isn't valid");
  }
  if (lock.eq(account.lock)) throw new RescueError("destination", "That's this KeyWay address. Send to an address you control with another wallet");
  await checkDestinationLock(client, lock);
  if (account.movable.length === 0) throw new RescueError("empty", "There's nothing to move from this address");
  if (!account.entries.includes(entry)) throw new RescueError("not-backup", "This backup isn't on the account's recovery list");

  const tokenCells = account.movable.filter((cell) => cell.cellOutput.type);
  const attempt = async (withPlain: boolean) => {
    const tokenOutputs = tokenCells.map((cell) => {
      const output = ccc.CellOutput.from({ lock, type: cell.cellOutput.type, capacity: 0n });
      output.capacity = occupied(output, cell.outputData);
      return output;
    });
    const plain = withPlain ? [ccc.CellOutput.from({ lock, capacity: 0n })] : [];
    const transaction = ccc.Transaction.from({
      inputs: account.movable.map((cell) => ({ previousOutput: cell.outPoint })),
      outputs: [...tokenOutputs, ...plain],
      outputsData: [...tokenCells.map((cell) => cell.outputData), ...plain.map(() => "0x")],
    });
    await addRescueTokenCellDeps(client, transaction, tokenCells);
    // The deps and the zeroed admin witness at its final length; the fee covers the signed size.
    const prepared = await prepareRecoveryWitness(transaction, rescueSpend(client, account, entry));
    transaction.cellDeps = prepared.cellDeps;
    transaction.witnesses = prepared.witnesses;
    const fee = (BigInt(transaction.toBytes().length + 4) * FEE_RATE + 999n) / 1000n;
    const tokenCapacity = tokenOutputs.reduce((total, output) => total + output.capacity, 0n);
    const spare = account.ckb + account.tokenCkb - tokenCapacity - fee;
    return { transaction, spare, fee };
  };

  const minimumPlain = occupied(ccc.CellOutput.from({ lock, capacity: 0n }), "0x");
  let built = await attempt(true);
  if (built.spare >= minimumPlain) {
    built.transaction.outputs[built.transaction.outputs.length - 1].capacity = built.spare;
  } else {
    if (tokenCells.length === 0) throw short(minimumPlain - built.spare);
    const tokensOnly = await attempt(false);
    if (tokensOnly.spare < 0n) throw short(-tokensOnly.spare);
    tokensOnly.transaction.outputs[0].capacity += tokensOnly.spare;
    built = tokensOnly;
  }
  const { transaction, fee } = built;
  const tokens = tokenCells.map((cell, index) => {
    const typeHash = cell.cellOutput.type!.hash();
    const amount = ccc.numLeFromBytes(ccc.bytesFrom(cell.outputData).slice(0, 16));
    return { typeHash, amount, amountText: formatAsset(amount, typeHash), cells: 1, capacity: transaction.outputs[index].capacity };
  });
  const ckb = transaction.outputs.length > tokenCells.length ? transaction.outputs[transaction.outputs.length - 1].capacity : 0n;
  checkRescueTransaction(transaction, account, lock);
  const { text } = await prepareRecoverySpend(transaction, rescueSpend(client, account, entry));
  return { transaction, entry, destination, approvalText: text, ckb, tokens, fee };
}

/**
 * Funds sent to a lock whose code isn't deployed are lost for good, and the page can't look a script up by its
 * hash, so it only sends to locks it knows: the network's standard locks and KeyWay's Omnilock.
 */
async function checkDestinationLock(client: ccc.Client, lock: ccc.Script): Promise<void> {
  const known = [
    ccc.KnownScript.Secp256k1Blake160, ccc.KnownScript.Secp256k1Multisig, ccc.KnownScript.Secp256k1MultisigV2, ccc.KnownScript.AnyoneCanPay,
    ccc.KnownScript.JoyId, ccc.KnownScript.OmniLock, ccc.KnownScript.PWLock, ccc.KnownScript.NostrLock,
  ];
  for (const name of known) {
    const script = await client.getKnownScript(name).catch(() => undefined);
    if (script && script.codeHash === lock.codeHash && script.hashType === lock.hashType) return;
  }
  if (knownOmnilock(lock.codeHash, lock.hashType) === keywayOmnilock(client)) return;
  throw new RescueError("destination", "This address uses a lock this page doesn't recognise, so it can't check that the funds could be spent from there. Send to a standard CKB address, such as one from another wallet");
}

function short(by: bigint): RescueError {
  return new RescueError("short", `There isn't enough CKB to pay the network fee and hold the moved cells. ${ccc.fixedPointToString(by)} CKB more is needed at this address`);
}

const occupied = (output: ccc.CellOutput, data: ccc.HexLike) => ccc.fixedPointFrom(output.occupiedSize + ccc.bytesFrom(data).length);

async function addRescueTokenCellDeps(client: ccc.Client, transaction: ccc.Transaction, tokenCells: ccc.Cell[]): Promise<void> {
  if (tokenCells.length === 0) return;
  const sudt = await client.getKnownScript(ccc.KnownScript.SUdt);
  const isSudt = (cell: ccc.Cell) => cell.cellOutput.type!.codeHash === sudt.codeHash && cell.cellOutput.type!.hashType === sudt.hashType;
  await addTokenCellDeps(client, transaction, tokenCells.filter((cell) => !isSudt(cell)));
  if (tokenCells.some(isSudt)) await transaction.addCellDepsOfKnownScripts(client, ccc.KnownScript.SUdt);
}

/** The backup's spend over the account's movable cells, whose capacities were checked against their creating transactions. */
function rescueSpend(client: ccc.Client, account: RescueAccount, entry: RecoveryListEntry): RecoverySpend {
  return { client, lock: account.lock, omnilock: account.omnilock, list: account.entries, entry, adminList: account.adminList.outPoint, inputCapacity: account.ckb + account.tokenCkb };
}

/**
 * The rescue's own shape, checked after building: every input is a movable cell of this account (as read from
 * its creating transaction) and never the AdminList, every output goes to the destination, tokens move one to
 * one with their data, the fee (verified inputs less outputs) is small.
 */
export function checkRescueTransaction(transaction: ccc.Transaction, account: RescueAccount, destination: ccc.Script): void {
  const refuse = (reason: string) => { throw new Error(`The rescue transaction is wrong: ${reason}`); };
  const movable = new Map(account.movable.map((cell) => [outPointKey(cell), cell]));
  const inputs = transaction.inputs.map(({ previousOutput }) => movable.get(`${previousOutput.txHash}:${previousOutput.index.toString().padStart(10, "0")}`));
  if (inputs.some((cell) => !cell)) refuse("an input isn't one of the account's movable cells");
  if (transaction.inputs.some(({ previousOutput }) => previousOutput.eq(account.adminList.outPoint))) refuse("it spends the recovery list");
  if (inputs.some((cell) => cell!.cellOutput.type?.hash() === account.adminListTypeHash)) refuse("it spends the recovery list");
  if (transaction.outputs.some((output) => !output.lock.eq(destination))) refuse("an output goes somewhere else");
  const tokenKeys = (cells: Array<{ type?: ccc.Script; data: ccc.HexLike }>) =>
    cells.filter(({ type }) => type).map(({ type, data }) => `${type!.hash()}:${ccc.hexFrom(data)}`).sort();
  const fromInputs = tokenKeys(inputs.map((cell) => ({ type: cell!.cellOutput.type, data: cell!.outputData })));
  const toOutputs = tokenKeys(transaction.outputs.map((output, index) => ({ type: output.type, data: transaction.outputsData[index] ?? "0x" })));
  if (JSON.stringify(fromInputs) !== JSON.stringify(toOutputs)) refuse("tokens don't move one to one");
  if (transaction.outputs.filter((output) => !output.type).length > 1) refuse("more than one plain output");
  const fee = inputs.reduce((total, cell) => total + cell!.cellOutput.capacity, 0n) - transaction.getOutputsCapacity();
  if (fee <= 0n || fee > BigInt(transaction.toBytes().length + 4) * 10n) refuse("the fee is outside the limit");
}

/** Signs the rescue once with an EVM backup: its wallet shows the plan's approval text. */
export async function signRescueWithEvm(client: ccc.Client, account: RescueAccount, plan: RescuePlan, ethereum: EthereumProvider): Promise<ccc.Transaction> {
  if (plan.entry.backup.kind !== "evm") throw new RescueError("not-backup", "This backup isn't an EVM wallet");
  const signed = await signRecoverySpendWithEvm(plan.transaction, rescueSpend(client, account, plan.entry), ethereum);
  return sameRescue(signed, plan);
}

/** Signs the rescue once with a JoyID backup through CCC's JoyID signer. */
export async function signRescueWithJoyId(client: ccc.Client, account: RescueAccount, plan: RescuePlan, signer: ccc.Signer): Promise<ccc.Transaction> {
  if (plan.entry.backup.kind !== "joyid") throw new RescueError("not-backup", "This backup isn't a JoyID passkey");
  const signed = await signRecoverySpendWithJoyId(plan.transaction, rescueSpend(client, account, plan.entry), signer);
  return sameRescue(signed, plan);
}

/** Signing only fills the witness (the hash leaves witnesses out): what the user reviewed is what was signed. */
function sameRescue(signed: ccc.Transaction, plan: RescuePlan): ccc.Transaction {
  if (signed.hash() !== plan.transaction.hash()) throw new Error("The signed transaction differs from the one reviewed");
  return signed;
}

/**
 * The input a node's verification error blames on its type script, such as a token cell that needs an extension
 * script, so the page can leave it out and build the rescue again.
 */
export function blamedInput(transaction: ccc.Transaction, message: string): ccc.OutPoint | undefined {
  const match = /Inputs\[(\d+)\]\.Type/i.exec(message);
  const input = match ? transaction.inputs[Number(match[1])] : undefined;
  return input?.previousOutput;
}

/**
 * Checks the transaction with the node first, so a refusal comes back as a message instead of a lost transaction.
 * When the node blames one input's type script, the refusal names that cell so the page can try without it.
 */
export async function sendRescue(client: ccc.Client, transaction: ccc.Transaction): Promise<ccc.Hex> {
  try {
    await client.sendTransactionDry(transaction, "passthrough");
  } catch (error) {
    const text = error instanceof Error ? error.message : String(error);
    const cell = blamedInput(transaction, text);
    if (cell) throw new RescueError("blocked", "One token cell at this address can't be moved by this page. It has been left out; review the rescue and sign again", cell);
    // Some public nodes don't offer the dry run; the real send still checks everything.
    if (!/method not found|-32601/i.test(text)) throw new Error(`The CKB node refused the rescue: ${text.slice(0, 240)}`);
  }
  return client.sendTransaction(transaction, "passthrough");
}

function outPointKey(cell: ccc.Cell): string {
  return `${cell.outPoint.txHash}:${cell.outPoint.index.toString().padStart(10, "0")}`;
}

import * as ccc from "@ckb-ccc/core";

/**
 * CKB sparse Merkle tree for Omnilock whitelists, a port of nervosnetwork/sparse-merkle-tree 0.6.1 (without the
 * "trie" feature) with blake2b-256 personalised "ckb-default-hash". Each member's key is its 21-byte Omnilock
 * auth followed by 11 zero bytes, and its value is 0x01 followed by 31 zero bytes. Proofs use the crate's
 * compiled format, which Omnilock checks on chain.
 */

type H256 = Uint8Array;
type MergeValue =
  | { kind: "value"; value: H256 }
  | { kind: "zeros"; baseNode: H256; zeroBits: H256; zeroCount: number };
type Branch = { left: MergeValue; right: MergeValue };

const MERGE_NORMAL = 1;
const MERGE_ZEROS = 2;
const ZERO = new Uint8Array(32);
/** The whitelist value every member's key maps to. */
export const SMT_MEMBER_VALUE: ccc.Hex = ccc.hexFrom(ccc.bytesConcat([0x01], new Uint8Array(31)));

const getBit = (key: H256, i: number) => ((key[i >> 3] >> (i & 7)) & 1) === 1;
const isZero = (key: H256) => key.every((byte) => byte === 0);
const hex = (key: H256) => ccc.hexFrom(key);

function setBit(key: H256, i: number): H256 {
  const out = key.slice();
  out[i >> 3] |= 1 << (i & 7);
  return out;
}

function parentPath(key: H256, height: number): H256 {
  if (height === 255) return new Uint8Array(32);
  const start = height + 1;
  const out = new Uint8Array(32);
  const startByte = start >> 3;
  out.set(key.slice(startByte), startByte);
  if (start & 7) out[startByte] &= (0xff << (start & 7)) & 0xff;
  return out;
}

/** Keys order from bit 255 down, i.e. by their bytes read last to first. */
function compareKeys(a: H256, b: H256): number {
  for (let i = 31; i >= 0; i -= 1) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

function forkHeight(a: H256, b: H256): number {
  for (let h = 255; h >= 0; h -= 1) if (getBit(a, h) !== getBit(b, h)) return h;
  return 0;
}

function hash(...parts: Array<number | H256>): H256 {
  const hasher = new ccc.HasherCkb();
  for (const part of parts) hasher.update(typeof part === "number" ? [part] : part);
  return ccc.bytesFrom(hasher.digest());
}

const zeroValue = (): MergeValue => ({ kind: "value", value: new Uint8Array(32) });
const mergeValueIsZero = (value: MergeValue) => value.kind === "value" && isZero(value.value);

function mergeValueHash(value: MergeValue): H256 {
  return value.kind === "value" ? value.value : hash(MERGE_ZEROS, value.baseNode, value.zeroBits, value.zeroCount);
}

function mergeWithZero(height: number, nodeKey: H256, value: MergeValue, setRight: boolean): MergeValue {
  if (value.kind === "value") {
    return { kind: "zeros", baseNode: hash(height, nodeKey, value.value), zeroBits: setRight ? setBit(ZERO, height) : new Uint8Array(32), zeroCount: 1 };
  }
  return { ...value, zeroBits: setRight ? setBit(value.zeroBits, height) : value.zeroBits, zeroCount: (value.zeroCount + 1) & 0xff };
}

function merge(height: number, nodeKey: H256, lhs: MergeValue, rhs: MergeValue): MergeValue {
  if (mergeValueIsZero(lhs) && mergeValueIsZero(rhs)) return zeroValue();
  if (mergeValueIsZero(lhs)) return mergeWithZero(height, nodeKey, rhs, true);
  if (mergeValueIsZero(rhs)) return mergeWithZero(height, nodeKey, lhs, false);
  return { kind: "value", value: hash(MERGE_NORMAL, height, nodeKey, mergeValueHash(lhs), mergeValueHash(rhs)) };
}

function h256(value: ccc.HexLike, what: string): H256 {
  const bytes = ccc.bytesFrom(value);
  if (bytes.length !== 32) throw new Error(`${what} must be 32 bytes`);
  return bytes;
}

export class CkbSmt {
  private readonly branches = new Map<string, Branch>();
  private readonly leaves = new Map<string, H256>();
  private rootHash: H256 = new Uint8Array(32);

  get root(): ccc.Hex {
    return hex(this.rootHash);
  }

  /** Sets a key's value; a zero value removes it. */
  update(keyLike: ccc.HexLike, valueLike: ccc.HexLike = SMT_MEMBER_VALUE): ccc.Hex {
    const key = h256(keyLike, "An SMT key");
    const value = h256(valueLike, "An SMT value");
    if (isZero(value)) this.leaves.delete(hex(key)); else this.leaves.set(hex(key), value);
    let currentKey = key;
    let currentNode: MergeValue = { kind: "value", value };
    for (let height = 0; height <= 255; height += 1) {
      const parentKey = parentPath(currentKey, height);
      const branchKey = `${height}:${hex(parentKey)}`;
      const branch = this.branches.get(branchKey);
      const right = getBit(currentKey, height);
      const [left, rightNode] = branch
        ? right ? [branch.left, currentNode] : [currentNode, branch.right]
        : right ? [zeroValue(), currentNode] : [currentNode, zeroValue()];
      if (!mergeValueIsZero(left) || !mergeValueIsZero(rightNode)) this.branches.set(branchKey, { left, right: rightNode });
      else this.branches.delete(branchKey);
      currentKey = parentKey;
      currentNode = merge(height, parentKey, left, rightNode);
    }
    this.rootHash = mergeValueHash(currentNode);
    return this.root;
  }

  /** The compiled Merkle proof for some of the tree's keys. */
  proof(keyLikes: ccc.HexLike[]): ccc.Hex {
    if (keyLikes.length === 0) throw new Error("An SMT proof needs at least one key");
    const keys = keyLikes.map((key) => h256(key, "An SMT key")).sort(compareKeys);
    const bitmaps = keys.map((key) => {
      const bits = new Array<boolean>(256).fill(false);
      for (let height = 0; height <= 255; height += 1) {
        const branch = this.branches.get(`${height}:${hex(parentPath(key, height))}`);
        if (branch && !mergeValueIsZero(getBit(key, height) ? branch.left : branch.right)) bits[height] = true;
      }
      return bits;
    });
    const out: number[] = [];
    const stack: number[] = [];
    keys.forEach((key, index) => {
      const last = index + 1 === keys.length;
      const fork = last ? 255 : forkHeight(key, keys[index + 1]);
      out.push(0x4c);
      let zeros = 0;
      const flushZeros = () => {
        if (zeros > 0) out.push(0x4f, zeros === 256 ? 0 : zeros);
        zeros = 0;
      };
      for (let height = 0; height <= fork; height += 1) {
        if (height === fork && !last) break;
        if (stack.length > 0 && stack[stack.length - 1] === height) {
          stack.pop();
          flushZeros();
          out.push(0x48);
        } else if (bitmaps[index][height]) {
          const branch = this.branches.get(`${height}:${hex(parentPath(key, height))}`)!;
          const sibling = getBit(key, height) ? branch.left : branch.right;
          flushZeros();
          if (sibling.kind === "value") out.push(0x50, ...sibling.value);
          else out.push(0x51, sibling.zeroCount, ...sibling.baseNode, ...sibling.zeroBits);
        } else {
          zeros += 1;
        }
      }
      flushZeros();
      stack.push(fork);
    });
    if (stack.length !== 1) throw new Error("SMT proof is corrupted");
    return ccc.hexFrom(Uint8Array.from(out));
  }
}

/** The root a compiled proof gives for these leaves, as Omnilock computes it on chain. */
export function smtProofRoot(proofLike: ccc.HexLike, leavesLike: Array<{ key: ccc.HexLike; value?: ccc.HexLike }>): ccc.Hex {
  const proof = ccc.bytesFrom(proofLike);
  const leaves = leavesLike.map(({ key, value }) => ({ key: h256(key, "An SMT key"), value: h256(value ?? SMT_MEMBER_VALUE, "An SMT value") }))
    .sort((a, b) => compareKeys(a.key, b.key));
  const corrupted = () => new Error("SMT proof is corrupted");
  const stack: Array<{ height: number; key: H256; value: MergeValue }> = [];
  let leafIndex = 0;
  let i = 0;
  const climb = (sibling: MergeValue) => {
    const top = stack.pop();
    if (!top || top.height > 255) throw corrupted();
    const parentKey = parentPath(top.key, top.height);
    const value = getBit(top.key, top.height) ? merge(top.height, parentKey, sibling, top.value) : merge(top.height, parentKey, top.value, sibling);
    stack.push({ height: top.height + 1, key: parentKey, value });
  };
  while (i < proof.length) {
    const code = proof[i++];
    if (code === 0x4c) {
      const leaf = leaves[leafIndex++];
      if (!leaf) throw corrupted();
      stack.push({ height: 0, key: leaf.key, value: { kind: "value", value: leaf.value } });
    } else if (code === 0x50) {
      if (i + 32 > proof.length) throw corrupted();
      climb({ kind: "value", value: proof.slice(i, i + 32) });
      i += 32;
    } else if (code === 0x51) {
      if (i + 65 > proof.length) throw corrupted();
      climb({ kind: "zeros", zeroCount: proof[i], baseNode: proof.slice(i + 1, i + 33), zeroBits: proof.slice(i + 33, i + 65) });
      i += 65;
    } else if (code === 0x48) {
      const b = stack.pop();
      const a = stack.pop();
      if (!a || !b || a.height !== b.height || a.height > 255) throw corrupted();
      const parentKey = parentPath(a.key, a.height);
      if (hex(parentKey) !== hex(parentPath(b.key, b.height))) throw corrupted();
      const value = getBit(a.key, a.height) ? merge(a.height, parentKey, b.value, a.value) : merge(a.height, parentKey, a.value, b.value);
      stack.push({ height: a.height + 1, key: parentKey, value });
    } else if (code === 0x4f) {
      if (i >= proof.length) throw corrupted();
      const n = proof[i++];
      const top = stack.pop();
      if (!top) throw corrupted();
      let { height, key, value } = top;
      for (let step = 0; step < (n === 0 ? 256 : n); step += 1) {
        if (height > 255) throw corrupted();
        key = parentPath(key, height);
        value = getBit(top.key, height) ? merge(height, key, zeroValue(), value) : merge(height, key, value, zeroValue());
        height += 1;
      }
      stack.push({ height, key, value });
    } else {
      throw corrupted();
    }
  }
  if (stack.length !== 1 || stack[0].height !== 256 || leafIndex !== leaves.length) throw corrupted();
  return hex(mergeValueHash(stack[0].value));
}

/** SMT key of an Omnilock auth: the 21 bytes followed by 11 zero bytes. */
export function smtKeyOfAuth(auth: ccc.HexLike): ccc.Hex {
  const bytes = ccc.bytesFrom(auth);
  if (bytes.length !== 21) throw new Error("An Omnilock auth must be 21 bytes");
  return ccc.hexFrom(ccc.bytesConcat(bytes, new Uint8Array(11)));
}

/** The whitelist root and each member's compiled proof (proof mask 3, one rule). */
export function whitelistTree(auths: ccc.HexLike[]): { root: ccc.Hex; proofs: Record<string, ccc.Hex> } {
  if (auths.length === 0) throw new Error("A recovery list needs at least one backup");
  const tree = new CkbSmt();
  const keys = auths.map(smtKeyOfAuth);
  if (new Set(keys).size !== keys.length) throw new Error("A backup is listed twice");
  for (const key of keys) tree.update(key);
  return { root: tree.root, proofs: Object.fromEntries(auths.map((auth, index) => [ccc.hexFrom(auth), tree.proof([keys[index]])])) };
}

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { CkbSmt, smtKeyOfAuth, smtProofRoot, whitelistTree } from "../src/sdk/browser/recovery-smt.ts";

type Vector = { name: string; keys: string[]; root: string; proofs: Record<string, string> };
const { vectors } = JSON.parse(await readFile(new URL("./fixtures/recovery-smt-vectors.json", import.meta.url), "utf8")) as { vectors: Vector[] };

// Roots of the AdminList cells the testnet spike created (research/omnilock/spike/state.json).
const SPIKE_ROOT_B1 = "0x0c88ee78ec4fa257f90022c7a770030bf58e4e97973921c2f2372b5029fc4486";
const SPIKE_ROOT_B1_B2 = "0x0f299f4a8f333225116cbf1688f9a609c2139f31019bd0c5e7fce76abee1aa11";
const B1 = "0x0079af2d8dbb19362ec15a4acc3c026c2386e0ffa2";
const B2 = "0x0024d1845cc38d23f3927fa692bce5dc646623def3";

test("matches the Rust sparse-merkle-tree roots and compiled proofs", () => {
  assert.ok(vectors.length >= 5);
  for (const vector of vectors) {
    const tree = new CkbSmt();
    for (const key of vector.keys) tree.update(key);
    assert.equal(tree.root, vector.root, vector.name);
    for (const key of vector.keys) {
      assert.equal(tree.proof([key]), vector.proofs[key], `${vector.name} proof`);
      assert.equal(smtProofRoot(vector.proofs[key], [{ key }]), vector.root, `${vector.name} verify`);
    }
  }
});

test("reproduces the spike's on-chain AdminList roots and B2's on-chain proof", () => {
  assert.equal(whitelistTree([B1]).root, SPIKE_ROOT_B1);
  const both = whitelistTree([B1, B2]);
  assert.equal(both.root, SPIKE_ROOT_B1_B2);
  assert.equal(whitelistTree([B2, B1]).root, SPIKE_ROOT_B1_B2, "member order doesn't matter");
  // The proofs B1 and B2 used in their admin-path spends, read from those transactions' witnesses.
  assert.equal(whitelistTree([B1]).proofs[B1], "0x4c4f00");
  assert.equal(both.proofs[B2], "0x4c4fa651a61ce2ff83b202a6191d6472b0ddb8bf1bd4adfdf1ff273a8ea8025bcaaab91d060079af2d8dbb19362ec15a4acc3c026c2386e0ff2200000000000000000000004f59");
});

test("proofs fail against another root or for a key that isn't a member", () => {
  const { proofs } = whitelistTree([B1, B2]);
  assert.notEqual(smtProofRoot(whitelistTree([B1]).proofs[B1], [{ key: smtKeyOfAuth(B1) }]), SPIKE_ROOT_B1_B2);
  assert.notEqual(smtProofRoot(proofs[B1], [{ key: smtKeyOfAuth(B2) }]), SPIKE_ROOT_B1_B2);
  assert.throws(() => smtProofRoot("0x4c4f", [{ key: smtKeyOfAuth(B1) }]), /corrupted/);
});

test("multi-key proofs, removal and input checks", () => {
  const vector = vectors.find(({ keys }) => keys.length > 2)!;
  const tree = new CkbSmt();
  for (const key of vector.keys) tree.update(key);
  assert.equal(smtProofRoot(tree.proof(vector.keys.slice(0, 3)), vector.keys.slice(0, 3).map((key) => ({ key }))), vector.root);
  const extra = `0x01${"ab".repeat(20)}${"00".repeat(11)}`;
  tree.update(extra);
  assert.notEqual(tree.root, vector.root);
  tree.update(extra, `0x${"00".repeat(32)}`);
  assert.equal(tree.root, vector.root, "removing a key restores the root");
  assert.throws(() => whitelistTree([]), /at least one/);
  assert.throws(() => whitelistTree([B1, B1]), /twice/);
  assert.throws(() => smtKeyOfAuth("0x00"), /21 bytes/);
});

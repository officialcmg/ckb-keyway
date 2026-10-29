// Reference CKB-SMT helper (sparse-merkle-tree 0.6.1 + blake2b "ckb-default-hash").
// Usage: smt-ref <key32hex> [<key32hex> ...]
// Each key gets value [1, 0 x 31] (Omnilock whitelist). Prints JSON with the root
// and, for each key, the compiled single-key proof.
use blake2b_rs::{Blake2b, Blake2bBuilder};
use sparse_merkle_tree::{default_store::DefaultStore, traits::Hasher, SparseMerkleTree, H256};

pub struct CkbHasher(Blake2b);
impl Default for CkbHasher {
    fn default() -> Self {
        CkbHasher(Blake2bBuilder::new(32).personal(b"ckb-default-hash").build())
    }
}
impl Hasher for CkbHasher {
    fn write_h256(&mut self, h: &H256) { self.0.update(h.as_slice()); }
    fn write_byte(&mut self, b: u8) { self.0.update(&[b][..]); }
    fn finish(self) -> H256 { let mut o = [0u8; 32]; self.0.finalize(&mut o); o.into() }
}
type Smt = SparseMerkleTree<CkbHasher, H256, DefaultStore<H256>>;

fn h(s: &str) -> H256 {
    let v = hex::decode(s.trim_start_matches("0x")).expect("hex");
    let mut a = [0u8; 32]; a.copy_from_slice(&v); a.into()
}

fn main() {
    let keys: Vec<H256> = std::env::args().skip(1).map(|s| h(&s)).collect();
    let mut one = [0u8; 32]; one[0] = 1; let one: H256 = one.into();
    let mut tree = Smt::default();
    for k in &keys { tree.update(*k, one).unwrap(); }
    let root = *tree.root();
    let mut out = format!("{{\"root\":\"0x{}\",\"proofs\":{{", hex::encode(root.as_slice()));
    for (i, k) in keys.iter().enumerate() {
        let p = tree.merkle_proof(vec![*k]).unwrap().compile(vec![*k]).unwrap();
        assert!(p.verify::<CkbHasher>(&root, vec![(*k, one)]).unwrap());
        if i > 0 { out.push(','); }
        out.push_str(&format!("\"0x{}\":\"0x{}\"", hex::encode(k.as_slice()), hex::encode(&p.0)));
    }
    out.push_str("}}");
    println!("{}", out);
}

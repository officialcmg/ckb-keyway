//! Audit (audit/omnilock-fable-5-1): host-side checks of the verifier library against the TypeScript rules.
//! `cargo test --release --test audit_fable51_parity` needs no ckb-debugger.
//!
//! 1. clientDataJSON parity: the cases in tests/fixtures/audit-fable51-clientdata-cases.json (written by
//!    tests/audit-fable51-clientdata-parity.test.ts) must get the same verdict from `check_client_data`.
//! 2. Robustness: random mutations of a valid signature blob never panic in `verify` (a panic would abort the
//!    VM, which fails the lock safely, but a parser that panics is a parser that was not reasoned about).

use base64::{engine::general_purpose::STANDARD, Engine};
use joyid_webauthn::{base64url, challenge_text, check_client_data, verify, Error, CHALLENGE_TEXT};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(serde::Deserialize)]
struct Fixture {
    msg: String,
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    #[serde(rename = "clientData")]
    client_data: String,
    expected: bool,
}

fn fixture() -> Fixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/audit-fable51-clientdata-cases.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("run tests/audit-fable51-clientdata-parity.test.ts first")).unwrap()
}

#[test]
fn client_data_rules_agree_with_the_typescript_side() {
    let fixture = fixture();
    let mut msg = [0u8; 32];
    hex::decode_to_slice(&fixture.msg, &mut msg).unwrap();
    let mut challenge = [0u8; 111];
    base64url(&challenge_text(&msg), &mut challenge);
    let mut disagreements = Vec::new();
    for case in &fixture.cases {
        let json = STANDARD.decode(&case.client_data).unwrap();
        let verdict = check_client_data(&json, &challenge).is_ok();
        if verdict != case.expected {
            disagreements.push(format!("{}: rust {} expected {}", case.name, verdict, case.expected));
        }
    }
    assert!(disagreements.is_empty(), "{disagreements:#?}");
}

/// A valid blob from a fresh P-256 key for `msg`, as the SDK's webAuthnSignatureBlob makes it.
fn valid_blob(msg: &[u8; 32]) -> (Vec<u8>, [u8; 20]) {
    let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let public_key = key.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec();
    let mut challenge = [0u8; 111];
    base64url(&challenge_text(msg), &mut challenge);
    let client_data = format!(r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://testnet.joyid.dev","crossOrigin":false}}"#, String::from_utf8_lossy(&challenge));
    let mut auth_data = Sha256::digest(b"testnet.joyid.dev").to_vec();
    auth_data.extend([0x05, 0, 0, 0, 0]);
    let digest = Sha256::new().chain_update(&auth_data).chain_update(Sha256::digest(client_data.as_bytes())).finalize();
    let signature: Signature = key.sign_prehash(&digest).unwrap();
    let mut blob = vec![1u8];
    blob.extend(&public_key);
    blob.extend(signature.to_bytes());
    blob.extend((auth_data.len() as u16).to_le_bytes());
    blob.extend(&auth_data);
    blob.extend((client_data.len() as u16).to_le_bytes());
    blob.extend(client_data.as_bytes());
    (blob, joyid_webauthn::blake160(&public_key))
}

#[test]
fn a_valid_blob_verifies_and_the_challenge_is_83_bytes() {
    let msg = [0x8au8; 32];
    let (blob, pubkey_hash) = valid_blob(&msg);
    assert_eq!(CHALLENGE_TEXT, 83);
    assert_eq!(verify(&pubkey_hash, &msg, &blob), Ok(()));
    let mut other = msg;
    other[0] ^= 1;
    assert_eq!(verify(&pubkey_hash, &other, &blob), Err(Error::Challenge));
}

/// xorshift, so the run is reproducible without a dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn random_mutations_of_a_valid_blob_never_panic_and_never_verify() {
    let msg = [0x8au8; 32];
    let (blob, pubkey_hash) = valid_blob(&msg);
    let mut rng = Rng(0x9e3779b97f4a7c15);
    let mut rejected = 0;
    for _ in 0..20_000 {
        let mut mutated = blob.clone();
        match rng.next() % 6 {
            0 => { let i = (rng.next() as usize) % mutated.len(); mutated[i] ^= 1 << (rng.next() % 8); }
            1 => { let i = (rng.next() as usize) % mutated.len(); mutated[i] = rng.next() as u8; }
            2 => { let n = (rng.next() as usize) % 64; mutated.truncate(mutated.len().saturating_sub(n)); }
            3 => { let n = (rng.next() as usize) % 300; mutated.extend(std::iter::repeat(rng.next() as u8).take(n)); }
            4 => { let i = (rng.next() as usize) % mutated.len(); mutated.remove(i); }
            _ => { let i = (rng.next() as usize) % mutated.len(); mutated.insert(i, rng.next() as u8); }
        }
        if mutated.len() > 1024 { mutated.truncate(1024); }
        let result = std::panic::catch_unwind(|| verify(&pubkey_hash, &msg, &mutated));
        let result = result.expect("verify must not panic");
        if mutated != blob {
            // The signature covers the public key hash, authenticatorData and clientDataJSON; the only
            // accepted change is extra zero padding.
            let padding_only = mutated.len() > blob.len() && mutated[..blob.len()] == blob[..] && mutated[blob.len()..].iter().all(|&b| b == 0);
            assert_eq!(result.is_ok(), padding_only, "mutation accepted: {mutated:?}");
            if result.is_err() { rejected += 1; }
        }
    }
    assert!(rejected > 19_000, "{rejected}");
}

//! Runs the real RISC-V binaries in CKB-VM through ckb-debugger, with the argument Omnilock's exec passes and,
//! for the verifier, a rescue transaction to rebuild the approval text from (`rescue.json`: everything to one
//! secp256k1 address). Build them first: `cargo build -p joyid-webauthn --release --target riscv64imac-unknown-none-elf`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Command;

const BINARY: &str = "joyid-webauthn";
const ORIGIN: &str = "https://testnet.joyid.dev";

fn binary(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/riscv64imac-unknown-none-elf/release").join(name);
    assert!(path.exists(), "build {name} for riscv64imac-unknown-none-elf first");
    path
}

fn rescue_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/rescue.json")
}

/// Exit code and cycles of one ckb-debugger run with `argument` as argv[0]; the verifier runs as input 0's lock
/// of the rescue transaction.
fn run(name: &str, argument: &str) -> (i64, u64) {
    let debugger = std::env::var("CKB_DEBUGGER").unwrap_or_else(|_| "ckb-debugger".into());
    let mut command = Command::new(debugger);
    if name == BINARY {
        command.arg("--tx-file").arg(rescue_file()).args(["--script", "input.0.lock"]);
    }
    let output = command.arg("--bin").arg(binary(name)).arg(argument).output().expect("ckb-debugger must be installed");
    let text = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    let field = |label: &str| {
        text.lines().find_map(|line| line.strip_prefix(label)).map(|value| value.trim().replace(',', "")).unwrap_or_else(|| panic!("no {label} in {text}"))
    };
    let code = field("Run result:").parse().unwrap();
    let cycles = field("All cycles:").split('(').next().unwrap().trim().parse().unwrap();
    (code, cycles)
}

fn blake160(data: &[u8]) -> [u8; 20] {
    joyid_webauthn::blake160(data)
}

/// The approval text the verifier rebuilds from rescue.json: 10,000 CKB less a 765-shannon fee, to one
/// secp256k1 address, no tokens.
fn approval(msg: &[u8; 32]) -> String {
    format!("KeyWay recovery\nMove everything to {RESCUE_DESTINATION}\nCKB: 9,999.99999235\nTokens: none\nFee: 0.00000765 CKB\nTransaction: 0x{}", hex::encode(msg))
}

const RESCUE_DESTINATION: &str = "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygfhutwy";

fn challenge(msg: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(approval(msg))
}

/// The clientDataJSON a browser produces for JoyID's testnet page, with Chrome's extra key.
fn client_data(challenge: &str) -> String {
    format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{ORIGIN}","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}}"#
    )
}

/// rpIdHash of testnet.joyid.dev ‖ flags (user present and verified) ‖ signCount 0, as JoyID's assertions have.
fn auth_data(flags: u8) -> Vec<u8> {
    let mut data = Sha256::digest(b"testnet.joyid.dev").to_vec();
    data.push(flags);
    data.extend([0, 0, 0, 0]);
    data
}

struct Passkey {
    key: SigningKey,
}

impl Passkey {
    fn new(seed: u8) -> Self {
        let mut bytes = [seed; 32];
        bytes[0] = 1;
        Passkey { key: SigningKey::from_slice(&bytes).unwrap() }
    }

    fn public_key(&self) -> Vec<u8> {
        self.key.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec()
    }

    fn sign(&self, auth_data: &[u8], client_data: &[u8]) -> Vec<u8> {
        let digest = Sha256::new().chain_update(auth_data).chain_update(Sha256::digest(client_data)).finalize();
        let signature: Signature = self.key.sign_prehash(&digest).unwrap();
        signature.to_bytes().to_vec()
    }
}

fn blob(public_key: &[u8], rs: &[u8], auth_data: &[u8], client_data: &[u8], slot: usize) -> Vec<u8> {
    let mut blob = vec![2u8, 0];
    blob.extend(public_key);
    blob.extend(rs);
    blob.extend((auth_data.len() as u16).to_le_bytes());
    blob.extend(auth_data);
    blob.extend((client_data.len() as u16).to_le_bytes());
    blob.extend(client_data);
    if blob.len() < slot {
        blob.resize(slot, 0);
    }
    blob
}

/// Omnilock's exec argument: code_hash:hash_type:pubkey_hash:msg:signature in hex.
fn argument(pubkey_hash: &[u8], msg: &[u8; 32], signature: &[u8]) -> String {
    format!("{}:02:{}:{}:{}", hex::encode([0x5a; 32]), hex::encode(pubkey_hash), hex::encode(msg), hex::encode(signature))
}

const MSG: [u8; 32] = [0x8a; 32];

/// A signed assertion for `MSG` with this clientDataJSON and flags.
fn signed(passkey: &Passkey, client: &str, flags: u8, slot: usize) -> String {
    let auth = auth_data(flags);
    let rs = passkey.sign(&auth, client.as_bytes());
    argument(&blake160(&passkey.public_key()), &MSG, &blob(&passkey.public_key(), &rs, &auth, client.as_bytes(), slot))
}

fn expect(argument: &str, code: i64) -> u64 {
    let (result, cycles) = run(BINARY, argument);
    assert_eq!(result, code, "exit code");
    cycles
}

#[test]
fn accepts_a_joyid_assertion_for_this_sighash() {
    let passkey = Passkey::new(7);
    let cycles = expect(&signed(&passkey, &client_data(&challenge(&MSG)), 0x05, 0), 0);
    println!("valid assertion: {cycles} cycles");
    let padded = expect(&signed(&passkey, &client_data(&challenge(&MSG)), 0x05, 640), 0);
    println!("valid assertion in a 640-byte slot: {padded} cycles");
    // User presence alone is enough; key order and whitespace don't matter.
    expect(&signed(&passkey, &client_data(&challenge(&MSG)), 0x01, 0), 0);
    let reordered = format!(r#"{{ "challenge" : "{}", "origin":"{ORIGIN}", "type":"webauthn.get" }}"#, challenge(&MSG));
    expect(&signed(&passkey, &reordered, 0x05, 0), 0);
}

#[test]
fn runs_the_p256_core_on_real_joyid_vectors() {
    // ckb-auth issue #31: JoyID's message is authenticatorData (37) ‖ sha256(clientDataJSON).
    let public_key = "3538dfd53ad93d2e0a6e7f470295dcd71057d825e1f87229e5afe2a906aa7cfc099fdfa04442dac33548b6988af8af58d2052529088f7b73ef00800f7fbcddb3";
    let rs = "bedea43a55185f12b458ec3ec590986e8c798fe2636424b12855d21e94b187a874eb3704471863d915b6e2cae932ad60ddd2bd1302ebbd116fa1b3396461808d";
    let message = "2b8b05e1f0303efb898fe4d6de601198c7a7b864abbe6a21c73b2e787e187c520500000000384894418ce002769e96ff7d6703fce9b5ba98b56aab181349eed402146a3e81";
    let (code, cycles) = run("p256-check", &format!("{public_key}:{rs}:{message}"));
    assert_eq!(code, 0);
    println!("ckb-auth#31 vector, P-256 core: {cycles} cycles");
    let tampered = format!("{}00", &message[..message.len() - 2]);
    assert_eq!(run("p256-check", &format!("{public_key}:{rs}:{tampered}")).0, 109);
}

/// A full JoyID testnet assertion (iany.me, "How to verify JoyID WebAuthn signature"): challenge
/// "Sign this for me", Chrome's extra key, and a high s, which WebAuthn allows.
fn blog_assertion() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let message = URL_SAFE_NO_PAD.decode("K4sF4fAwPvuJj-TW3mARmMenuGSrvmohxzsueH4YfFIFAAAAAHsidHlwZSI6IndlYmF1dGhuLmdldCIsImNoYWxsZW5nZSI6IlUybG5iaUIwYUdseklHWnZjaUJ0WlEiLCJvcmlnaW4iOiJodHRwczovL3Rlc3RuZXQuam95aWQuZGV2IiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0").unwrap();
    let der = URL_SAFE_NO_PAD.decode("MEUCICF25qdO6nLreEoBHnyaw-9R6XFHbIu-NwsAI53t016qAiEAgmhlwTEMxoWxKj79R1rUkB_6nrhJfws82DqHkY_HnqQ").unwrap();
    let rs = Signature::from_der(&der).unwrap().to_bytes().to_vec();
    let public_key = hex::decode("3538dfd53ad93d2e0a6e7f470295dcd71057d825e1f87229e5afe2a906aa7cfc099fdfa04442dac33548b6988af8af58d2052529088f7b73ef00800f7fbcddb3").unwrap();
    (public_key, rs, message[..37].to_vec(), message[37..].to_vec())
}

#[test]
fn reads_a_real_joyid_assertion() {
    let (public_key, rs, auth, client) = blog_assertion();
    let mut message = auth.clone();
    message.extend(Sha256::digest(&client));
    let (code, _) = run("p256-check", &format!("{}:{}:{}", hex::encode(&public_key), hex::encode(&rs), hex::encode(&message)));
    assert_eq!(code, 0, "the real high-s signature verifies");
    // Through the deployed binary it parses and passes every check up to the challenge, which is
    // "Sign this for me" rather than a CKB transaction.
    expect(&argument(&blake160(&public_key), &MSG, &blob(&public_key, &rs, &auth, &client, 0)), 107);
}

#[test]
fn rejects_wrong_challenges() {
    let passkey = Passkey::new(7);
    // Signed for another transaction.
    expect(&signed(&passkey, &client_data(&challenge(&[0x8b; 32])), 0x05, 0), 107);
    // The raw sighash, or its hex without the prefix, as the challenge.
    expect(&signed(&passkey, &client_data(&URL_SAFE_NO_PAD.encode(MSG)), 0x05, 0), 107);
    expect(&signed(&passkey, &client_data(&URL_SAFE_NO_PAD.encode(hex::encode(MSG))), 0x05, 0), 107);
    // Padded base64url, upper-case hex.
    let padded = format!("{}=", challenge(&MSG));
    expect(&signed(&passkey, &client_data(&padded), 0x05, 0), 107);
    let upper = URL_SAFE_NO_PAD.encode(approval(&MSG).replace(&hex::encode(MSG), &hex::encode_upper(MSG)));
    expect(&signed(&passkey, &client_data(&upper), 0x05, 0), 107);
    // The text before readable approvals.
    expect(&signed(&passkey, &client_data(&URL_SAFE_NO_PAD.encode(format!("CKB transaction: 0x{}", hex::encode(MSG)))), 0x05, 0), 107);
    // The mainnet prefix for the same destination: the network byte says testnet.
    expect(&signed(&passkey, &client_data(&URL_SAFE_NO_PAD.encode(approval(&MSG).replace("ckt1", "ckb1"))), 0x05, 0), 107);
    let good = challenge(&MSG);
    // Only present in another field, or in a nested object, or smuggled inside the origin string.
    expect(&signed(&passkey, &format!(r#"{{"type":"webauthn.get","challenge":"x","origin":"{good}"}}"#), 0x05, 0), 107);
    expect(&signed(&passkey, &format!(r#"{{"type":"webauthn.get","origin":"{ORIGIN}","extra":{{"challenge":"{good}"}}}}"#), 0x05, 0), 107);
    expect(&signed(&passkey, &format!(r#"{{"type":"webauthn.get","challenge":"x","origin":"\",\"challenge\":\"{good}\""}}"#), 0x05, 0), 107);
    expect(&signed(&passkey, &format!(r#"{{"type":"webauthn.get","challenges":"{good}"}}"#), 0x05, 0), 107);
    // Not a string.
    expect(&signed(&passkey, &format!(r#"{{"type":"webauthn.get","challenge":["{good}"]}}"#), 0x05, 0), 107);
}

#[test]
fn compares_unescaped_keys_and_values() {
    let passkey = Passkey::new(7);
    let good = challenge(&MSG);
    // An escaped key is the same key, so this is a duplicate.
    expect(&signed(&passkey, &format!(r#"{{"type":"webauthn.get","challenge":"x","challenge":"{good}"}}"#), 0x05, 0), 105);
    // An escaped value that unescapes to the right challenge is the right challenge.
    let escaped = format!("\\u{:04x}{}", good.as_bytes()[0], &good[1..]);
    expect(&signed(&passkey, &format!(r#"{{"type":"webauthn.get","challenge":"{escaped}"}}"#), 0x05, 0), 0);
}

#[test]
fn rejects_duplicate_keys() {
    let passkey = Passkey::new(7);
    let good = challenge(&MSG);
    expect(&signed(&passkey, &format!(r#"{{"type":"webauthn.get","challenge":"x","challenge":"{good}"}}"#), 0x05, 0), 105);
    expect(&signed(&passkey, &format!(r#"{{"type":"webauthn.get","challenge":"{good}","challenge":"x"}}"#), 0x05, 0), 105);
    expect(&signed(&passkey, &format!(r#"{{"type":"webauthn.create","type":"webauthn.get","challenge":"{good}"}}"#), 0x05, 0), 105);
}

#[test]
fn rejects_the_wrong_type() {
    let passkey = Passkey::new(7);
    let good = challenge(&MSG);
    expect(&signed(&passkey, &format!(r#"{{"type":"webauthn.create","challenge":"{good}"}}"#), 0x05, 0), 106);
    expect(&signed(&passkey, &format!(r#"{{"challenge":"{good}"}}"#), 0x05, 0), 106);
    expect(&signed(&passkey, &format!(r#"{{"type":"webauthn.get ","challenge":"{good}"}}"#), 0x05, 0), 106);
    expect(&signed(&passkey, &format!(r#"{{"type":null,"challenge":"{good}"}}"#), 0x05, 0), 106);
}

#[test]
fn rejects_malformed_client_data() {
    let passkey = Passkey::new(7);
    let good = client_data(&challenge(&MSG));
    expect(&signed(&passkey, &format!("{good}x"), 0x05, 0), 105);
    expect(&signed(&passkey, &format!("{good} "), 0x05, 0), 105);
    expect(&signed(&passkey, &format!(" {good}"), 0x05, 0), 105);
    expect(&signed(&passkey, &good[..good.len() - 1], 0x05, 0), 105);
    expect(&signed(&passkey, &format!("[{good}]"), 0x05, 0), 105);
    let nested = format!(r#"{{"type":"webauthn.get","challenge":"{}","x":{}1{}}}"#, challenge(&MSG), "[".repeat(12), "]".repeat(12));
    expect(&signed(&passkey, &nested, 0x05, 0), 105);
    let control = format!(r#"{{"type":"webauthn.get","challenge":"{}","origin":"a{}b"}}"#, challenge(&MSG), '\u{1}');
    expect(&signed(&passkey, &control, 0x05, 0), 105);
    let lone_surrogate = format!(r#"{{"type":"webauthn.get","challenge":"{}","origin":"\ud800"}}"#, challenge(&MSG));
    expect(&signed(&passkey, &lone_surrogate, 0x05, 0), 105);
    let number = format!(r#"{{"type":"webauthn.get","challenge":"{}","n":01}}"#, challenge(&MSG));
    expect(&signed(&passkey, &number, 0x05, 0), 105);
    // Not UTF-8.
    let auth = auth_data(0x05);
    let mut bytes = good.clone().into_bytes();
    bytes.insert(bytes.len() - 1, b' ');
    let at = bytes.len() - 2;
    bytes[at] = 0xff;
    let rs = passkey.sign(&auth, &bytes);
    expect(&argument(&blake160(&passkey.public_key()), &MSG, &blob(&passkey.public_key(), &rs, &auth, &bytes, 0)), 105);
}

#[test]
fn rejects_authenticator_data_without_user_presence() {
    let passkey = Passkey::new(7);
    expect(&signed(&passkey, &client_data(&challenge(&MSG)), 0x04, 0), 104);
    expect(&signed(&passkey, &client_data(&challenge(&MSG)), 0x00, 0), 104);
    let client = client_data(&challenge(&MSG));
    let short = auth_data(0x05)[..36].to_vec();
    let rs = passkey.sign(&short, client.as_bytes());
    expect(&argument(&blake160(&passkey.public_key()), &MSG, &blob(&passkey.public_key(), &rs, &short, client.as_bytes(), 0)), 103);
}

#[test]
fn rejects_tampering_and_other_keys() {
    let passkey = Passkey::new(7);
    let client = client_data(&challenge(&MSG));
    let auth = auth_data(0x05);
    let rs = passkey.sign(&auth, client.as_bytes());
    let hash = blake160(&passkey.public_key());
    let mut counter = auth.clone();
    counter[36] = 1;
    expect(&argument(&hash, &MSG, &blob(&passkey.public_key(), &rs, &counter, client.as_bytes(), 0)), 109);
    let origin = client.replace("testnet.joyid.dev", "testnet.joyid.dew");
    expect(&argument(&hash, &MSG, &blob(&passkey.public_key(), &rs, &auth, origin.as_bytes(), 0)), 109);
    let mut flipped = rs.clone();
    flipped[63] ^= 1;
    expect(&argument(&hash, &MSG, &blob(&passkey.public_key(), &flipped, &auth, client.as_bytes(), 0)), 109);
    expect(&argument(&hash, &MSG, &blob(&passkey.public_key(), &[0u8; 64], &auth, client.as_bytes(), 0)), 109);
    // Another passkey: its own key doesn't hash to the identity; with the identity's key its signature fails.
    let other = Passkey::new(9);
    let other_rs = other.sign(&auth, client.as_bytes());
    expect(&argument(&hash, &MSG, &blob(&other.public_key(), &other_rs, &auth, client.as_bytes(), 0)), 101);
    expect(&argument(&hash, &MSG, &blob(&passkey.public_key(), &other_rs, &auth, client.as_bytes(), 0)), 109);
    // A public key that isn't on the curve, under its own hash.
    let mut off_curve = passkey.public_key();
    off_curve[63] ^= 1;
    expect(&argument(&blake160(&off_curve), &MSG, &blob(&off_curve, &rs, &auth, client.as_bytes(), 0)), 108);
}

#[test]
fn rejects_malformed_lengths() {
    let passkey = Passkey::new(7);
    let client = client_data(&challenge(&MSG));
    let auth = auth_data(0x05);
    let rs = passkey.sign(&auth, client.as_bytes());
    let hash = blake160(&passkey.public_key());
    let good = blob(&passkey.public_key(), &rs, &auth, client.as_bytes(), 0);
    let with = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut bytes = good.clone();
        edit(&mut bytes);
        argument(&hash, &MSG, &bytes)
    };
    expect(&with(&|bytes| bytes[0] = 1), 102);
    expect(&with(&|bytes| bytes[0] = 3), 102);
    expect(&with(&|bytes| bytes[1] = 2), 110);
    expect(&with(&|bytes| bytes.truncate(bytes.len() - 1)), 102);
    expect(&with(&|bytes| bytes.push(1)), 102);
    expect(&with(&|bytes| { bytes.resize(700, 0); bytes[699] = 1; }), 102);
    expect(&with(&|bytes| bytes[130] = 200), 102);
    expect(&with(&|bytes| { let at = 132 + 37; bytes[at] = 0xff; bytes[at + 1] = 0xff; }), 102);
    expect(&with(&|bytes| bytes.truncate(100)), 102);
    // Over Omnilock's 1024-byte signature limit.
    expect(&with(&|bytes| bytes.resize(1025, 0)), 100);
    // The exec argument itself.
    let valid = argument(&hash, &MSG, &good);
    expect(&format!("{valid}:00"), 100);
    expect(&valid.replacen(':', "", 1), 100);
    expect(&valid[..valid.len() - 1], 100);
    expect(&format!("{}:{}", &valid[..valid.rfind(':').unwrap()], "zz"), 100);
    expect(&valid.replacen(&hex::encode(MSG), &hex::encode([0x8a; 31]), 1), 100);
}

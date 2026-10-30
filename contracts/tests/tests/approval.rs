//! KeyWay's readable recovery approval: the Rust text builder against the SDK's (fixtures written by
//! `npx tsx scripts/approval-fixtures.ts`), and both verifiers in CKB-VM through ckb-debugger on random
//! transactions, with the account's lock replaced by the verifier so it reads the transaction itself.
//! Build the binaries first: `cargo build -p joyid-webauthn -p evm-personal-sign --release --target riscv64imac-unknown-none-elf`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use k256::ecdsa::SigningKey as EvmKey;
use keyway_approval::{approval_text, full_address, Destination, Network, Rescue};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::path::PathBuf;
use std::process::Command;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TextCase {
    network: String,
    code_hash: String,
    hash_type: u8,
    args: String,
    address: String,
    ckb: String,
    fee: String,
    token_cells: u64,
    sighash: String,
    text: Option<String>,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ScriptJson {
    code_hash: String,
    hash_type: String,
    args: String,
}

#[derive(Deserialize, Clone)]
struct InputJson {
    lock: ScriptJson,
    capacity: String,
}

#[derive(Deserialize, Clone)]
struct OutputJson {
    lock: ScriptJson,
    #[serde(rename = "type")]
    type_: Option<ScriptJson>,
    data: String,
    capacity: String,
}

#[derive(Deserialize, Clone)]
struct TransactionCase {
    network: String,
    account: ScriptJson,
    sighash: String,
    text: Option<String>,
    inputs: Vec<InputJson>,
    outputs: Vec<OutputJson>,
}

fn fixture<T: for<'a> Deserialize<'a>>(name: &str) -> T {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name);
    serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|_| panic!("run `npx tsx scripts/approval-fixtures.ts` to write {name}"))).unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text.trim_start_matches("0x")).unwrap()
}

fn network(name: &str) -> Network {
    if name == "mainnet" { Network::Mainnet } else { Network::Testnet }
}

#[test]
fn text_matches_the_sdk_and_addresses_match_ccc() {
    let cases: Vec<TextCase> = fixture("approval-text-cases.json");
    assert!(cases.len() >= 400);
    for case in &cases {
        let code_hash: [u8; 32] = unhex(&case.code_hash).try_into().unwrap();
        let args = unhex(&case.args);
        let destination = Destination { code_hash: &code_hash, hash_type: case.hash_type, args: &args };
        let mut address = [0u8; 1024];
        let length = full_address(network(&case.network), &destination, &mut address).unwrap();
        assert_eq!(std::str::from_utf8(&address[..length]).unwrap(), case.address);
        let rescue = Rescue { destination, ckb: case.ckb.parse().unwrap(), token_cells: case.token_cells, fee: case.fee.parse().unwrap() };
        let mut text = [0u8; keyway_approval::MAX_TEXT];
        let sighash: [u8; 32] = unhex(&case.sighash).try_into().unwrap();
        match (approval_text(network(&case.network), &rescue, &sighash, &mut text), &case.text) {
            (Ok(length), Some(expected)) => assert_eq!(std::str::from_utf8(&text[..length]).unwrap(), expected),
            (Err(keyway_approval::ApprovalError::TooLong), None) => {}
            (result, expected) => panic!("{result:?} vs {expected:?} for {}", case.address),
        }
    }
}

fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn script_json(script: &ScriptJson) -> serde_json::Value {
    serde_json::json!({ "code_hash": script.code_hash, "hash_type": script.hash_type, "args": script.args })
}

/// A ckb-debugger mock transaction: the inputs and outputs of `case`, a stand-in code cell (data 0x00) for the
/// account's lock and empty witnesses. The verifier binary replaces the stand-in.
fn mock_transaction(case: &TransactionCase) -> String {
    let dep_out_point = serde_json::json!({ "tx_hash": format!("0x{}", "11".repeat(32)), "index": "0x0" });
    let dead = serde_json::json!({ "code_hash": format!("0x{}", "00".repeat(32)), "hash_type": "data", "args": "0x" });
    let inputs: Vec<_> = case.inputs.iter().enumerate().map(|(index, input)| {
        let previous = serde_json::json!({ "tx_hash": format!("0x{:064x}", index + 0x100), "index": "0x0" });
        (
            serde_json::json!({ "previous_output": previous, "since": "0x0" }),
            serde_json::json!({ "capacity": format!("0x{:x}", input.capacity.parse::<u64>().unwrap()), "lock": script_json(&input.lock), "type": null }),
        )
    }).collect();
    let outputs: Vec<_> = case.outputs.iter().map(|output| serde_json::json!({
        "capacity": format!("0x{:x}", output.capacity.parse::<u64>().unwrap()),
        "lock": script_json(&output.lock),
        "type": output.type_.as_ref().map(script_json),
    })).collect();
    serde_json::json!({
        "mock_info": {
            "inputs": inputs.iter().map(|(input, output)| serde_json::json!({ "input": input, "output": output, "data": "0x", "header": null })).collect::<Vec<_>>(),
            "cell_deps": [{ "cell_dep": { "out_point": dep_out_point, "dep_type": "code" }, "output": { "capacity": "0x0", "lock": dead, "type": null }, "data": "0x00", "header": null }],
            "header_deps": [],
        },
        "tx": {
            "version": "0x0",
            "cell_deps": [{ "out_point": dep_out_point, "dep_type": "code" }],
            "header_deps": [],
            "inputs": inputs.iter().map(|(input, _)| input.clone()).collect::<Vec<_>>(),
            "outputs": outputs,
            "outputs_data": case.outputs.iter().map(|output| output.data.clone()).collect::<Vec<_>>(),
            "witnesses": case.inputs.iter().map(|_| "0x").collect::<Vec<_>>(),
        }
    }).to_string()
}

fn binary(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/riscv64imac-unknown-none-elf/release").join(name);
    assert!(path.exists(), "build {name} for riscv64imac-unknown-none-elf first");
    path
}

/// Exit code and cycles of the verifier run as input 0's lock of `case`, with `argument` as argv[0].
fn run(name: &str, case: &TransactionCase, argument: &str) -> (i64, u64) {
    let directory = std::env::temp_dir().join(format!("keyway-approval-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let file = directory.join(format!("{name}-{:x}.json", hash(argument.as_bytes())[0] as u64 * 1_000_003 + case.sighash.len() as u64 + rand_suffix()));
    std::fs::write(&file, mock_transaction(case)).unwrap();
    let debugger = std::env::var("CKB_DEBUGGER").unwrap_or_else(|_| "ckb-debugger".into());
    let output = Command::new(debugger)
        .args(["--tx-file", file.to_str().unwrap(), "--script", "input.0.lock", "--bin"])
        .arg(binary(name))
        .arg(argument)
        .output()
        .expect("ckb-debugger must be installed");
    std::fs::remove_file(&file).ok();
    let text = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    let field = |label: &str| text.lines().find_map(|line| line.strip_prefix(label)).map(|value| value.trim().replace(',', "")).unwrap_or_else(|| panic!("no {label} in {text}"));
    let code = field("Run result:").parse().unwrap();
    let cycles = field("All cycles:").split('(').next().unwrap().trim().parse().unwrap();
    (code, cycles)
}

fn rand_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn personal_sign(key: &EvmKey, text: &[u8]) -> Vec<u8> {
    let digest = Keccak256::new().chain_update(format!("\x19Ethereum Signed Message:\n{}", text.len())).chain_update(text).finalize();
    let (signature, recovery) = key.sign_prehash_recoverable(&digest).unwrap();
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(27 + recovery.to_byte());
    bytes
}

fn evm_address(key: &EvmKey) -> [u8; 20] {
    let point = key.verifying_key().to_encoded_point(false);
    Keccak256::digest(&point.as_bytes()[1..])[12..].try_into().unwrap()
}

fn exec_argument(code_hash: &[u8; 32], pubkey_hash: &[u8], msg: &[u8], signature: &[u8]) -> String {
    format!("{}:02:{}:{}:{}", hex::encode(code_hash), hex::encode(pubkey_hash), hex::encode(msg), hex::encode(signature))
}

fn evm_blob(network: u8, signature: &[u8]) -> Vec<u8> {
    let mut blob = vec![1u8, network];
    blob.extend(signature);
    blob
}

fn network_byte(name: &str) -> u8 {
    if name == "mainnet" { 1 } else { 0 }
}

/// Every transaction the SDK reads as a rescue passes the EVM verifier with a signature over the SDK's text;
/// every one it refuses is refused on chain as not a rescue (111) or with outputs above inputs.
#[test]
fn evm_verifier_rebuilds_the_sdk_text_from_random_transactions() {
    let cases: Vec<TransactionCase> = fixture("approval-transaction-cases.json");
    let key = EvmKey::from_slice(&[7u8; 32]).unwrap();
    let address = evm_address(&key);
    let code_hash = [0x42u8; 32];
    let mut accepted = 0;
    let mut max_cycles = 0;
    for case in &cases {
        let sighash = unhex(&case.sighash);
        let text = case.text.clone().unwrap_or_else(|| "KeyWay recovery".into());
        let signature = evm_blob(network_byte(&case.network), &personal_sign(&key, text.as_bytes()));
        let (code, cycles) = run("evm-personal-sign", case, &exec_argument(&code_hash, &address, &sighash, &signature));
        if case.text.is_some() {
            assert_eq!(code, 0, "{text}");
            accepted += 1;
            max_cycles = max_cycles.max(cycles);
        } else {
            assert_eq!(code, 111, "refused shape for {}", case.sighash);
        }
    }
    println!("EVM verifier: {accepted} accepted, {} refused, at most {max_cycles} cycles", cases.len() - accepted);
    assert!(accepted > 50);
}

/// The approvals a phishing page would try: the right text replayed on another destination or amount, the
/// right sighash with a wrong destination line, the old "CKB transaction: 0x…" text, the wrong network, and
/// a 0/1 recovery id, which wallets also use.
#[test]
fn evm_verifier_refuses_other_text() {
    let cases: Vec<TransactionCase> = fixture("approval-transaction-cases.json");
    let case = cases.iter().find(|case| case.text.is_some() && case.network == "testnet").unwrap().clone();
    let key = EvmKey::from_slice(&[7u8; 32]).unwrap();
    let address = evm_address(&key);
    let code_hash = [0x42u8; 32];
    let sighash = unhex(&case.sighash);
    let text = case.text.clone().unwrap();
    let argument = |text: &str, network: u8| exec_argument(&code_hash, &address, &sighash, &evm_blob(network, &personal_sign(&key, text.as_bytes())));
    assert_eq!(run("evm-personal-sign", &case, &argument(&text, 0)).0, 0);

    let mut low_v = personal_sign(&key, text.as_bytes());
    low_v[64] -= 27;
    assert_eq!(run("evm-personal-sign", &case, &exec_argument(&code_hash, &address, &sighash, &evm_blob(0, &low_v))).0, 0);

    let mut other_destination = case.clone();
    for output in &mut other_destination.outputs {
        output.lock.args = format!("{}ff", output.lock.args);
    }
    assert_eq!(run("evm-personal-sign", &other_destination, &argument(&text, 0)).0, 101);
    let mut other_amount = case.clone();
    other_amount.outputs[0].capacity = (other_amount.outputs[0].capacity.parse::<u64>().unwrap() - 1).to_string();
    assert_eq!(run("evm-personal-sign", &other_amount, &argument(&text, 0)).0, 101);

    let line = text.lines().nth(1).unwrap();
    let wrong_line = text.replace(line, &format!("{}q", &line[..line.len() - 1]));
    assert_eq!(run("evm-personal-sign", &case, &argument(&wrong_line, 0)).0, 101);
    let old = format!("CKB transaction: 0x{}", hex::encode(&sighash));
    assert_eq!(run("evm-personal-sign", &case, &argument(&old, 0)).0, 101);
    assert_eq!(run("evm-personal-sign", &case, &argument(&text, 1)).0, 101);
    assert_eq!(run("evm-personal-sign", &case, &argument(&text, 2)).0, 110);
    let other_key = EvmKey::from_slice(&[9u8; 32]).unwrap();
    let foreign = exec_argument(&code_hash, &address, &sighash, &evm_blob(0, &personal_sign(&other_key, text.as_bytes())));
    assert_eq!(run("evm-personal-sign", &case, &foreign).0, 101);
}

struct Passkey(SigningKey);

impl Passkey {
    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec()
    }

    /// A JoyID-shaped assertion over `text` as the challenge, as the version 2 blob in a `slot`-byte signature.
    fn blob(&self, network: u8, text: &str, slot: usize) -> Vec<u8> {
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://testnet.joyid.dev","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}}"#,
            URL_SAFE_NO_PAD.encode(text)
        );
        let mut auth_data = Sha256::digest(b"testnet.joyid.dev").to_vec();
        auth_data.extend([5, 0, 0, 0, 0]);
        let digest = Sha256::new().chain_update(&auth_data).chain_update(Sha256::digest(client_data.as_bytes())).finalize();
        let signature: Signature = self.0.sign_prehash(&digest).unwrap();
        let mut blob = vec![2u8, network];
        blob.extend(self.public_key());
        blob.extend(signature.to_bytes());
        blob.extend((auth_data.len() as u16).to_le_bytes());
        blob.extend(&auth_data);
        blob.extend((client_data.len() as u16).to_le_bytes());
        blob.extend(client_data.as_bytes());
        assert!(blob.len() <= slot, "{} bytes", blob.len());
        blob.resize(slot, 0);
        blob
    }
}

#[test]
fn webauthn_verifier_rebuilds_the_sdk_text_and_fits_omnilock() {
    let cases: Vec<TransactionCase> = fixture("approval-transaction-cases.json");
    let passkey = Passkey(SigningKey::from_slice(&[3u8; 32]).unwrap());
    let pubkey_hash = joyid_webauthn::blake160(&passkey.public_key());
    let code_hash = [0x24u8; 32];
    let mut accepted = 0;
    let mut max_cycles = 0;
    for case in cases.iter().step_by(2) {
        let sighash = unhex(&case.sighash);
        let text = case.text.clone().unwrap_or_else(|| "KeyWay recovery".into());
        let argument = exec_argument(&code_hash, &pubkey_hash, &sighash, &passkey.blob(network_byte(&case.network), &text, 1024));
        let (code, cycles) = run("joyid-webauthn", case, &argument);
        if case.text.is_some() {
            assert_eq!(code, 0, "{text}");
            accepted += 1;
            max_cycles = max_cycles.max(cycles);
        } else {
            assert_eq!(code, 111);
        }
    }
    println!("WebAuthn verifier: {accepted} accepted, at most {max_cycles} cycles");

    // The longest text the builder allows still fits in 1024 bytes with Chrome's extra clientDataJSON key.
    let longest = "x".repeat(keyway_approval::MAX_TEXT);
    passkey.blob(0, &longest, 1024);

    let case = cases.iter().find(|case| case.text.is_some() && case.network == "testnet").unwrap().clone();
    let sighash = unhex(&case.sighash);
    let text = case.text.clone().unwrap();
    let argument = |text: &str| exec_argument(&code_hash, &pubkey_hash, &sighash, &passkey.blob(0, text, 1024));
    assert_eq!(run("joyid-webauthn", &case, &argument(&text)).0, 0);
    let mut other_destination = case.clone();
    for output in &mut other_destination.outputs {
        output.lock.args = format!("{}ff", output.lock.args);
    }
    assert_eq!(run("joyid-webauthn", &other_destination, &argument(&text)).0, 107);
    let old = format!("CKB transaction: 0x{}", hex::encode(&sighash));
    assert_eq!(run("joyid-webauthn", &case, &argument(&old)).0, 107);
    let mut version_1 = passkey.blob(0, &text, 1024);
    version_1[0] = 1;
    assert_eq!(run("joyid-webauthn", &case, &exec_argument(&code_hash, &pubkey_hash, &sighash, &version_1)).0, 102);
}

/// Random byte mutations of valid signatures, through the library code the binaries run: no panic and no
/// accept unless the mutation left the checked bytes as they were.
#[test]
fn mutated_signatures_are_refused() {
    let text = "KeyWay recovery\nMove everything to ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqfkjp7ljqd2tnjqxjvsvpwfgqvz5fz5rcqgqrxl6\nCKB: 9,802.99998207\nTokens: none\nFee: 0.00000765 CKB\nTransaction: 0x0102030405060708091011121314151617181920212223242526272829303132";
    let key = EvmKey::from_slice(&[7u8; 32]).unwrap();
    let address = evm_address(&key);
    let msg = [1u8; 32];
    let evm = evm_blob(0, &personal_sign(&key, text.as_bytes()));
    let passkey = Passkey(SigningKey::from_slice(&[3u8; 32]).unwrap());
    let pubkey_hash = joyid_webauthn::blake160(&passkey.public_key());
    let webauthn = passkey.blob(0, text, 768);
    let mut state = 0x1234_5678_9abc_def0u64;
    let mut next = move || { state ^= state << 13; state ^= state >> 7; state ^= state << 17; state };
    let mut accepted = 0;
    for round in 0..40_000 {
        let evm_round = round % 2 == 0;
        let mut blob = if evm_round { evm.clone() } else { webauthn.clone() };
        for _ in 0..1 + next() % 4 {
            let at = (next() as usize) % blob.len();
            blob[at] = next() as u8;
        }
        if evm_round {
            let argument = exec_argument(&[0; 32], &address, &msg, &blob);
            let ok = evm_personal_sign::parse_argument(argument.as_bytes()).and_then(|parsed| evm_personal_sign::verify(&parsed, text.as_bytes())).is_ok();
            if ok {
                // Only v's alternative encodings (0/1 for 27/28) may still verify.
                assert_eq!(blob[..66], evm[..66]);
                accepted += 1;
            }
        } else if joyid_webauthn::verify(&pubkey_hash, text.as_bytes(), &blob).is_ok() {
            // Bytes outside what is checked: the signCount, the clientDataJSON fields other than type and
            // challenge are signed, so only the network byte (same prefix) or nothing may differ.
            assert_eq!(blob, webauthn);
            accepted += 1;
        }
    }
    println!("mutations: 40000, accepted unchanged signatures: {accepted}");
}

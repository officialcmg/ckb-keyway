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
    #[serde(rename = "type")]
    type_: Option<ScriptJson>,
    data: String,
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
            serde_json::json!({ "capacity": format!("0x{:x}", input.capacity.parse::<u64>().unwrap()), "lock": script_json(&input.lock), "type": input.type_.as_ref().map(script_json) }),
            input.data.clone(),
        )
    }).collect();
    let outputs: Vec<_> = case.outputs.iter().map(|output| serde_json::json!({
        "capacity": format!("0x{:x}", output.capacity.parse::<u64>().unwrap()),
        "lock": script_json(&output.lock),
        "type": output.type_.as_ref().map(script_json),
    })).collect();
    serde_json::json!({
        "mock_info": {
            "inputs": inputs.iter().map(|(input, output, data)| serde_json::json!({ "input": input, "output": output, "data": data, "header": null })).collect::<Vec<_>>(),
            "cell_deps": [{ "cell_dep": { "out_point": dep_out_point, "dep_type": "code" }, "output": { "capacity": "0x0", "lock": dead, "type": null }, "data": "0x00", "header": null }],
            "header_deps": [],
        },
        "tx": {
            "version": "0x0",
            "cell_deps": [{ "out_point": dep_out_point, "dep_type": "code" }],
            "header_deps": [],
            "inputs": inputs.iter().map(|(input, _, _)| input.clone()).collect::<Vec<_>>(),
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

/// Exit code and cycles of the verifier run as the lock of `case`'s first input of the account, with `argument`
/// as argv[0].
fn run(name: &str, case: &TransactionCase, argument: &str) -> (i64, u64) {
    let account = case.inputs.iter().position(|input| input.lock.code_hash == case.account.code_hash && input.lock.args == case.account.args).expect("an input of the account");
    let directory = std::env::temp_dir().join(format!("keyway-approval-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let file = directory.join(format!("{name}-{:x}.json", hash(argument.as_bytes())[0] as u64 * 1_000_003 + case.sighash.len() as u64 + rand_suffix()));
    std::fs::write(&file, mock_transaction(case)).unwrap();
    let debugger = std::env::var("CKB_DEBUGGER").unwrap_or_else(|_| "ckb-debugger".into());
    let output = Command::new(debugger)
        .args(["--tx-file", file.to_str().unwrap(), "--script", &format!("input.{account}.lock"), "--bin"])
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

/// The rescue text the SDK would build for `case` (which must be one the verifiers accept), with its token count.
fn sdk_text(case: &TransactionCase, token_cells: u64, ckb: u128, fee: u128) -> String {
    let lock = &case.outputs[0].lock;
    let code_hash: [u8; 32] = unhex(&lock.code_hash).try_into().unwrap();
    let hash_type = match lock.hash_type.as_str() { "data" => 0, "type" => 1, "data1" => 2, _ => 4 };
    let args = unhex(&lock.args);
    let rescue = Rescue { destination: Destination { code_hash: &code_hash, hash_type, args: &args }, ckb, token_cells, fee };
    let mut text = [0u8; keyway_approval::MAX_TEXT];
    let sighash: [u8; 32] = unhex(&case.sighash).try_into().unwrap();
    let length = approval_text(network(&case.network), &rescue, &sighash, &mut text).unwrap();
    String::from_utf8(text[..length].to_vec()).unwrap()
}

/// The text counts token cells rather than naming them, so both verifiers accept only the account's own token cells
/// moved unchanged: a token cell changed (its data), put under another type script, left out (burned), moved twice,
/// taken from someone else's input, or CKB put under a type script the account didn't hold, all behind the same
/// "N token cells" line the honest rescue shows, are refused (111) before any signature is checked.
#[test]
fn token_cells_must_be_the_accounts_own_moved_unchanged() {
    let cases: Vec<TransactionCase> = fixture("approval-transaction-cases.json");
    let base = cases.iter().find(|case| case.text.is_some() && case.network == "testnet").unwrap().clone();
    let account = base.account.clone();
    let destination = base.outputs[0].lock.clone();
    let other = ScriptJson { code_hash: format!("0x{}", "ee".repeat(32)), hash_type: "type".into(), args: format!("0x{}", "ee".repeat(20)) };
    let udt = |byte: &str| ScriptJson { code_hash: format!("0x{}", "5d".repeat(32)), hash_type: "type".into(), args: format!("0x{}", byte.repeat(32)) };
    let amount = |value: u128| format!("0x{}", hex::encode(value.to_le_bytes()));
    let input = |lock: &ScriptJson, type_: Option<ScriptJson>, data: String, capacity: u64| InputJson { lock: lock.clone(), type_, data, capacity: capacity.to_string() };
    let output = |type_: Option<ScriptJson>, data: String, capacity: u64| OutputJson { lock: destination.clone(), type_, data, capacity: capacity.to_string() };
    const CKB: u64 = 100_000_000;
    // The account holds two token cells of one token and plain CKB; the honest rescue moves each token cell as it is.
    let honest = TransactionCase {
        inputs: vec![
            input(&account, Some(udt("a1")), amount(1_000), 143 * CKB),
            input(&account, Some(udt("a1")), amount(25), 143 * CKB),
            input(&account, None, "0x".into(), 1_000 * CKB),
        ],
        outputs: vec![
            output(Some(udt("a1")), amount(25), 143 * CKB),
            output(Some(udt("a1")), amount(1_000), 143 * CKB),
            output(None, "0x".into(), 999 * CKB),
        ],
        ..base.clone()
    };
    let key = EvmKey::from_slice(&[7u8; 32]).unwrap();
    let address = evm_address(&key);
    let code_hash = [0x42u8; 32];
    let text = sdk_text(&honest, 2, 1_285 * CKB as u128, CKB as u128);
    assert!(text.contains("\nTokens: 2 token cells\n"));
    let argument = |case: &TransactionCase| exec_argument(&code_hash, &identity(&address, case), &unhex(&case.sighash), &evm_blob(0, &personal_sign(&key, text.as_bytes())));
    assert_eq!(run("evm-personal-sign", &honest, &argument(&honest)).0, 0);

    let mut attempts: Vec<(&str, TransactionCase)> = Vec::new();
    let mut changed = honest.clone();
    changed.outputs[1].data = amount(1);
    attempts.push(("a token cell changed, its tokens burned", changed));
    let mut retyped = honest.clone();
    retyped.outputs[1].type_ = Some(udt("b2"));
    attempts.push(("the same data under another type script", retyped));
    let mut left_out = honest.clone();
    left_out.outputs.remove(1);
    left_out.outputs.push(output(Some(udt("c3")), "0x".into(), 143 * CKB));
    attempts.push(("one token cell burned, CKB under the builder's own type script in its place", left_out));
    let mut burned = honest.clone();
    burned.outputs.remove(1);
    burned.outputs[1].capacity = (1_142 * CKB).to_string();
    attempts.push(("one token cell burned, its CKB moved as plain CKB", burned));
    let mut twice = honest.clone();
    twice.outputs[0].data = amount(1_000);
    attempts.push(("one token cell moved twice", twice));
    let mut foreign = honest.clone();
    foreign.inputs[0].lock = other.clone();
    attempts.push(("a token cell taken from someone else's input", foreign));
    let mut planted = honest.clone();
    planted.outputs[2].type_ = Some(udt("d4"));
    planted.outputs[2].data = "0x".into();
    attempts.push(("the plain CKB locked under the builder's own type script", planted));
    // Anyone can send the account a cell under their own type script. Moving it with the rescued CKB inside, and
    // leaving one of the account's token cells unspent, would show exactly the honest rescue's text.
    let mut trap = honest.clone();
    trap.inputs[1] = input(&account, Some(udt("e5")), "0x".into(), 143 * CKB);
    trap.outputs = vec![output(Some(udt("a1")), amount(1_000), 143 * CKB), output(Some(udt("e5")), "0x".into(), 1_142 * CKB)];
    attempts.push(("the rescued CKB put in a typed cell someone sent the account", trap));
    let mut richer = honest.clone();
    richer.outputs[0].capacity = (144 * CKB).to_string();
    richer.outputs[2].capacity = (998 * CKB).to_string();
    attempts.push(("a token cell given 1 CKB more than it held", richer));
    for (what, case) in &attempts {
        assert_eq!(run("evm-personal-sign", case, &argument(case)).0, 111, "{what}");
        let passkey = Passkey(SigningKey::from_slice(&[3u8; 32]).unwrap());
        let pubkey_hash = identity(&joyid_webauthn::blake160(&passkey.public_key()), case);
        let blob = passkey.blob(0, &text, 1024);
        assert_eq!(run("joyid-webauthn", case, &exec_argument(&[0x24u8; 32], &pubkey_hash, &unhex(&case.sighash), &blob)).0, 111, "{what}");
    }

    // Less CKB than a token cell held is fine (the rest arrives as plain CKB), and identical cells count together.
    let mut leaner = honest.clone();
    leaner.outputs[0].capacity = (142 * CKB).to_string();
    leaner.outputs[2].capacity = (1_000 * CKB).to_string();
    let mut swapped = honest.clone();
    swapped.inputs[1].data = amount(1_000);
    swapped.inputs[1].capacity = (150 * CKB).to_string();
    swapped.inputs[2].capacity = (993 * CKB).to_string();
    swapped.outputs[0] = output(Some(udt("a1")), amount(1_000), 150 * CKB);
    swapped.outputs[2].capacity = (992 * CKB).to_string();
    for case in [leaner, swapped] {
        let text = sdk_text(&case, 2, 1_285 * CKB as u128, CKB as u128);
        let signed = exec_argument(&code_hash, &identity(&address, &case), &unhex(&case.sighash), &evm_blob(0, &personal_sign(&key, text.as_bytes())));
        assert_eq!(run("evm-personal-sign", &case, &signed).0, 0);
    }
}

/// At most `MAX_TOKEN_CELLS` (256) token cells: 256 of the account's own are moved, 257 are refused (111), by
/// both verifiers.
#[test]
fn moves_at_most_256_token_cells() {
    let cases: Vec<TransactionCase> = fixture("approval-transaction-cases.json");
    let base = cases.iter().find(|case| case.text.is_some() && case.network == "testnet").unwrap().clone();
    let key = EvmKey::from_slice(&[7u8; 32]).unwrap();
    let address = evm_address(&key);
    const CKB: u64 = 100_000_000;
    for (count, expected) in [(100, 0), (keyway_approval::MAX_TOKEN_CELLS, 0), (keyway_approval::MAX_TOKEN_CELLS + 1, 111)] {
        let type_ = |at: usize| ScriptJson { code_hash: format!("0x{}", "5d".repeat(32)), hash_type: "type".into(), args: format!("0x{:064x}", at) };
        let mut case = base.clone();
        case.inputs = (0..count).map(|at| InputJson { lock: base.account.clone(), type_: Some(type_(at)), data: "0x".into(), capacity: (150 * CKB).to_string() }).collect();
        case.inputs.push(InputJson { lock: base.account.clone(), type_: None, data: "0x".into(), capacity: CKB.to_string() });
        case.outputs = (0..count).map(|at| OutputJson { lock: base.outputs[0].lock.clone(), type_: Some(type_(at)), data: "0x".into(), capacity: (150 * CKB).to_string() }).collect();
        let text = sdk_text(&case, count as u64, (count as u128) * 150 * CKB as u128, CKB as u128);
        let argument = exec_argument(&[0x42u8; 32], &identity(&address, &case), &unhex(&case.sighash), &evm_blob(0, &personal_sign(&key, text.as_bytes())));
        let (code, cycles) = run("evm-personal-sign", &case, &argument);
        assert_eq!(code, expected, "{count} token cells, EVM");
        let passkey = Passkey(SigningKey::from_slice(&[3u8; 32]).unwrap());
        let pubkey_hash = identity(&joyid_webauthn::blake160(&passkey.public_key()), &case);
        let blob = passkey.blob(0, &text, 1024);
        let (webauthn_code, webauthn_cycles) = run("joyid-webauthn", &case, &exec_argument(&[0x24u8; 32], &pubkey_hash, &unhex(&case.sighash), &blob));
        assert_eq!(webauthn_code, expected, "{count} token cells, WebAuthn");
        println!("{count} token cells: EVM exit {code}, {cycles} cycles; WebAuthn exit {webauthn_code}, {webauthn_cycles} cycles");
    }
}

/// The account's salt: the AdminList type hash at args[22..54] of its Omnilock (the case's account lock).
fn salt(case: &TransactionCase) -> [u8; 32] {
    keyway_approval::account_salt(&unhex(&case.account.args)).unwrap()
}

/// The identity's pubkey hash for a backup id in this case's account: blake160(id ‖ salt).
fn identity(id: &[u8; 20], case: &TransactionCase) -> [u8; 20] {
    keyway_approval::salted_id(id, &salt(case))
}

/// The case with the account's lock (wherever it appears) given other args.
fn with_account_args(case: &TransactionCase, args: &[u8]) -> TransactionCase {
    let mut changed = case.clone();
    let account = case.account.args.clone();
    let args = format!("0x{}", hex::encode(args));
    for lock in changed.inputs.iter_mut().map(|input| &mut input.lock).chain(changed.outputs.iter_mut().map(|output| &mut output.lock)) {
        if lock.args == account && lock.code_hash == case.account.code_hash {
            lock.args = args.clone();
        }
    }
    changed.account.args = args;
    changed
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
        let (code, cycles) = run("evm-personal-sign", case, &exec_argument(&code_hash, &identity(&address, case), &sighash, &signature));
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
    let pubkey_hash = identity(&address, &case);
    let argument = |text: &str, network: u8| exec_argument(&code_hash, &pubkey_hash, &sighash, &evm_blob(network, &personal_sign(&key, text.as_bytes())));
    assert_eq!(run("evm-personal-sign", &case, &argument(&text, 0)).0, 0);

    let mut low_v = personal_sign(&key, text.as_bytes());
    low_v[64] -= 27;
    assert_eq!(run("evm-personal-sign", &case, &exec_argument(&code_hash, &pubkey_hash, &sighash, &evm_blob(0, &low_v))).0, 0);

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
    let foreign = exec_argument(&code_hash, &pubkey_hash, &sighash, &evm_blob(0, &personal_sign(&other_key, text.as_bytes())));
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
    let pubkey_hash = identity(&joyid_webauthn::blake160(&passkey.public_key()), &cases[0]);
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
    let salt = [0x5au8; 32];
    let pubkey_hash = keyway_approval::salted_id(&joyid_webauthn::blake160(&passkey.public_key()), &salt);
    let evm_hash = keyway_approval::salted_id(&address, &salt);
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
            let argument = exec_argument(&[0; 32], &evm_hash, &msg, &blob);
            let ok = evm_personal_sign::parse_argument(argument.as_bytes()).and_then(|parsed| evm_personal_sign::verify(&parsed, &salt, text.as_bytes())).is_ok();
            if ok {
                // Only v's alternative encodings (0/1 for 27/28) may still verify.
                assert_eq!(blob[..66], evm[..66]);
                accepted += 1;
            }
        } else if joyid_webauthn::verify(&pubkey_hash, &salt, text.as_bytes(), &blob).is_ok() {
            // Bytes outside what is checked: the signCount, the clientDataJSON fields other than type and
            // challenge are signed, so only the network byte (same prefix) or nothing may differ.
            assert_eq!(blob, webauthn);
            accepted += 1;
        }
    }
    println!("mutations: 40000, accepted unchanged signatures: {accepted}");
}

/// A backup's identity is salted with the account's AdminList type hash, read by the verifier from the running
/// Omnilock's args: the same EVM address or passkey has unrelated identities in two accounts, a signature with
/// account A's identity is refused when the verifier runs for account B, the bare (unsalted) id is refused, and
/// a lock that isn't a KeyWay account's administrator-mode Omnilock gives no salt (114).
#[test]
fn identities_are_salted_per_account() {
    let cases: Vec<TransactionCase> = fixture("approval-transaction-cases.json");
    let a = cases.iter().find(|case| case.text.is_some() && case.network == "testnet").unwrap().clone();
    let mut b_args = unhex(&a.account.args);
    for byte in &mut b_args[22..] {
        *byte ^= 0xa5;
    }
    let b = with_account_args(&a, &b_args);
    assert_ne!(salt(&a), salt(&b));
    let sighash = unhex(&a.sighash);
    let text = a.text.clone().unwrap();

    let key = EvmKey::from_slice(&[7u8; 32]).unwrap();
    let address = evm_address(&key);
    let evm_code = [0x42u8; 32];
    let signature = evm_blob(0, &personal_sign(&key, text.as_bytes()));
    assert_ne!(identity(&address, &a), identity(&address, &b));
    assert_ne!(identity(&address, &a), address);
    let for_a = exec_argument(&evm_code, &identity(&address, &a), &sighash, &signature);
    let for_b = exec_argument(&evm_code, &identity(&address, &b), &sighash, &signature);
    assert_eq!(run("evm-personal-sign", &a, &for_a).0, 0);
    assert_eq!(run("evm-personal-sign", &b, &for_b).0, 0);
    assert_eq!(run("evm-personal-sign", &b, &for_a).0, 101);
    assert_eq!(run("evm-personal-sign", &a, &for_b).0, 101);
    assert_eq!(run("evm-personal-sign", &a, &exec_argument(&evm_code, &address, &sighash, &signature)).0, 101);

    let passkey = Passkey(SigningKey::from_slice(&[3u8; 32]).unwrap());
    let id = joyid_webauthn::blake160(&passkey.public_key());
    let webauthn_code = [0x24u8; 32];
    let blob = passkey.blob(0, &text, 1024);
    assert_ne!(identity(&id, &a), identity(&id, &b));
    let for_a = exec_argument(&webauthn_code, &identity(&id, &a), &sighash, &blob);
    let for_b = exec_argument(&webauthn_code, &identity(&id, &b), &sighash, &blob);
    assert_eq!(run("joyid-webauthn", &a, &for_a).0, 0);
    assert_eq!(run("joyid-webauthn", &b, &for_b).0, 0);
    assert_eq!(run("joyid-webauthn", &b, &for_a).0, 101);
    assert_eq!(run("joyid-webauthn", &a, &for_b).0, 101);
    assert_eq!(run("joyid-webauthn", &a, &exec_argument(&webauthn_code, &id, &sighash, &blob)).0, 101);

    // Not a KeyWay account's lock: owner mode only, other Omnilock flags, or args of another length.
    let evm = exec_argument(&evm_code, &identity(&address, &a), &sighash, &signature);
    let webauthn = exec_argument(&webauthn_code, &identity(&id, &a), &sighash, &blob);
    let args = unhex(&a.account.args);
    let mut flags = args.clone();
    for flag in [0x00u8, 0x03, 0x09, 0x81] {
        flags[21] = flag;
        assert_eq!(run("evm-personal-sign", &with_account_args(&a, &flags), &evm).0, 114);
        assert_eq!(run("joyid-webauthn", &with_account_args(&a, &flags), &webauthn).0, 114);
    }
    for args in [args[..53].to_vec(), [args.clone(), vec![0]].concat(), args[..22].to_vec(), Vec::new(), [args.clone(), vec![0; 300]].concat()] {
        assert_eq!(run("evm-personal-sign", &with_account_args(&a, &args), &evm).0, 114);
        assert_eq!(run("joyid-webauthn", &with_account_args(&a, &args), &webauthn).0, 114);
    }
}

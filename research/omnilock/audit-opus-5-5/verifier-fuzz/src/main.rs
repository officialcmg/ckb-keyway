//! Host-side adversarial checks of contracts/joyid-webauthn (the same library the deployed binary is built from).
//! Run: cargo run --release. Prints each check and panics on the first property that fails. Updated for the
//! version 2 blob (a network byte after the version) and the readable approval text as the challenge; on chain the
//! binary rebuilds that text from the transaction, here it is given.
use joyid_webauthn::*;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sha2::{Digest, Sha256};
use p256::elliptic_curve::PrimeField;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 }
    fn below(&mut self, n: usize) -> usize { (self.next() % n as u64) as usize }
}

fn b64(input: &[u8]) -> String {
    let mut out = vec![0u8; (input.len() * 4 + 2) / 3];
    base64url(input, &mut out);
    String::from_utf8(out).unwrap()
}

fn blob(key: &SigningKey, auth: &[u8], client: &[u8], pad: usize) -> Vec<u8> {
    let digest = Sha256::new().chain_update(auth).chain_update(Sha256::digest(client)).finalize();
    let sig: Signature = key.sign_prehash(&digest).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let mut out = vec![SIGNATURE_VERSION, 0];
    out.extend_from_slice(&point.as_bytes()[1..]);
    out.extend_from_slice(&sig.to_bytes());
    out.extend_from_slice(&(auth.len() as u16).to_le_bytes());
    out.extend_from_slice(auth);
    out.extend_from_slice(&(client.len() as u16).to_le_bytes());
    out.extend_from_slice(client);
    out.resize(out.len() + pad, 0);
    out
}

fn main() {
    let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let pubkey = &key.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec();
    let pkh = blake160(pubkey);
    let approval = |sighash: &[u8; 32]| format!("KeyWay recovery\nMove everything to ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygfhutwy\nCKB: 100\nTokens: none\nFee: 0.00000765 CKB\nTransaction: 0x{}", sighash.iter().map(|x| format!("{x:02x}")).collect::<String>()).into_bytes();
    let msg = approval(&[0x5au8; 32]);
    let other = approval(&[0xa5u8; 32]);
    let challenge = b64(&msg);
    let auth = { let mut a = vec![0x11u8; 32]; a.extend_from_slice(&[0x05, 0, 0, 0, 0]); a };
    let good = format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://testnet.joyid.dev","crossOrigin":false}}"#);
    assert_eq!(verify(&pkh, &msg, &blob(&key, &auth, good.as_bytes(), 0)), Ok(()));
    assert_eq!(verify(&pkh, &other, &blob(&key, &auth, good.as_bytes(), 0)), Err(Error::Challenge));
    println!("control: a valid assertion verifies, and only for its own sighash");

    // Hand-written attempts to make a clientDataJSON whose "real" challenge (to a lenient parser) differs.
    let cases: Vec<(&str, String, Result<(), Error>)> = vec![
        ("duplicate challenge", format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","challenge":"x"}}"#), Err(Error::ClientDataJson)),
        ("duplicate via escape", format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","challenge":"x"}}"#), Err(Error::ClientDataJson)),
        ("challenge only nested", format!(r#"{{"type":"webauthn.get","x":{{"challenge":"{challenge}"}}}}"#), Err(Error::Challenge)),
        ("challenge in origin", format!(r#"{{"type":"webauthn.get","origin":"{challenge}"}}"#), Err(Error::Challenge)),
        ("trailing data", format!(r#"{}  {{}}"#, good), Err(Error::ClientDataJson)),
        ("BOM", format!("\u{feff}{good}"), Err(Error::ClientDataJson)),
        ("type missing", format!(r#"{{"challenge":"{challenge}"}}"#), Err(Error::Type)),
        ("type not a string", format!(r#"{{"type":["webauthn.get"],"challenge":"{challenge}"}}"#), Err(Error::Type)),
        ("webauthn.create", format!(r#"{{"type":"webauthn.create","challenge":"{challenge}"}}"#), Err(Error::Type)),
        ("NUL in key", format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\",\"a\u{0}\":1}}"), Err(Error::ClientDataJson)),
        ("lone surrogate", format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","a":"\ud800"}}"#), Err(Error::ClientDataJson)),
        ("depth 10", format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","a":[[[[[[[[[[1]]]]]]]]]]}}"#), Err(Error::ClientDataJson)),
        ("leading zero", format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","a":01}}"#), Err(Error::ClientDataJson)),
        ("escaped challenge", format!(r#"{{"type":"webauthn.get","challenge":"{}"}}"#, challenge.replace('A', "\\u0041")), Ok(())),
    ];
    for (name, json, expected) in cases {
        assert_eq!(check_client_data(json.as_bytes(), challenge.as_bytes()), expected, "{name}");
        println!("clientDataJSON {name}: {expected:?}");
    }

    // Blob framing: padding must be zero, lengths must fit, version 1, at most 1024 bytes.
    let base = blob(&key, &auth, good.as_bytes(), 100);
    assert_eq!(verify(&pkh, &msg, &base), Ok(()));
    let mut dirty = base.clone(); *dirty.last_mut().unwrap() = 1;
    assert_eq!(verify(&pkh, &msg, &dirty), Err(Error::Encoding));
    let mut long = base.clone(); long.resize(1025, 0);
    assert_eq!(verify(&pkh, &msg, &long), Err(Error::Encoding));
    let mut v1 = base.clone(); v1[0] = 1;
    assert_eq!(verify(&pkh, &msg, &v1), Err(Error::Encoding));
    // A shorter clientDataJSON length leaves non-zero bytes in the padding.
    let mut shorter = base.clone(); let at = 2 + 64 + 64 + 2 + auth.len(); shorter[at] -= 1;
    assert_eq!(verify(&pkh, &msg, &shorter), Err(Error::Encoding));
    // High s is accepted (malleable witness, same transaction hash); s = n - s.
    let mut high = base.clone();
    let s = p256::Scalar::from_repr(p256::FieldBytes::clone_from_slice(&high[98..130])).unwrap();
    high[98..130].copy_from_slice(&(-s).to_bytes());
    assert_eq!(verify(&pkh, &msg, &high), Ok(()));
    println!("blob framing: dirty padding, >1024, version, short length refused; high-s accepted (witness malleability only)");

    // The exec argument: hex case, field count, lengths.
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let run = |arg: &[u8]| parse_argument(arg).and_then(|parsed| verify(&parsed.pubkey_hash, &msg, parsed.signature()));
    let arg = format!("{}:02:{}:{}:{}", hex(&[0x24; 32]), hex(&pkh), hex(&[0x5au8; 32]), hex(&base));
    assert_eq!(run(arg.as_bytes()), Ok(()));
    assert!(matches!(run(format!("{arg}:00").as_bytes()), Err(Error::Args)));
    assert_eq!(run(arg.to_uppercase().as_bytes()), Ok(()));
    println!("exec argument: extra field refused, uppercase hex accepted (Omnilock emits lowercase)");

    // Random mutations of a valid blob: none may verify unless the bytes that are signed are unchanged.
    let mut rng = Rng(0x9e3779b97f4a7c15);
    let mut accepted_changed = 0;
    let mut runs = 0;
    for _ in 0..20_000 {
        let mut m = base.clone();
        for _ in 0..1 + rng.below(4) {
            let i = rng.below(m.len());
            m[i] = rng.next() as u8;
        }
        if m.len() > 10 && rng.below(4) == 0 { let n = rng.below(m.len()); m.truncate(n); }
        runs += 1;
        // The network byte only picks the prefix the chain writes into the text, which is given here.
        let network_only = m.len() == base.len() && m[1] <= 1 && m[0] == base[0] && m[2..] == base[2..];
        if verify(&pkh, &msg, &m).is_ok() && m != base && m != high && !network_only {
            // Dropping trailing zero padding keeps the same assertion; on chain the witness length (and so the
            // sighash) would change, so it can't be reused. Anything else accepted would be a forgery.
            let unpadded = base.len() - 100;
            let same_assertion = m.len() >= unpadded && m[..unpadded] == base[..unpadded] && m[unpadded..].iter().all(|&b| b == 0);
            if !same_assertion { accepted_changed += 1; println!("ACCEPTED forged blob len {}", m.len()); }
        }
    }
    assert_eq!(accepted_changed, 0);
    // Random clientDataJSON bytes around the valid one: never accepted, never a panic.
    for _ in 0..200_000 {
        let mut j = good.clone().into_bytes();
        for _ in 0..1 + rng.below(3) {
            let i = rng.below(j.len());
            match rng.below(3) { 0 => j[i] = rng.next() as u8, 1 => { j.insert(i, b"{}[]\",:\\ u0"[rng.below(11)]); } _ => { j.remove(i); } }
        }
        let _ = check_client_data(&j, challenge.as_bytes());
        runs += 1;
    }
    println!("{runs} random mutations: no panic, no mutated blob accepted");
}

//! KeyWay's WebAuthn (P-256) verifier for Omnilock exec identities (flag 0xFD).
//!
//! Omnilock execs this binary with one argument, the ckb-auth exec convention: lowercase hex fields
//! `code_hash:hash_type:pubkey_hash:msg:signature` joined by `:`. `msg` is the lock group's sighash_all and
//! `pubkey_hash` is the last 20 bytes of the identity's preimage. The signature is the blob described in
//! `parse_signature`. The binary exits 0 only when a passkey whose public key hashes to `pubkey_hash` made a
//! WebAuthn assertion whose challenge is KeyWay's readable approval for this transaction (`keyway_approval`),
//! rebuilt from the transaction itself, the way JoyID's sign-message page turns a text challenge into a
//! WebAuthn challenge (its UTF-8 bytes, base64url).
#![no_std]

use ecdsa::signature::hazmat::PrehashVerifier;
pub use keyway_approval::{ApprovalError, Network, MAX_TEXT};
use p256::NistP256;
use sha2::{Digest, Sha256};

/// Omnilock reads at most this many signature bytes from the witness.
pub const MAX_SIGNATURE: usize = 1024;
pub const SIGNATURE_VERSION: u8 = 2;
pub const PUBLIC_KEY: usize = 64;
pub const RS: usize = 64;
/// rpIdHash (32) ‖ flags (1) ‖ signCount (4).
pub const MIN_AUTH_DATA: usize = 37;
/// version ‖ network ‖ public key ‖ r ‖ s ‖ authenticatorData length.
const HEADER: usize = 2 + PUBLIC_KEY + RS + 2;
/// The base64url form of the longest approval text.
pub const MAX_CHALLENGE: usize = (MAX_TEXT * 4).div_ceil(3);
const FLAG_USER_PRESENT: u8 = 0x01;
const MAX_KEYS: usize = 32;
const MAX_KEY: usize = 256;
const MAX_DEPTH: usize = 8;

/// Exit codes. Omnilock's own codes stay below 100; the approval's are 110–113.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i8)]
pub enum Error {
    /// The exec argument isn't five hex fields of the expected lengths.
    Args = 100,
    /// blake160(public key) isn't the identity's pubkey hash.
    PublicKeyHash = 101,
    /// The signature blob's version, lengths or zero padding are wrong.
    Encoding = 102,
    /// authenticatorData is shorter than 37 bytes.
    AuthData = 103,
    /// authenticatorData doesn't have the user-presence flag.
    UserPresence = 104,
    /// clientDataJSON isn't a well-formed JSON object with unique keys within the limits.
    ClientDataJson = 105,
    /// clientDataJSON's top-level "type" isn't "webauthn.get".
    Type = 106,
    /// clientDataJSON's top-level "challenge" isn't the approval for this transaction.
    Challenge = 107,
    /// The public key isn't a point on P-256.
    PublicKey = 108,
    /// r ‖ s is out of range or doesn't verify.
    Signature = 109,
    Network = 110,
    Shape = 111,
    TooLong = 112,
    Syscall = 113,
}

impl From<ApprovalError> for Error {
    fn from(error: ApprovalError) -> Self {
        match error {
            ApprovalError::Network => Error::Network,
            ApprovalError::Shape => Error::Shape,
            ApprovalError::TooLong => Error::TooLong,
            ApprovalError::Syscall => Error::Syscall,
        }
    }
}

/// The signature blob's parts.
pub struct Assertion<'a> {
    pub network: Network,
    pub public_key: &'a [u8],
    pub rs: &'a [u8],
    pub auth_data: &'a [u8],
    pub client_data_json: &'a [u8],
}

/// Omnilock's exec argument, decoded.
pub struct Argument {
    pub pubkey_hash: [u8; 20],
    pub msg: [u8; 32],
    signature: [u8; MAX_SIGNATURE],
    signature_length: usize,
}

impl Argument {
    pub fn signature(&self) -> &[u8] {
        &self.signature[..self.signature_length]
    }
}

/// Decodes Omnilock's exec argument (without its trailing NUL).
pub fn parse_argument(argument: &[u8]) -> Result<Argument, Error> {
    let mut fields = argument.split(|&byte| byte == b':');
    let mut code_hash = [0u8; 32];
    let mut hash_type = [0u8; 1];
    let mut parsed = Argument { pubkey_hash: [0; 20], msg: [0; 32], signature: [0; MAX_SIGNATURE], signature_length: 0 };
    decode_exact(fields.next(), &mut code_hash)?;
    decode_exact(fields.next(), &mut hash_type)?;
    decode_exact(fields.next(), &mut parsed.pubkey_hash)?;
    decode_exact(fields.next(), &mut parsed.msg)?;
    parsed.signature_length = decode_hex(fields.next().ok_or(Error::Args)?, &mut parsed.signature)?;
    if fields.next().is_some() {
        return Err(Error::Args);
    }
    Ok(parsed)
}

/// The network byte of a signature blob, which picks the address prefix in the approval text.
pub fn signature_network(signature: &[u8]) -> Result<Network, Error> {
    if signature.len() < HEADER || signature[0] != SIGNATURE_VERSION {
        return Err(Error::Encoding);
    }
    Ok(Network::from_byte(signature[1])?)
}

/// The whole check against the approval `text`: key binding, blob, authenticatorData, clientDataJSON, then
/// the P-256 signature.
pub fn verify(pubkey_hash: &[u8; 20], text: &[u8], signature: &[u8]) -> Result<(), Error> {
    let assertion = parse_signature(signature)?;
    if blake160(assertion.public_key) != *pubkey_hash {
        return Err(Error::PublicKeyHash);
    }
    check_auth_data(assertion.auth_data)?;
    if text.len() > MAX_TEXT {
        return Err(Error::TooLong);
    }
    let mut challenge = [0u8; MAX_CHALLENGE];
    let length = text.len().div_ceil(3) * 4 - (3 - text.len() % 3) % 3;
    base64url(text, &mut challenge[..length]);
    check_client_data(assertion.client_data_json, &challenge[..length])?;
    verify_assertion(&assertion)
}

/// `version 2 (1) ‖ network (1: 0 testnet, 1 mainnet) ‖ public key X ‖ Y (64) ‖ r ‖ s (64) ‖ authenticatorData
/// length (u16 LE) ‖ authenticatorData ‖ clientDataJSON length (u16 LE) ‖ clientDataJSON ‖ zero padding`, at most
/// 1024 bytes. The padding lets the
/// signer fix the witness length before the sighash is known; every padding byte must be zero.
pub fn parse_signature(signature: &[u8]) -> Result<Assertion<'_>, Error> {
    if signature.len() > MAX_SIGNATURE || signature.len() < HEADER || signature[0] != SIGNATURE_VERSION {
        return Err(Error::Encoding);
    }
    let auth_length = u16::from_le_bytes([signature[HEADER - 2], signature[HEADER - 1]]) as usize;
    let auth_end = HEADER + auth_length;
    if auth_end + 2 > signature.len() {
        return Err(Error::Encoding);
    }
    let client_length = u16::from_le_bytes([signature[auth_end], signature[auth_end + 1]]) as usize;
    let client_end = auth_end + 2 + client_length;
    if client_end > signature.len() || signature[client_end..].iter().any(|&byte| byte != 0) {
        return Err(Error::Encoding);
    }
    Ok(Assertion {
        network: Network::from_byte(signature[1])?,
        public_key: &signature[2..2 + PUBLIC_KEY],
        rs: &signature[2 + PUBLIC_KEY..2 + PUBLIC_KEY + RS],
        auth_data: &signature[HEADER..auth_end],
        client_data_json: &signature[auth_end + 2..client_end],
    })
}

/// At least rpIdHash, flags and signCount, with the user-presence flag. User verification and the rpIdHash
/// aren't checked: the passkey only ever signs for JoyID's relying party, and JoyID's page, not the caller,
/// decides whether to ask for user verification.
pub fn check_auth_data(auth_data: &[u8]) -> Result<(), Error> {
    if auth_data.len() < MIN_AUTH_DATA {
        return Err(Error::AuthData);
    }
    if auth_data[32] & FLAG_USER_PRESENT == 0 {
        return Err(Error::UserPresence);
    }
    Ok(())
}

/// clientDataJSON must be one JSON object (RFC 8259, UTF-8, nothing before or after it) whose top-level keys are
/// unique, whose "type" is the string "webauthn.get" and whose "challenge" is exactly `challenge`. Keys and
/// strings are compared after unescaping, so an escaped key is still the same key.
pub fn check_client_data(json: &[u8], challenge: &[u8]) -> Result<(), Error> {
    if core::str::from_utf8(json).is_err() {
        return Err(Error::ClientDataJson);
    }
    let mut parser = Parser { input: json, at: 0 };
    let mut keys = [[0u8; MAX_KEY]; MAX_KEYS];
    let mut key_lengths = [0usize; MAX_KEYS];
    let mut count = 0;
    let mut type_ok = None;
    let mut challenge_ok = None;
    parser.expect(b'{')?;
    parser.whitespace();
    if parser.peek() == Some(b'}') {
        parser.at += 1;
    } else {
        loop {
            parser.whitespace();
            if count == MAX_KEYS {
                return Err(Error::ClientDataJson);
            }
            let key_length = parser.string(Some(&mut keys[count][..]))?;
            if (0..count).any(|index| key_lengths[index] == key_length && keys[index][..key_length] == keys[count][..key_length]) {
                return Err(Error::ClientDataJson);
            }
            key_lengths[count] = key_length;
            let key = &keys[count][..key_length];
            count += 1;
            parser.whitespace();
            parser.expect(b':')?;
            parser.whitespace();
            if key == b"type" || key == b"challenge" {
                let matches = if parser.peek() == Some(b'"') {
                    let mut value = [0u8; MAX_CHALLENGE];
                    let length = parser.string(Some(&mut value))?;
                    let expected: &[u8] = if key == b"type" { b"webauthn.get" } else { challenge };
                    &value[..length] == expected
                } else {
                    parser.value(0)?;
                    false
                };
                if key == b"type" { type_ok = Some(matches) } else { challenge_ok = Some(matches) }
            } else {
                parser.value(0)?;
            }
            parser.whitespace();
            match parser.next() {
                Some(b',') => continue,
                Some(b'}') => break,
                _ => return Err(Error::ClientDataJson),
            }
        }
    }
    if parser.at != json.len() {
        return Err(Error::ClientDataJson);
    }
    match (type_ok, challenge_ok) {
        (Some(true), Some(true)) => Ok(()),
        (Some(true), _) => Err(Error::Challenge),
        _ => Err(Error::Type),
    }
}

/// ECDSA P-256 over sha256(authenticatorData ‖ sha256(clientDataJSON)).
pub fn verify_assertion(assertion: &Assertion) -> Result<(), Error> {
    let client_hash = Sha256::digest(assertion.client_data_json);
    let digest = Sha256::new().chain_update(assertion.auth_data).chain_update(client_hash).finalize();
    verify_p256(assertion.public_key, assertion.rs, digest.as_ref())
}

/// ECDSA P-256 of a 32-byte digest by a 64-byte X ‖ Y public key. WebAuthn signatures aren't normalised, so a
/// high s is accepted, as WebCrypto does.
pub fn verify_p256(public_key: &[u8], rs: &[u8], digest: &[u8]) -> Result<(), Error> {
    if public_key.len() != PUBLIC_KEY {
        return Err(Error::PublicKey);
    }
    let mut sec1 = [4u8; 1 + PUBLIC_KEY];
    sec1[1..].copy_from_slice(public_key);
    let key = ecdsa::VerifyingKey::<NistP256>::from_sec1_bytes(&sec1).map_err(|_| Error::PublicKey)?;
    let signature = ecdsa::Signature::<NistP256>::from_slice(rs).map_err(|_| Error::Signature)?;
    key.verify_prehash(digest, &signature).map_err(|_| Error::Signature)
}

/// The first 20 bytes of CKB's blake2b-256 (personalisation "ckb-default-hash").
pub fn blake160(data: &[u8]) -> [u8; 20] {
    let mut hasher = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    hasher.update(data);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    let mut short = [0u8; 20];
    short.copy_from_slice(&hash[..20]);
    short
}

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url; `out` must be exactly the encoded length.
pub fn base64url(input: &[u8], out: &mut [u8]) {
    let mut at = 0;
    for chunk in input.chunks(3) {
        let bits = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for index in 0..chunk.len() + 1 {
            out[at] = BASE64URL[(bits >> (18 - 6 * index) & 63) as usize];
            at += 1;
        }
    }
}

fn decode_exact(field: Option<&[u8]>, out: &mut [u8]) -> Result<(), Error> {
    if decode_hex(field.ok_or(Error::Args)?, out)? != out.len() {
        return Err(Error::Args);
    }
    Ok(())
}

pub fn decode_hex(field: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if field.len() % 2 != 0 || field.len() / 2 > out.len() {
        return Err(Error::Args);
    }
    for (index, pair) in field.chunks(2).enumerate() {
        out[index] = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Ok(field.len() / 2)
}

fn nibble(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::Args),
    }
}

fn is_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// A strict RFC 8259 parser over UTF-8 input that only keeps what the checks need.
struct Parser<'a> {
    input: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.at).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.at += 1;
        Some(byte)
    }

    fn expect(&mut self, byte: u8) -> Result<(), Error> {
        if self.next() != Some(byte) {
            return Err(Error::ClientDataJson);
        }
        Ok(())
    }

    fn whitespace(&mut self) {
        while self.peek().is_some_and(is_whitespace) {
            self.at += 1;
        }
    }

    /// A string, unescaped into `out` when given (an error if it doesn't fit). Returns the unescaped length.
    fn string(&mut self, mut out: Option<&mut [u8]>) -> Result<usize, Error> {
        self.expect(b'"')?;
        let mut length = 0;
        let mut push = |bytes: &[u8], out: &mut Option<&mut [u8]>| -> Result<(), Error> {
            if let Some(out) = out {
                if length + bytes.len() > out.len() {
                    return Err(Error::ClientDataJson);
                }
                out[length..length + bytes.len()].copy_from_slice(bytes);
            }
            length += bytes.len();
            Ok(())
        };
        loop {
            let byte = self.next().ok_or(Error::ClientDataJson)?;
            match byte {
                b'"' => break,
                0..=0x1f => return Err(Error::ClientDataJson),
                b'\\' => {
                    let escaped = match self.next().ok_or(Error::ClientDataJson)? {
                        b'"' => b'"',
                        b'\\' => b'\\',
                        b'/' => b'/',
                        b'b' => 8,
                        b'f' => 12,
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'u' => {
                            let mut code = self.code_unit()?;
                            if (0xdc00..0xe000).contains(&code) {
                                return Err(Error::ClientDataJson);
                            }
                            if (0xd800..0xdc00).contains(&code) {
                                self.expect(b'\\')?;
                                self.expect(b'u')?;
                                let low = self.code_unit()?;
                                if !(0xdc00..0xe000).contains(&low) {
                                    return Err(Error::ClientDataJson);
                                }
                                code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                            }
                            let character = char::from_u32(code).ok_or(Error::ClientDataJson)?;
                            let mut buffer = [0u8; 4];
                            push(character.encode_utf8(&mut buffer).as_bytes(), &mut out)?;
                            continue;
                        }
                        _ => return Err(Error::ClientDataJson),
                    };
                    push(&[escaped], &mut out)?;
                }
                _ => push(&[byte], &mut out)?,
            }
        }
        Ok(length)
    }

    fn code_unit(&mut self) -> Result<u32, Error> {
        let mut code = 0u32;
        for _ in 0..4 {
            let digit = nibble(self.next().ok_or(Error::ClientDataJson)?).map_err(|_| Error::ClientDataJson)?;
            code = code << 4 | digit as u32;
        }
        Ok(code)
    }

    fn value(&mut self, depth: usize) -> Result<(), Error> {
        if depth > MAX_DEPTH {
            return Err(Error::ClientDataJson);
        }
        match self.peek().ok_or(Error::ClientDataJson)? {
            b'"' => self.string(None).map(|_| ()),
            b'{' => self.container(b'}', depth, true),
            b'[' => self.container(b']', depth, false),
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(Error::ClientDataJson),
        }
    }

    /// A nested object or array; nested keys may repeat, only the top level's matter.
    fn container(&mut self, close: u8, depth: usize, object: bool) -> Result<(), Error> {
        self.at += 1;
        self.whitespace();
        if self.peek() == Some(close) {
            self.at += 1;
            return Ok(());
        }
        loop {
            self.whitespace();
            if object {
                self.string(None)?;
                self.whitespace();
                self.expect(b':')?;
                self.whitespace();
            }
            self.value(depth + 1)?;
            self.whitespace();
            match self.next() {
                Some(b',') => continue,
                Some(byte) if byte == close => return Ok(()),
                _ => return Err(Error::ClientDataJson),
            }
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), Error> {
        if !self.input[self.at..].starts_with(word) {
            return Err(Error::ClientDataJson);
        }
        self.at += word.len();
        Ok(())
    }

    fn number(&mut self) -> Result<(), Error> {
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.next() {
            Some(b'0') => {}
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(Error::ClientDataJson),
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            self.required_digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            self.required_digits()?;
        }
        Ok(())
    }

    fn digits(&mut self) {
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.at += 1;
        }
    }

    fn required_digits(&mut self) -> Result<(), Error> {
        if !self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            return Err(Error::ClientDataJson);
        }
        self.digits();
        Ok(())
    }
}

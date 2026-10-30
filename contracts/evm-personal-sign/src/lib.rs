//! KeyWay's EVM wallet verifier for Omnilock exec identities (flag 0xFD).
//!
//! Omnilock execs this binary with one argument, the ckb-auth exec convention: lowercase hex fields
//! `code_hash:hash_type:pubkey_hash:msg:signature` joined by `:`. `msg` is the lock group's sighash_all and
//! `pubkey_hash` is the last 20 bytes of the identity's preimage, here the EVM address. The binary exits 0 only
//! when that address personal_signed (EIP-191) KeyWay's readable approval for this transaction
//! (`keyway_approval`), which the binary rebuilds from the transaction itself.
#![no_std]

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
pub use keyway_approval::{ApprovalError, Network, MAX_TEXT};
use sha3::{Digest, Keccak256};

pub const SIGNATURE_VERSION: u8 = 1;
/// version ‖ network ‖ r ‖ s ‖ v.
pub const SIGNATURE_LENGTH: usize = 1 + 1 + 65;

/// Exit codes. Omnilock's own codes stay below 100; the approval's are 110–113.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i8)]
pub enum Error {
    /// The exec argument isn't five hex fields of the expected lengths.
    Args = 100,
    /// The signature doesn't recover to the identity's address.
    Address = 101,
    /// The signature's version, length or v is wrong.
    Encoding = 102,
    /// r ‖ s is out of range or recovers no key.
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

/// The parsed exec argument.
pub struct Argument {
    pub address: [u8; 20],
    pub msg: [u8; 32],
    pub network: Network,
    /// r ‖ s ‖ recovery id 0 or 1.
    pub signature: [u8; 65],
}

/// Parses Omnilock's exec argument (without its trailing NUL) and the 67-byte signature
/// `version (1) ‖ network (0 testnet, 1 mainnet) ‖ r ‖ s ‖ v`, with v 27/28 or 0/1.
pub fn parse_argument(argument: &[u8]) -> Result<Argument, Error> {
    let mut fields = argument.split(|&byte| byte == b':');
    let mut code_hash = [0u8; 32];
    let mut hash_type = [0u8; 1];
    let mut address = [0u8; 20];
    let mut msg = [0u8; 32];
    let mut blob = [0u8; SIGNATURE_LENGTH];
    decode_exact(fields.next(), &mut code_hash)?;
    decode_exact(fields.next(), &mut hash_type)?;
    decode_exact(fields.next(), &mut address)?;
    decode_exact(fields.next(), &mut msg)?;
    let field = fields.next().ok_or(Error::Args)?;
    if fields.next().is_some() {
        return Err(Error::Args);
    }
    if field.len() != 2 * SIGNATURE_LENGTH {
        return Err(Error::Encoding);
    }
    decode_hex(field, &mut blob)?;
    if blob[0] != SIGNATURE_VERSION {
        return Err(Error::Encoding);
    }
    let network = Network::from_byte(blob[1])?;
    let mut signature = [0u8; 65];
    signature.copy_from_slice(&blob[2..]);
    signature[64] = match signature[64] {
        0 | 27 => 0,
        1 | 28 => 1,
        _ => return Err(Error::Encoding),
    };
    Ok(Argument { address, msg, network, signature })
}

/// keccak256("\x19Ethereum Signed Message:\n" ‖ decimal length ‖ text).
pub fn personal_sign_digest(text: &[u8]) -> [u8; 32] {
    let mut length = [0u8; 20];
    let mut at = length.len();
    let mut rest = text.len();
    loop {
        at -= 1;
        length[at] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    Keccak256::new().chain_update(b"\x19Ethereum Signed Message:\n").chain_update(&length[at..]).chain_update(text).finalize().into()
}

/// The 20-byte address whose key made `signature` over `digest`. A high s is accepted, as `ecrecover` does.
pub fn recover_address(digest: &[u8; 32], signature: &[u8; 65]) -> Result<[u8; 20], Error> {
    let mut parsed = Signature::from_slice(&signature[..64]).map_err(|_| Error::Signature)?;
    let mut recovery = signature[64];
    if let Some(normalized) = parsed.normalize_s() {
        parsed = normalized;
        recovery ^= 1;
    }
    let id = RecoveryId::from_byte(recovery).ok_or(Error::Signature)?;
    let key = VerifyingKey::recover_from_prehash(digest, &parsed, id).map_err(|_| Error::Signature)?;
    let point = key.to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Ok(address)
}

/// Checks the signature over `text` (the approval the transaction is rebuilt into) against the address.
pub fn verify(argument: &Argument, text: &[u8]) -> Result<(), Error> {
    if recover_address(&personal_sign_digest(text), &argument.signature)? != argument.address {
        return Err(Error::Address);
    }
    Ok(())
}

fn decode_exact(field: Option<&[u8]>, out: &mut [u8]) -> Result<(), Error> {
    let field = field.ok_or(Error::Args)?;
    if field.len() != 2 * out.len() {
        return Err(Error::Args);
    }
    decode_hex(field, out)
}

fn decode_hex(field: &[u8], out: &mut [u8]) -> Result<(), Error> {
    for (index, pair) in field.chunks(2).enumerate() {
        out[index] = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Ok(())
}

fn nibble(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::Args),
    }
}

//! The text a KeyWay recovery backup signs to approve a rescue, shared by both of KeyWay's Omnilock exec
//! verifiers so they rebuild exactly the same bytes:
//!
//! ```text
//! KeyWay recovery
//! Move everything to ckt1…
//! CKB: 12,345.678
//! Tokens: 2 token cells
//! Fee: 0.00001234 CKB
//! Transaction: 0x<sighash in 64 lowercase hex digits>
//! ```
//!
//! Lines are joined by `\n`, with no newline at the end. The address is the destination lock in CKB's full
//! address format (bech32m, payload `0x00 ‖ code_hash ‖ hash_type ‖ args`), with the prefix `ckt` on testnet and
//! `ckb` on mainnet. `CKB` is the total capacity of the outputs, which is everything the destination receives,
//! including the CKB held by token cells. `Tokens` counts the outputs with a type script: `none`, `1 token cell`
//! or `N token cells`. `Fee` is the inputs' capacity less the outputs'. Amounts are in CKB with thousands
//! separators and up to 8 decimals, trailing zeros dropped. The sighash line binds the signature to one
//! transaction; the other lines are what the person reads.
//!
//! On chain, `chain::rescue_text` reads those values from the transaction being verified and refuses any
//! transaction that isn't a rescue: at least one output, every output locked by the same lock, which isn't the
//! account's own (the running script), and no output carrying data without a type script.
#![no_std]

#[cfg(target_arch = "riscv64")]
pub mod chain;

/// The longest text the verifiers build. A JoyID backup signs it as a WebAuthn challenge, which must fit in
/// Omnilock's 1024-byte signature with the rest of the assertion, so the destination's address is limited.
pub const MAX_TEXT: usize = 480;
pub const HEADER: &[u8] = b"KeyWay recovery\nMove everything to ";

/// Exit codes shared by the verifiers, after their own (100–109).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i8)]
pub enum ApprovalError {
    /// The network byte isn't 0 (testnet) or 1 (mainnet).
    Network = 110,
    /// The transaction isn't a rescue: no outputs, outputs to more than one lock or to the account itself,
    /// data without a type script, or outputs above the inputs.
    Shape = 111,
    /// The destination's address doesn't fit the text's limit.
    TooLong = 112,
    /// A syscall failed unexpectedly.
    Syscall = 113,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Testnet,
    Mainnet,
}

impl Network {
    pub fn from_byte(byte: u8) -> Result<Network, ApprovalError> {
        match byte {
            0 => Ok(Network::Testnet),
            1 => Ok(Network::Mainnet),
            _ => Err(ApprovalError::Network),
        }
    }

    pub fn prefix(self) -> &'static [u8] {
        match self {
            Network::Testnet => b"ckt",
            Network::Mainnet => b"ckb",
        }
    }
}

/// A lock script as the address encodes it. `hash_type` is the molecule byte (data 0, type 1, data1 2, data2 4).
pub struct Destination<'a> {
    pub code_hash: &'a [u8; 32],
    pub hash_type: u8,
    pub args: &'a [u8],
}

/// What a rescue moves, as the text states it.
pub struct Rescue<'a> {
    pub destination: Destination<'a>,
    /// Shannons in all outputs.
    pub ckb: u128,
    /// Outputs with a type script.
    pub token_cells: u64,
    /// Shannons of inputs less outputs.
    pub fee: u128,
}

/// Writes the approval text into `out` and returns its length.
pub fn approval_text(network: Network, rescue: &Rescue, sighash: &[u8; 32], out: &mut [u8]) -> Result<usize, ApprovalError> {
    let mut writer = Writer { out, at: 0 };
    writer.push(HEADER)?;
    let at = writer.at;
    let length = full_address(network, &rescue.destination, &mut writer.out[at..])?;
    writer.at += length;
    writer.push(b"\nCKB: ")?;
    writer.amount(rescue.ckb)?;
    writer.push(b"\nTokens: ")?;
    match rescue.token_cells {
        0 => writer.push(b"none")?,
        1 => writer.push(b"1 token cell")?,
        count => {
            writer.decimal(count as u128, false)?;
            writer.push(b" token cells")?;
        }
    }
    writer.push(b"\nFee: ")?;
    writer.amount(rescue.fee)?;
    writer.push(b" CKB\nTransaction: 0x")?;
    for byte in sighash {
        writer.push(&[HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]])?;
    }
    Ok(writer.at)
}

const HEX: &[u8; 16] = b"0123456789abcdef";
const SHANNONS: u128 = 100_000_000;

struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn push(&mut self, bytes: &[u8]) -> Result<(), ApprovalError> {
        let end = self.at + bytes.len();
        if end > self.out.len() {
            return Err(ApprovalError::TooLong);
        }
        self.out[self.at..end].copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }

    /// A whole number, with a comma between each group of three digits when `grouped`.
    fn decimal(&mut self, value: u128, grouped: bool) -> Result<(), ApprovalError> {
        let mut digits = [0u8; 39];
        let mut count = 0;
        let mut rest = value;
        loop {
            digits[count] = b'0' + (rest % 10) as u8;
            count += 1;
            rest /= 10;
            if rest == 0 {
                break;
            }
        }
        for index in (0..count).rev() {
            self.push(&[digits[index]])?;
            if grouped && index > 0 && index % 3 == 0 {
                self.push(b",")?;
            }
        }
        Ok(())
    }

    /// Shannons as CKB: grouped whole part, then up to 8 decimals without trailing zeros.
    fn amount(&mut self, shannons: u128) -> Result<(), ApprovalError> {
        self.decimal(shannons / SHANNONS, true)?;
        let mut fraction = (shannons % SHANNONS) as u32;
        if fraction == 0 {
            return Ok(());
        }
        let mut places = 8;
        while fraction % 10 == 0 {
            fraction /= 10;
            places -= 1;
        }
        self.push(b".")?;
        let mut digits = [b'0'; 8];
        for index in (0..places).rev() {
            digits[index] = b'0' + (fraction % 10) as u8;
            fraction /= 10;
        }
        self.push(&digits[..places])
    }
}

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M: u32 = 0x2bc8_30a3;

fn polymod_step(checksum: u32, value: u8) -> u32 {
    const GENERATOR: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let top = checksum >> 25;
    let mut next = (checksum & 0x01ff_ffff) << 5 ^ value as u32;
    for (bit, generator) in GENERATOR.iter().enumerate() {
        if (top >> bit) & 1 == 1 {
            next ^= generator;
        }
    }
    next
}

/// CKB's full address format: bech32m over `0x00 ‖ code_hash ‖ hash_type ‖ args`, without bech32's 90-character
/// limit. Returns the length written to `out`.
pub fn full_address(network: Network, destination: &Destination, out: &mut [u8]) -> Result<usize, ApprovalError> {
    let prefix = network.prefix();
    let payload_length = 1 + 32 + 1 + destination.args.len();
    let words = (payload_length * 8).div_ceil(5);
    let length = prefix.len() + 1 + words + 6;
    if length > out.len() {
        return Err(ApprovalError::TooLong);
    }
    let mut checksum = 1u32;
    for &byte in prefix {
        checksum = polymod_step(checksum, byte >> 5);
    }
    checksum = polymod_step(checksum, 0);
    for &byte in prefix {
        checksum = polymod_step(checksum, byte & 31);
    }
    out[..prefix.len()].copy_from_slice(prefix);
    out[prefix.len()] = b'1';
    let mut at = prefix.len() + 1;
    let mut accumulator = 0u32;
    let mut bits = 0;
    let mut emit = |word: u8, at: &mut usize, checksum: &mut u32| {
        *checksum = polymod_step(*checksum, word);
        out[*at] = CHARSET[word as usize];
        *at += 1;
    };
    let hash_type = [destination.hash_type];
    let payload = [0u8].iter().chain(destination.code_hash.iter()).chain(hash_type.iter()).chain(destination.args.iter());
    for &byte in payload {
        accumulator = accumulator << 8 | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            emit((accumulator >> bits & 31) as u8, &mut at, &mut checksum);
        }
        accumulator &= (1 << bits) - 1;
    }
    if bits > 0 {
        emit((accumulator << (5 - bits) & 31) as u8, &mut at, &mut checksum);
    }
    for _ in 0..6 {
        checksum = polymod_step(checksum, 0);
    }
    checksum ^= BECH32M;
    for index in 0..6 {
        out[at] = CHARSET[(checksum >> (5 * (5 - index)) & 31) as usize];
        at += 1;
    }
    Ok(at)
}

/// Splits a molecule `Script` table into its fields; None if malformed.
pub fn parse_script(bytes: &[u8]) -> Option<Destination<'_>> {
    let read = |at: usize| -> Option<usize> { Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize) };
    let total = read(0)?;
    if total != bytes.len() || read(4)? != 16 || read(8)? != 48 || read(12)? != 49 {
        return None;
    }
    let args_length = read(49)?;
    if 53 + args_length != total {
        return None;
    }
    Some(Destination { code_hash: bytes[16..48].try_into().ok()?, hash_type: bytes[48], args: &bytes[53..] })
}

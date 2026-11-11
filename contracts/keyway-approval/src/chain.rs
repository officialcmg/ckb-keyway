//! Reading the rescue the text describes from the transaction being verified. Omnilock execs the verifier in
//! the same script group, so the running script is the account's Omnilock.
use crate::{account_salt, approval_text, parse_script, ApprovalError, Network, Rescue};
use ckb_std::ckb_constants::{CellField, Source};
use ckb_std::error::SysError;
use ckb_std::syscalls::{load_cell_by_field, load_cell_data, load_script, load_script_hash};

/// A lock script longer than this can't be encoded within the text's limit anyway.
const MAX_SCRIPT: usize = 400;

fn field(buffer: &mut [u8], index: usize, source: Source, cell_field: CellField) -> Result<Option<usize>, ApprovalError> {
    match load_cell_by_field(buffer, 0, index, source, cell_field) {
        Ok(length) => Ok(Some(length)),
        Err(SysError::IndexOutOfBound) => Ok(None),
        Err(SysError::LengthNotEnough(_)) => Err(ApprovalError::TooLong),
        Err(_) => Err(ApprovalError::Syscall),
    }
}

fn capacity(index: usize, source: Source) -> Result<Option<u64>, ApprovalError> {
    let mut bytes = [0u8; 8];
    Ok(field(&mut bytes, index, source, CellField::Capacity)?.map(|_| u64::from_le_bytes(bytes)))
}

/// A KeyWay account's Omnilock script: 53 bytes of molecule header, code hash and hash type, then 54 bytes of args.
const ACCOUNT_SCRIPT: usize = 53 + crate::ACCOUNT_ARGS_LENGTH;

/// The running script's salt (`crate::account_salt`). Omnilock execs the verifier with `ckb_exec_cell`, which
/// replaces the program but keeps the script group, so `load_script` is the account's Omnilock lock being
/// unlocked, whose args Omnilock has just checked the backup's SMT proof against (args[22..54] is the root).
pub fn running_account_salt() -> Result<[u8; 32], ApprovalError> {
    let mut script = [0u8; ACCOUNT_SCRIPT];
    let length = match load_script(&mut script, 0) {
        Ok(length) => length,
        Err(SysError::LengthNotEnough(_)) => return Err(ApprovalError::Account),
        Err(_) => return Err(ApprovalError::Syscall),
    };
    let parsed = parse_script(&script[..length]).ok_or(ApprovalError::Account)?;
    account_salt(parsed.args)
}

/// The most token cells (outputs with a type script) a rescue may move. KeyWay's rescue moves at most 100 cells
/// at a time; a larger rescue is refused (111) and can be split.
pub const MAX_TOKEN_CELLS: usize = 256;

/// A cell's type script hash and data hash, or None when it has no type script.
fn token_key(index: usize, source: Source) -> Result<Option<[u8; 64]>, ApprovalError> {
    let mut key = [0u8; 64];
    match load_cell_by_field(&mut key[..32], 0, index, source, CellField::TypeHash) {
        Ok(_) => {}
        Err(SysError::ItemMissing) => return Ok(None),
        Err(_) => return Err(ApprovalError::Syscall),
    }
    load_cell_by_field(&mut key[32..], 0, index, source, CellField::DataHash).map_err(|_| ApprovalError::Syscall)?;
    Ok(Some(key))
}

/// Builds the approval text for this transaction into `out`, refusing anything that isn't a rescue.
///
/// The text counts token cells rather than naming them, so the token cells must be exactly the account's own,
/// moved unchanged: each output with a type script has the type script hash and data hash of a distinct input of
/// the account, and each of the account's inputs with a type script is one of them. Anything else (a token cell
/// changed, left behind to be burned, or made under a type script the account didn't hold) is refused (111).
pub fn rescue_text(network: Network, sighash: &[u8; 32], out: &mut [u8]) -> Result<usize, ApprovalError> {
    let mut account = [0u8; 32];
    load_script_hash(&mut account, 0).map_err(|_| ApprovalError::Syscall)?;
    let mut destination_hash = [0u8; 32];
    if field(&mut destination_hash, 0, Source::Output, CellField::LockHash)?.is_none() || destination_hash == account {
        return Err(ApprovalError::Shape);
    }
    let mut ckb = 0u128;
    let mut tokens = [[0u8; 64]; MAX_TOKEN_CELLS];
    let mut moved = [false; MAX_TOKEN_CELLS];
    let mut token_cells = 0;
    let mut index = 0;
    while let Some(value) = capacity(index, Source::Output)? {
        let mut lock_hash = [0u8; 32];
        field(&mut lock_hash, index, Source::Output, CellField::LockHash)?;
        if lock_hash != destination_hash {
            return Err(ApprovalError::Shape);
        }
        ckb += value as u128;
        match token_key(index, Source::Output)? {
            Some(key) => {
                if token_cells == MAX_TOKEN_CELLS {
                    return Err(ApprovalError::Shape);
                }
                tokens[token_cells] = key;
                token_cells += 1;
            }
            None => match load_cell_data(&mut [], 0, index, Source::Output) {
                Ok(0) => {}
                Ok(_) | Err(SysError::LengthNotEnough(_)) => return Err(ApprovalError::Shape),
                Err(_) => return Err(ApprovalError::Syscall),
            },
        }
        index += 1;
    }
    let mut inputs = 0u128;
    let mut index = 0;
    while let Some(value) = capacity(index, Source::Input)? {
        inputs += value as u128;
        let mut lock_hash = [0u8; 32];
        field(&mut lock_hash, index, Source::Input, CellField::LockHash)?;
        if lock_hash == account {
            if let Some(key) = token_key(index, Source::Input)? {
                let found = (0..token_cells).find(|&at| !moved[at] && tokens[at] == key).ok_or(ApprovalError::Shape)?;
                moved[found] = true;
            }
        }
        index += 1;
    }
    if moved[..token_cells].iter().any(|&done| !done) {
        return Err(ApprovalError::Shape);
    }
    let fee = inputs.checked_sub(ckb).ok_or(ApprovalError::Shape)?;
    let mut script = [0u8; MAX_SCRIPT];
    let length = field(&mut script, 0, Source::Output, CellField::Lock)?.ok_or(ApprovalError::Shape)?;
    let destination = parse_script(&script[..length]).ok_or(ApprovalError::Shape)?;
    approval_text(network, &Rescue { destination, ckb, token_cells: token_cells as u64, fee }, sighash, out)
}

//! Reading the rescue the text describes from the transaction being verified. Omnilock execs the verifier in
//! the same script group, so the running script is the account's Omnilock.
use crate::{approval_text, parse_script, ApprovalError, Network, Rescue};
use ckb_std::ckb_constants::{CellField, Source};
use ckb_std::error::SysError;
use ckb_std::syscalls::{load_cell_by_field, load_cell_data, load_script_hash};

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

/// Builds the approval text for this transaction into `out`, refusing anything that isn't a rescue.
pub fn rescue_text(network: Network, sighash: &[u8; 32], out: &mut [u8]) -> Result<usize, ApprovalError> {
    let mut account = [0u8; 32];
    load_script_hash(&mut account, 0).map_err(|_| ApprovalError::Syscall)?;
    let mut destination_hash = [0u8; 32];
    if field(&mut destination_hash, 0, Source::Output, CellField::LockHash)?.is_none() || destination_hash == account {
        return Err(ApprovalError::Shape);
    }
    let mut ckb = 0u128;
    let mut token_cells = 0u64;
    let mut index = 0;
    while let Some(value) = capacity(index, Source::Output)? {
        let mut lock_hash = [0u8; 32];
        field(&mut lock_hash, index, Source::Output, CellField::LockHash)?;
        if lock_hash != destination_hash {
            return Err(ApprovalError::Shape);
        }
        ckb += value as u128;
        let mut type_hash = [0u8; 32];
        match load_cell_by_field(&mut type_hash, 0, index, Source::Output, CellField::TypeHash) {
            Ok(_) => token_cells += 1,
            Err(SysError::ItemMissing) => match load_cell_data(&mut [], 0, index, Source::Output) {
                Ok(0) => {}
                Ok(_) | Err(SysError::LengthNotEnough(_)) => return Err(ApprovalError::Shape),
                Err(_) => return Err(ApprovalError::Syscall),
            },
            Err(_) => return Err(ApprovalError::Syscall),
        }
        index += 1;
    }
    let mut inputs = 0u128;
    let mut index = 0;
    while let Some(value) = capacity(index, Source::Input)? {
        inputs += value as u128;
        index += 1;
    }
    let fee = inputs.checked_sub(ckb).ok_or(ApprovalError::Shape)?;
    let mut script = [0u8; MAX_SCRIPT];
    let length = field(&mut script, 0, Source::Output, CellField::Lock)?.ok_or(ApprovalError::Shape)?;
    let destination = parse_script(&script[..length]).ok_or(ApprovalError::Shape)?;
    approval_text(network, &Rescue { destination, ckb, token_cells, fee }, sighash, out)
}

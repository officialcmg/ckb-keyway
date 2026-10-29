//! Test-only, never deployed: runs the verifier's P-256 core in CKB-VM on `public_key:rs:message` (hex),
//! checking the signature over sha256(message), the shape of ckb-auth issue #31's JoyID vector.
#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "riscv64", no_main)]

#[cfg(target_arch = "riscv64")]
ckb_std::entry!(program_entry);

#[cfg(target_arch = "riscv64")]
struct NoAlloc;

#[cfg(target_arch = "riscv64")]
unsafe impl core::alloc::GlobalAlloc for NoAlloc {
    unsafe fn alloc(&self, _: core::alloc::Layout) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe fn dealloc(&self, _: *mut u8, _: core::alloc::Layout) {}
}

#[cfg(target_arch = "riscv64")]
#[global_allocator]
static ALLOCATOR: NoAlloc = NoAlloc;

#[cfg(target_arch = "riscv64")]
fn program_entry() -> i8 {
    use joyid_webauthn::{decode_hex, verify_p256, Error};
    use sha2::{Digest, Sha256};
    let argv = ckb_std::env::argv();
    if argv.len() != 1 {
        return Error::Args as i8;
    }
    let mut fields = argv[0].to_bytes().split(|&byte| byte == b':');
    let (mut public_key, mut rs, mut message) = ([0u8; 64], [0u8; 64], [0u8; 1024]);
    let decoded = (|| {
        let a = decode_hex(fields.next().ok_or(Error::Args)?, &mut public_key)?;
        let b = decode_hex(fields.next().ok_or(Error::Args)?, &mut rs)?;
        let c = decode_hex(fields.next().ok_or(Error::Args)?, &mut message)?;
        if a != 64 || b != 64 { return Err(Error::Args); }
        Ok(c)
    })();
    let result = decoded.and_then(|length| verify_p256(&public_key, &rs, &Sha256::digest(&message[..length])));
    match result {
        Ok(()) => 0,
        Err(error) => error as i8,
    }
}

#[cfg(not(target_arch = "riscv64"))]
fn main() {}

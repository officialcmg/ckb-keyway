//! The deployed binary: Omnilock execs it with one argument (see the library docs) and its exit code becomes
//! the lock's result.
#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "riscv64", no_main)]

#[cfg(target_arch = "riscv64")]
ckb_std::entry!(program_entry);

/// Nothing here allocates; ckb-std's entry only needs an allocator to exist.
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
    let argv = ckb_std::env::argv();
    if argv.len() != 1 {
        return evm_personal_sign::Error::Args as i8;
    }
    let run = || -> Result<(), evm_personal_sign::Error> {
        let argument = evm_personal_sign::parse_argument(argv[0].to_bytes())?;
        let mut text = [0u8; evm_personal_sign::MAX_TEXT];
        let length = keyway_approval::chain::rescue_text(argument.network, &argument.msg, &mut text)?;
        evm_personal_sign::verify(&argument, &text[..length])
    };
    match run() {
        Ok(()) => 0,
        Err(error) => error as i8,
    }
}

#[cfg(not(target_arch = "riscv64"))]
fn main() {}

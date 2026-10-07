//! CPU feature detection for the assembly dispatch.
//!
//! x86_64 reads the `OPENSSL_ia32cap_P` flags that the cpuid assembly fills
//! from the `.init` section at load time. aarch64 reads the Linux HWCAP words
//! into `OPENSSL_armcap_P` (see [`armcap`]), the global the aarch64 assembly
//! modules test at their entry points. riscv64 reads `riscv_hwprobe` (see
//! [`riscvcap`]) into a capability word of its own; its assembly does not
//! self-dispatch, so the query answers the dispatch sites directly.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/utils/cpuid/x86_64.ts"),
    options(att_syntax)
);

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
extern "C" {
    static mut OPENSSL_ia32cap_P: [u32; 10];
    fn OPENSSL_ia32_cpuid(out: *mut u32) -> u64;
}

/// Returns the CPU feature flags collected by OPENSSL_cpuid_setup.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub(crate) fn ia32cap(index: usize) -> u32 {
    unsafe { (*core::ptr::addr_of!(OPENSSL_ia32cap_P))[index] }
}

/// Called from the .init section stub emitted by x86_64.ts, mirroring
/// OpenSSL's cryptlib.c OPENSSL_cpuid_setup: fills OPENSSL_ia32cap_P with
/// the CPU feature flags. The OPENSSL_ia32CAP environment override is not
/// supported.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
#[no_mangle]
extern "C" fn OPENSSL_cpuid_setup() {
    use core::sync::atomic::{AtomicBool, Ordering};
    static TRIGGER: AtomicBool = AtomicBool::new(false);
    if TRIGGER.swap(true, Ordering::Relaxed) {
        return;
    }

    unsafe {
        let caps = core::ptr::addr_of_mut!(OPENSSL_ia32cap_P);
        core::ptr::write_bytes(caps, 0, 1);
        let vec = OPENSSL_ia32_cpuid(caps.cast());
        (*caps)[0] = vec as u32;
        (*caps)[1] = (vec >> 32) as u32;
    }
}

/// aarch64 capability detection (crypto/armcap.c). The `crown_aarch64_asm`
/// cfg (crown/build.rs) already covers the `asm` feature and the ELF targets
/// whose assembler accepts the perlasm output.
#[cfg(crown_aarch64_asm)]
mod armcap;

#[cfg(crown_aarch64_asm)]
pub(crate) use armcap::*;

/// riscv64 capability detection (crypto/riscvcap.c). The `crown_riscv64_asm`
/// cfg (crown/build.rs) already covers the `asm` feature and the ELF targets
/// whose assembler accepts the perlasm output.
#[cfg(crown_riscv64_asm)]
mod riscvcap;

#[cfg(crown_riscv64_asm)]
pub(crate) use riscvcap::*;

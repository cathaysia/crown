//! x86_64 CPUID support.
//!
//! The assembly modules are dispatched on the CPU feature flags stored in
//! OPENSSL_ia32cap_P (defined by x86_64.ts and initialised at load time by
//! OPENSSL_cpuid_setup through the .init section stub the assembly emits).

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

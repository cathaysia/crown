//! SM4 assembly implementation (SM4-NI on x86_64, ARMv8.4 SM4 on aarch64).
//!
//! On x86_64 the round-key schedule is the 32 native-endian `u32` words
//! produced by the software key expansion (`Sm4.ek`);
//! `hw_x86_64_sm4_decrypt` walks that same schedule in reverse, so no separate
//! decryption schedule is required. On aarch64 the `sm4_v8_set_*_key` routines
//! build their own schedule, which `sm4_v8_encrypt`/`sm4_v8_decrypt` consume,
//! so the caller keeps a separate pair of hardware schedules.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/sm4/x86_64.ts"),
    options(att_syntax)
);

#[cfg(crown_aarch64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/sm4/aarch64.ts"),
    // The aarch64 operands carry `{v0.16b}`-style lane braces.
    options(raw)
);

extern "C" {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    fn hw_x86_64_sm4_set_key(user_key: *const u8, key: *mut u32) -> i32;
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    fn hw_x86_64_sm4_encrypt(inp: *const u8, out: *mut u8, ks: *const u32);
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    fn hw_x86_64_sm4_decrypt(inp: *const u8, out: *mut u8, ks: *const u32);

    #[cfg(crown_aarch64_asm)]
    fn sm4_v8_set_encrypt_key(user_key: *const u8, key: *mut u32);
    #[cfg(crown_aarch64_asm)]
    fn sm4_v8_set_decrypt_key(user_key: *const u8, key: *mut u32);
    #[cfg(crown_aarch64_asm)]
    fn sm4_v8_encrypt(inp: *const u8, out: *mut u8, ks: *const u32);
    #[cfg(crown_aarch64_asm)]
    fn sm4_v8_decrypt(inp: *const u8, out: *mut u8, ks: *const u32);
}

/// SM4-NI needs AVX2 (CPUID leaf 7.0 EBX bit 5 -> ia32cap[2] bit 5) plus
/// SM4-NI itself (CPUID leaf 7.1 EAX bit 2 -> ia32cap[5] bit 2), matching
/// OpenSSL's `HWSM4_CAPABLE_X86_64`.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn sm4_supported() -> bool {
    use crate::utils::cpuid::ia32cap;
    (ia32cap(2) & (1 << 5) != 0) && (ia32cap(5) & (1 << 2) != 0)
}

/// The aarch64 side needs the ARMv8.4 SM4 crypto extension (HWCAP_SM4).
#[cfg(crown_aarch64_asm)]
pub fn sm4_supported() -> bool {
    crate::utils::cpuid::armcap() & crate::utils::cpuid::ARMV8_SM4 != 0
}

/// Expand `user_key` into the 32 round keys, same layout as `Sm4.ek`.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
#[allow(dead_code)] // compared against the software schedule in tests
pub fn set_key(user_key: &[u8], key: &mut [u32]) {
    unsafe {
        hw_x86_64_sm4_set_key(user_key.as_ptr(), key.as_mut_ptr());
    }
}

/// Build the ARMv8 forward (`enc`) and inverse (`dec`) schedules, which
/// differ from the software ones in layout, so the caller keeps them
/// alongside `Sm4.ek`/`Sm4.dk`.
#[cfg(crown_aarch64_asm)]
pub fn set_keys(user_key: &[u8], enc: &mut [u32; 32], dec: &mut [u32; 32]) {
    unsafe {
        sm4_v8_set_encrypt_key(user_key.as_ptr(), enc.as_mut_ptr());
        sm4_v8_set_decrypt_key(user_key.as_ptr(), dec.as_mut_ptr());
    }
}

/// Encrypt one 16-byte block in place.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn encrypt_block(inout: &mut [u8], ks: &[u32]) {
    let p = inout.as_mut_ptr();
    unsafe {
        hw_x86_64_sm4_encrypt(p, p, ks.as_ptr());
    }
}

/// Decrypt one 16-byte block in place, using the forward key schedule.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn decrypt_block(inout: &mut [u8], ks: &[u32]) {
    let p = inout.as_mut_ptr();
    unsafe {
        hw_x86_64_sm4_decrypt(p, p, ks.as_ptr());
    }
}

/// Encrypt one 16-byte block in place with the ARMv8 schedule.
#[cfg(crown_aarch64_asm)]
pub fn encrypt_block(inout: &mut [u8], ks: &[u32]) {
    let p = inout.as_mut_ptr();
    unsafe {
        sm4_v8_encrypt(p, p, ks.as_ptr());
    }
}

/// Decrypt one 16-byte block in place with the ARMv8 inverse schedule.
#[cfg(crown_aarch64_asm)]
pub fn decrypt_block(inout: &mut [u8], ks: &[u32]) {
    let p = inout.as_mut_ptr();
    unsafe {
        sm4_v8_decrypt(p, p, ks.as_ptr());
    }
}

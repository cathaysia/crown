//! SM4 assembly implementation for x86_64 using the SM4-NI instructions.
//!
//! The round-key schedule is the 32 native-endian `u32` words produced by the
//! software key expansion (`Sm4.ek`); `hw_x86_64_sm4_decrypt` walks that same
//! schedule in reverse, so no separate decryption schedule is required.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/sm4/x86_64.ts"),
    options(att_syntax)
);

use crate::utils::cpuid::ia32cap;

extern "C" {
    #[allow(dead_code)]
    fn hw_x86_64_sm4_set_key(user_key: *const u8, key: *mut u32) -> i32;
    fn hw_x86_64_sm4_encrypt(inp: *const u8, out: *mut u8, ks: *const u32);
    fn hw_x86_64_sm4_decrypt(inp: *const u8, out: *mut u8, ks: *const u32);
}

/// SM4-NI needs AVX2 (CPUID leaf 7.0 EBX bit 5 -> ia32cap[2] bit 5) plus
/// SM4-NI itself (CPUID leaf 7.1 EAX bit 2 -> ia32cap[5] bit 2), matching
/// OpenSSL's `HWSM4_CAPABLE_X86_64`.
pub fn sm4_supported() -> bool {
    (ia32cap(2) & (1 << 5) != 0) && (ia32cap(5) & (1 << 2) != 0)
}

/// Expand `user_key` into the 32 round keys, same layout as `Sm4.ek`.
#[allow(dead_code)] // compared against the software schedule in tests
pub fn set_key(user_key: &[u8], key: &mut [u32]) {
    unsafe {
        hw_x86_64_sm4_set_key(user_key.as_ptr(), key.as_mut_ptr());
    }
}

/// Encrypt one 16-byte block in place.
pub fn encrypt_block(inout: &mut [u8], ks: &[u32]) {
    let p = inout.as_mut_ptr();
    unsafe {
        hw_x86_64_sm4_encrypt(p, p, ks.as_ptr());
    }
}

/// Decrypt one 16-byte block in place, using the forward key schedule.
pub fn decrypt_block(inout: &mut [u8], ks: &[u32]) {
    let p = inout.as_mut_ptr();
    unsafe {
        hw_x86_64_sm4_decrypt(p, p, ks.as_ptr());
    }
}

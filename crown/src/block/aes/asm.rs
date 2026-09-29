#![allow(dead_code, unused_imports)]
//! AES assembly modules for x86_64.
//!
//! vpaes (SSSE3) is compiled in here. Its key schedule lives in a transformed
//! domain produced by vpaes_set_encrypt_key/vpaes_set_decrypt_key, so wiring
//! it into the block dispatch requires calling those at key-expansion time.
//! The plain aes and aesni modules consume the standard FIPS-197 schedule
//! (crown's BlockExpanded.enc limb) directly through an AES_KEY shim.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/aes/vpaes/x86_64.ts"),
    options(att_syntax)
);

use super::ttable::AesKey;
use crate::utils::cpuid::ia32cap;

extern "C" {
    fn vpaes_set_encrypt_key_ffi(user_key: *const u8, bits: i32, key: *mut AesKey) -> i32;
    fn vpaes_set_decrypt_key_ffi(user_key: *const u8, bits: i32, key: *mut AesKey) -> i32;
    fn vpaes_encrypt_ffi(inp: *const u8, out: *mut u8, key: *const AesKey);
    fn vpaes_decrypt_ffi(inp: *const u8, out: *mut u8, key: *const AesKey);
}

// Aliases to the C symbols (global_asm names).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(".set vpaes_set_encrypt_key_ffi, vpaes_set_encrypt_key");
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(".set vpaes_set_decrypt_key_ffi, vpaes_set_decrypt_key");
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(".set vpaes_encrypt_ffi, vpaes_encrypt");
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(".set vpaes_decrypt_ffi, vpaes_decrypt");

/// VPAES requires SSSE3 (ECX bit 9 of CPUID leaf 1, i.e. ia32cap[1] bit 9).
pub fn vpaes_supported() -> bool {
    ia32cap(1) & (1 << 9) != 0
}

/// AES-NI requires ECX bit 25 of CPUID leaf 1.
pub fn aesni_supported() -> bool {
    ia32cap(1) & (1 << 25) != 0
}

/// Expand into the vpaes transformed-domain schedule.
pub fn vpaes_set_encrypt_key(user_key: &[u8]) -> AesKey {
    let mut key = AesKey {
        rd_key: [0; 60],
        rounds: 0,
    };
    let rc = unsafe {
        vpaes_set_encrypt_key_ffi(user_key.as_ptr(), (user_key.len() * 8) as i32, &mut key)
    };
    debug_assert_eq!(rc, 0);
    key
}

pub fn vpaes_set_decrypt_key(user_key: &[u8]) -> AesKey {
    let mut key = AesKey {
        rd_key: [0; 60],
        rounds: 0,
    };
    let rc = unsafe {
        vpaes_set_decrypt_key_ffi(user_key.as_ptr(), (user_key.len() * 8) as i32, &mut key)
    };
    debug_assert_eq!(rc, 0);
    key
}

pub fn vpaes_encrypt_block(inout: &mut [u8], key: &AesKey) {
    unsafe { vpaes_encrypt_ffi(inout.as_ptr(), inout.as_mut_ptr(), key) }
}

pub fn vpaes_decrypt_block(inout: &mut [u8], key: &AesKey) {
    unsafe { vpaes_decrypt_ffi(inout.as_ptr(), inout.as_mut_ptr(), key) }
}

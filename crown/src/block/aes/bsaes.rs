//! Bit-sliced AES for x86_64 (bsaes-x86_64.pl).
//!
//! Provides CBC-decrypt / CTR32 / XTS accelerators over a conventional
//! [`AesKey`] schedule. Falls back to `asm_AES_*` (the T-table module) for
//! CBC encrypt and short tails.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/aes/bsaes/x86_64.ts"),
    options(att_syntax)
);

use super::ttable::AesKey;

extern "C" {
    // Defined by the ttable generator (aes-x86_64.pl aliases).
    fn ossl_bsaes_cbc_encrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key: *const AesKey,
        ivp: *mut u8,
        enc: i32,
    );
    fn ossl_bsaes_ctr32_encrypt_blocks(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key: *const AesKey,
        ivec: *const u8,
    );
    fn ossl_bsaes_xts_encrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key1: *const AesKey,
        key2: *const AesKey,
        iv: *const u8,
    );
    fn ossl_bsaes_xts_decrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key1: *const AesKey,
        key2: *const AesKey,
        iv: *const u8,
    );
}

/// SSSE3 is CPUID leaf 1 ECX bit 9 (ia32cap[1] bit 9).
#[allow(dead_code)]
pub fn supported() -> bool {
    crate::utils::cpuid::ia32cap(1) & (1 << 9) != 0
}

/// CBC; `enc == 0` uses the bit-sliced fast path when `len >= 128`.
#[allow(dead_code)]
pub fn cbc_encrypt(inp: &[u8], out: &mut [u8], key: &AesKey, ivp: &mut [u8], enc: bool) {
    debug_assert_eq!(inp.len(), out.len());
    unsafe {
        ossl_bsaes_cbc_encrypt(
            inp.as_ptr(),
            out.as_mut_ptr(),
            inp.len(),
            key,
            ivp.as_mut_ptr(),
            enc as i32,
        );
    }
}

/// CTR32 over whole blocks; `len` is in bytes.
#[allow(dead_code)]
pub fn ctr32_encrypt_blocks(inp: &[u8], out: &mut [u8], key: &AesKey, ivec: &[u8; 16]) {
    debug_assert_eq!(inp.len(), out.len());
    unsafe {
        ossl_bsaes_ctr32_encrypt_blocks(
            inp.as_ptr(),
            out.as_mut_ptr(),
            inp.len(),
            key,
            ivec.as_ptr(),
        );
    }
}

#[allow(dead_code)]
pub fn xts_encrypt(inp: &[u8], out: &mut [u8], key1: &AesKey, key2: &AesKey, iv: &[u8; 16]) {
    debug_assert_eq!(inp.len(), out.len());
    unsafe {
        ossl_bsaes_xts_encrypt(
            inp.as_ptr(),
            out.as_mut_ptr(),
            inp.len(),
            key1,
            key2,
            iv.as_ptr(),
        );
    }
}

#[allow(dead_code)]
pub fn xts_decrypt(inp: &[u8], out: &mut [u8], key1: &AesKey, key2: &AesKey, iv: &[u8; 16]) {
    debug_assert_eq!(inp.len(), out.len());
    unsafe {
        ossl_bsaes_xts_decrypt(
            inp.as_ptr(),
            out.as_mut_ptr(),
            inp.len(),
            key1,
            key2,
            iv.as_ptr(),
        );
    }
}

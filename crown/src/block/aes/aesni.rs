//! AES-NI implementation for x86_64 (aesni-x86_64.pl).
//!
//! Consumes the standard FIPS-197 schedule in [`AesKey`] (same layout as
//! [`super::ttable::AesKey`]).

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/aes/aesni/x86_64.ts"),
    options(att_syntax)
);

use super::ttable::AesKey;
use crate::utils::cpuid::ia32cap;

extern "C" {
    fn aesni_set_encrypt_key(user_key: *const u8, bits: i32, key: *mut AesKey) -> i32;
    fn aesni_set_decrypt_key(user_key: *const u8, bits: i32, key: *mut AesKey) -> i32;
    fn aesni_encrypt(inp: *const u8, out: *mut u8, key: *const AesKey);
    fn aesni_decrypt(inp: *const u8, out: *mut u8, key: *const AesKey);
    #[allow(dead_code)]
    fn aesni_ctr32_encrypt_blocks(
        inp: *const u8,
        out: *mut u8,
        blocks: usize,
        key: *const AesKey,
        ivec: *const u8,
    );
}

/// AES-NI requires CPUID leaf 1 ECX bit 25 (ia32cap[1] bit 25).
pub fn supported() -> bool {
    ia32cap(1) & (1 << 25) != 0
}

pub fn set_encrypt_key(user_key: &[u8]) -> AesKey {
    let mut key = AesKey {
        rd_key: [0; 60],
        rounds: 0,
    };
    let rc =
        unsafe { aesni_set_encrypt_key(user_key.as_ptr(), (user_key.len() * 8) as i32, &mut key) };
    debug_assert_eq!(rc, 0, "aesni_set_encrypt_key failed: {rc}");
    key
}

pub fn set_decrypt_key(user_key: &[u8]) -> AesKey {
    let mut key = AesKey {
        rd_key: [0; 60],
        rounds: 0,
    };
    let rc =
        unsafe { aesni_set_decrypt_key(user_key.as_ptr(), (user_key.len() * 8) as i32, &mut key) };
    debug_assert_eq!(rc, 0, "aesni_set_decrypt_key failed: {rc}");
    key
}

pub fn encrypt_block(inout: &mut [u8], key: &AesKey) {
    let p = inout.as_mut_ptr();
    unsafe { aesni_encrypt(p, p, key) }
}

pub fn decrypt_block(inout: &mut [u8], key: &AesKey) {
    let p = inout.as_mut_ptr();
    unsafe { aesni_decrypt(p, p, key) }
}

/// Encrypt `blocks` 16-byte blocks in CTR32 mode. `ivec` is the 16-byte
/// counter block; the 32-bit counter is in the last four bytes (big-endian
/// order as in OpenSSL). Does not write back the updated counter.
#[allow(dead_code)] // mode accelerator; CTR dispatch is pending
pub fn ctr32_encrypt_blocks(
    inp: &[u8],
    out: &mut [u8],
    blocks: usize,
    key: &AesKey,
    ivec: &[u8; 16],
) {
    unsafe {
        aesni_ctr32_encrypt_blocks(inp.as_ptr(), out.as_mut_ptr(), blocks, key, ivec.as_ptr());
    }
}

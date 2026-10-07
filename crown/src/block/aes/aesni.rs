//! AES-NI implementation for x86_64 (aesni-x86_64.pl).
//!
//! Consumes the standard FIPS-197 schedule in [`AesKey`] (same layout as
//! [`super::ttable::AesKey`]).

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/aes/aesni/x86_64.ts"),
    options(att_syntax)
);

pub use super::ttable::AesKey;
use crate::utils::cpuid::ia32cap;

extern "C" {
    fn aesni_cbc_encrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key: *const AesKey,
        ivec: *mut u8,
        enc: i32,
    );
    fn aesni_set_encrypt_key(user_key: *const u8, bits: i32, key: *mut AesKey) -> i32;
    fn aesni_set_decrypt_key(user_key: *const u8, bits: i32, key: *mut AesKey) -> i32;
    fn aesni_encrypt(inp: *const u8, out: *mut u8, key: *const AesKey);
    fn aesni_decrypt(inp: *const u8, out: *mut u8, key: *const AesKey);
    fn aesni_ecb_encrypt(inp: *const u8, out: *mut u8, len: usize, key: *const AesKey, enc: i32);
    fn aesni_ocb_encrypt(
        inp: *const u8,
        out: *mut u8,
        blocks: usize,
        key: *const AesKey,
        start_block_num: u32,
        offset_i: *mut u8,
        l: *const u8,
        checksum: *mut u8,
    );
    fn aesni_ocb_decrypt(
        inp: *const u8,
        out: *mut u8,
        blocks: usize,
        key: *const AesKey,
        start_block_num: u32,
        offset_i: *mut u8,
        l: *const u8,
        checksum: *mut u8,
    );
    fn aesni_ccm64_encrypt_blocks(
        inp: *const u8,
        out: *mut u8,
        blocks: usize,
        key: *const AesKey,
        ivec: *const u8,
        cmac: *mut u8,
    );
    fn aesni_ccm64_decrypt_blocks(
        inp: *const u8,
        out: *mut u8,
        blocks: usize,
        key: *const AesKey,
        ivec: *const u8,
        cmac: *mut u8,
    );
    fn aesni_xts_encrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key1: *const AesKey,
        key2: *const AesKey,
        iv: *const u8,
    );
    fn aesni_xts_decrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key1: *const AesKey,
        key2: *const AesKey,
        iv: *const u8,
    );
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
#[allow(dead_code)]
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

/// In-place CBC encrypt/decrypt over full blocks (`enc != 0` encrypts).
/// Updates `ivec` to the last ciphertext block, like OpenSSL.
pub fn cbc_encrypt(inout: &mut [u8], key: &AesKey, ivec: &mut [u8; 16], enc: bool) {
    unsafe {
        aesni_cbc_encrypt(
            inout.as_ptr(),
            inout.as_mut_ptr(),
            inout.len(),
            key,
            ivec.as_mut_ptr(),
            enc as i32,
        );
    }
}

/// In-place ECB over whole blocks (`enc != 0` encrypts).
pub fn ecb_encrypt(inout: &mut [u8], key: &AesKey, enc: bool) {
    unsafe {
        aesni_ecb_encrypt(
            inout.as_ptr(),
            inout.as_mut_ptr(),
            inout.len(),
            key,
            enc as i32,
        );
    }
}

/// Fused CBC-MAC + CTR over `blocks` complete 16-byte blocks (the CCM body
/// routine of `crypto/modes/ccm128.c`). `ivec` is the counter block of the
/// first block and is read but not updated; `cmac` is the running CBC-MAC of
/// the plaintext (the decrypted output when `enc` is false), updated in
/// place. Trailing partial blocks stay with the caller.
pub fn ccm64_crypt(
    inout: &mut [u8],
    blocks: usize,
    key: &AesKey,
    ivec: &[u8; 16],
    cmac: &mut [u8; 16],
    enc: bool,
) {
    debug_assert!(inout.len() >= blocks * 16);
    unsafe {
        if enc {
            aesni_ccm64_encrypt_blocks(
                inout.as_ptr(),
                inout.as_mut_ptr(),
                blocks,
                key,
                ivec.as_ptr(),
                cmac.as_mut_ptr(),
            );
        } else {
            aesni_ccm64_decrypt_blocks(
                inout.as_ptr(),
                inout.as_mut_ptr(),
                blocks,
                key,
                ivec.as_ptr(),
                cmac.as_mut_ptr(),
            );
        }
    }
}

/// OCB's whole-block loop: `Offset_i = Offset_{i-1} xor L_{ntz(i)}`, the
/// plaintext is folded into `checksum` and the block is enciphered under
/// `Offset_i`. `start_block_num` is the 1-based index of the first block;
/// `l` is the `L_i` table (`L_[][16]` upstream) that the routine indexes by
/// `ntz(i)`, so entry `i` must be `L_i`. `offset` and `checksum` are updated
/// in place. The partial block, the AAD and the tag stay with the caller,
/// exactly like `crypto/modes/ocb128.c`.
#[allow(clippy::too_many_arguments)]
pub fn ocb_crypt(
    inout: &mut [u8],
    blocks: usize,
    key: &AesKey,
    start_block_num: u32,
    offset: &mut [u8; 16],
    l: &[[u8; 16]; 64],
    checksum: &mut [u8; 16],
    enc: bool,
) {
    debug_assert!(inout.len() >= blocks * 16);
    unsafe {
        if enc {
            aesni_ocb_encrypt(
                inout.as_ptr(),
                inout.as_mut_ptr(),
                blocks,
                key,
                start_block_num,
                offset.as_mut_ptr(),
                l.as_ptr().cast(),
                checksum.as_mut_ptr(),
            );
        } else {
            aesni_ocb_decrypt(
                inout.as_ptr(),
                inout.as_mut_ptr(),
                blocks,
                key,
                start_block_num,
                offset.as_mut_ptr(),
                l.as_ptr().cast(),
                checksum.as_mut_ptr(),
            );
        }
    }
}

/// In-place XTS over one data unit, ciphertext stealing included. `key1` is
/// the data key (encryption schedule when encrypting, decryption schedule
/// otherwise), `key2` the tweak key (always an encryption schedule); `iv` is
/// read but not updated, like `aesni_xts_encrypt`.
pub fn xts_crypt(inout: &mut [u8], key1: &AesKey, key2: &AesKey, iv: &[u8; 16], enc: bool) {
    debug_assert!(inout.len() >= 16);
    unsafe {
        if enc {
            aesni_xts_encrypt(
                inout.as_ptr(),
                inout.as_mut_ptr(),
                inout.len(),
                key1,
                key2,
                iv.as_ptr(),
            );
        } else {
            aesni_xts_decrypt(
                inout.as_ptr(),
                inout.as_mut_ptr(),
                inout.len(),
                key1,
                key2,
                iv.as_ptr(),
            );
        }
    }
}

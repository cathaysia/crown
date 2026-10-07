//! ARMv8 AES implementation (aesv8-armx.pl).
//!
//! The crypto-extension routines consume the standard `AES_KEY` schedule in
//! [`AesKey`] (same FIPS-197 word order as [`super::ttable`]), like OpenSSL's
//! `HWAES_*` dispatch in `crypto/include/internal/aes_platform.h`.

#[cfg(crown_aarch64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/aes/aesv8/aarch64.ts"),
    // The aarch64 operands carry `{v0.16b}`-style lane braces.
    options(raw)
);

pub use super::key::AesKey;

extern "C" {
    fn aes_v8_set_encrypt_key(user_key: *const u8, bits: i32, key: *mut AesKey) -> i32;
    fn aes_v8_set_decrypt_key(user_key: *const u8, bits: i32, key: *mut AesKey) -> i32;
    fn aes_v8_encrypt(inp: *const u8, out: *mut u8, key: *const AesKey);
    fn aes_v8_decrypt(inp: *const u8, out: *mut u8, key: *const AesKey);
    fn aes_v8_ecb_encrypt(inp: *const u8, out: *mut u8, len: usize, key: *const AesKey, enc: i32);
    fn aes_v8_cbc_encrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key: *const AesKey,
        ivec: *mut u8,
        enc: i32,
    );
    fn aes_v8_ctr32_encrypt_blocks(
        inp: *const u8,
        out: *mut u8,
        blocks: usize,
        key: *const AesKey,
        ivec: *const u8,
    );
    fn aes_v8_xts_encrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key1: *const AesKey,
        key2: *const AesKey,
        iv: *const u8,
    );
    fn aes_v8_xts_decrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key1: *const AesKey,
        key2: *const AesKey,
        iv: *const u8,
    );
}

/// The AES instructions require the ARMv8 AES crypto extension (HWCAP_AES).
pub fn supported() -> bool {
    crate::utils::cpuid::armcap() & crate::utils::cpuid::ARMV8_AES != 0
}

pub fn set_encrypt_key(user_key: &[u8]) -> AesKey {
    let mut key = AesKey {
        rd_key: [0; 60],
        rounds: 0,
    };
    let rc =
        unsafe { aes_v8_set_encrypt_key(user_key.as_ptr(), (user_key.len() * 8) as i32, &mut key) };
    debug_assert_eq!(rc, 0, "aes_v8_set_encrypt_key failed: {rc}");
    key
}

pub fn set_decrypt_key(user_key: &[u8]) -> AesKey {
    let mut key = AesKey {
        rd_key: [0; 60],
        rounds: 0,
    };
    let rc =
        unsafe { aes_v8_set_decrypt_key(user_key.as_ptr(), (user_key.len() * 8) as i32, &mut key) };
    debug_assert_eq!(rc, 0, "aes_v8_set_decrypt_key failed: {rc}");
    key
}

pub fn encrypt_block(inout: &mut [u8], key: &AesKey) {
    let p = inout.as_mut_ptr();
    unsafe { aes_v8_encrypt(p, p, key) }
}

pub fn decrypt_block(inout: &mut [u8], key: &AesKey) {
    let p = inout.as_mut_ptr();
    unsafe { aes_v8_decrypt(p, p, key) }
}

/// In-place CBC over full blocks (`enc != 0` encrypts). Updates `ivec` to the
/// last ciphertext block, like OpenSSL. Decryption needs the inverse schedule
/// (`aes_v8_cbc_encrypt` runs `aesd` then).
pub fn cbc_encrypt(inout: &mut [u8], key: &AesKey, ivec: &mut [u8; 16], enc: bool) {
    unsafe {
        aes_v8_cbc_encrypt(
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
        aes_v8_ecb_encrypt(
            inout.as_ptr(),
            inout.as_mut_ptr(),
            inout.len(),
            key,
            enc as i32,
        );
    }
}

/// In-place CTR32 over `blocks` 16-byte blocks. `ivec` is the counter block,
/// read but not written back; the 32-bit counter lives in its last four bytes.
pub fn ctr32_encrypt_blocks(
    inp: &[u8],
    out: &mut [u8],
    blocks: usize,
    key: &AesKey,
    ivec: &[u8; 16],
) {
    debug_assert!(blocks > 0);
    unsafe {
        aes_v8_ctr32_encrypt_blocks(inp.as_ptr(), out.as_mut_ptr(), blocks, key, ivec.as_ptr())
    }
}

/// In-place XTS over one data unit, ciphertext stealing included. `key1` is
/// the data key (encryption schedule when encrypting, decryption schedule
/// otherwise), `key2` the tweak key (always an encryption schedule); `iv` is
/// read but not updated, like `aes_v8_xts_encrypt`.
pub fn xts_crypt(inout: &mut [u8], key1: &AesKey, key2: &AesKey, iv: &[u8; 16], enc: bool) {
    debug_assert!(inout.len() >= 16);
    unsafe {
        if enc {
            aes_v8_xts_encrypt(
                inout.as_ptr(),
                inout.as_mut_ptr(),
                inout.len(),
                key1,
                key2,
                iv.as_ptr(),
            );
        } else {
            aes_v8_xts_decrypt(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::aes::{generic, BlockExpanded};

    #[test]
    fn aesv8_matches_generic() {
        if !supported() {
            return;
        }
        for key_len in [16usize, 24, 32] {
            let mut key = alloc::vec![0u8; key_len];
            rand::fill(&mut key[..]);
            let enc_key = set_encrypt_key(&key);
            let dec_key = set_decrypt_key(&key);

            let mut block = BlockExpanded::default();
            block.expand(&key);

            for _ in 0..32 {
                let mut buf = [0u8; 16];
                rand::fill(&mut buf);

                let mut soft = buf;
                generic::encrypt_block_generic(&block, &mut soft);
                let mut hw = buf;
                encrypt_block(&mut hw, &enc_key);
                assert_eq!(soft, hw, "encrypt key_len={key_len}");

                let mut soft_dec = hw;
                generic::decrypt_block_generic(&block, &mut soft_dec);
                let mut hw_dec = hw;
                decrypt_block(&mut hw_dec, &dec_key);
                assert_eq!(soft_dec, hw_dec, "decrypt key_len={key_len}");
            }
        }
    }

    /// CBC and ECB bulk bodies against the per-block software implementation.
    #[test]
    fn aesv8_bulk_matches_generic() {
        if !supported() {
            return;
        }
        for key_len in [16usize, 32] {
            let mut key = alloc::vec![0u8; key_len];
            rand::fill(&mut key[..]);
            let enc_key = set_encrypt_key(&key);
            let dec_key = set_decrypt_key(&key);
            let mut block = BlockExpanded::default();
            block.expand(&key);

            for blocks in [1usize, 2, 3, 4, 5, 8, 17] {
                let mut data = alloc::vec![0u8; blocks * 16];
                rand::fill(&mut data[..]);
                let mut iv = [0u8; 16];
                rand::fill(&mut iv);

                // ECB encrypt/decrypt
                let mut soft = data.clone();
                for chunk in soft.as_chunks_mut::<16>().0 {
                    generic::encrypt_block_generic(&block, chunk);
                }
                let mut hw = data.clone();
                ecb_encrypt(&mut hw, &enc_key, true);
                assert_eq!(soft, hw, "ecb enc blocks={blocks}");

                let mut soft_dec = hw.clone();
                for chunk in soft_dec.as_chunks_mut::<16>().0 {
                    generic::decrypt_block_generic(&block, chunk);
                }
                let mut hw_dec = hw.clone();
                ecb_encrypt(&mut hw_dec, &dec_key, false);
                assert_eq!(soft_dec, hw_dec, "ecb dec blocks={blocks}");

                // CBC encrypt/decrypt: compare against the per-block chain
                let mut soft_cbc = data.clone();
                let mut prev = iv;
                for chunk in soft_cbc.as_chunks_mut::<16>().0 {
                    for j in 0..16 {
                        chunk[j] ^= prev[j];
                    }
                    generic::encrypt_block_generic(&block, chunk);
                    prev = *chunk;
                }
                let mut hw_cbc = data.clone();
                let mut hw_iv = iv;
                cbc_encrypt(&mut hw_cbc, &enc_key, &mut hw_iv, true);
                assert_eq!(soft_cbc, hw_cbc, "cbc enc blocks={blocks}");
                assert_eq!(hw_iv, prev, "cbc enc iv blocks={blocks}");

                // Software CBC decryption, the same backwards chain as
                // `cbc/decrypt.rs`: block i is XORed with ct_{i-1}, with the
                // IV standing in for ct_{-1}.
                let mut soft_dec = soft_cbc.clone();
                let mut hl = soft_dec.len();
                while hl > 0 {
                    let start = hl - 16;
                    let mut prev_ct = [0u8; 16];
                    if start > 0 {
                        prev_ct.copy_from_slice(&soft_dec[start - 16..start]);
                    } else {
                        prev_ct = iv;
                    }
                    generic::decrypt_block_generic(&block, &mut soft_dec[start..hl]);
                    for j in 0..16 {
                        soft_dec[start + j] ^= prev_ct[j];
                    }
                    hl = start;
                }
                let mut hw_dec = soft_cbc.clone();
                let mut hw_iv = iv;
                cbc_encrypt(&mut hw_dec, &dec_key, &mut hw_iv, false);
                assert_eq!(soft_dec, hw_dec, "cbc dec blocks={blocks}");
            }
        }
    }
}

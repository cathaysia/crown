//! AES T-table implementation for x86_64 (aes-x86_64.pl).
//!
//! Exposes OpenSSL-compatible `AES_set_*_key` / `AES_encrypt` / `AES_decrypt`
//! over the FIPS-197 round-key schedule in `AesKey`.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/aes/ttable.ts"),
    options(att_syntax)
);

/// OpenSSL `AES_KEY`: 15 round keys then the round count.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AesKey {
    pub rd_key: [u32; 60],
    pub rounds: u32,
}

extern "C" {
    fn AES_set_encrypt_key(user_key: *const u8, bits: i32, key: *mut AesKey) -> i32;
    fn AES_set_decrypt_key(user_key: *const u8, bits: i32, key: *mut AesKey) -> i32;
    fn AES_encrypt(inp: *const u8, out: *mut u8, key: *const AesKey);
    fn AES_decrypt(inp: *const u8, out: *mut u8, key: *const AesKey);
}

pub fn set_encrypt_key(user_key: &[u8]) -> AesKey {
    let mut key = AesKey {
        rd_key: [0; 60],
        rounds: 0,
    };
    let rc =
        unsafe { AES_set_encrypt_key(user_key.as_ptr(), (user_key.len() * 8) as i32, &mut key) };
    debug_assert_eq!(rc, 0, "AES_set_encrypt_key failed: {rc}");
    key
}

pub fn set_decrypt_key(user_key: &[u8]) -> AesKey {
    let mut key = AesKey {
        rd_key: [0; 60],
        rounds: 0,
    };
    let rc =
        unsafe { AES_set_decrypt_key(user_key.as_ptr(), (user_key.len() * 8) as i32, &mut key) };
    debug_assert_eq!(rc, 0, "AES_set_decrypt_key failed: {rc}");
    key
}

pub fn encrypt_block(inout: &mut [u8], key: &AesKey) {
    let p = inout.as_mut_ptr();
    unsafe { AES_encrypt(p, p, key) }
}

pub fn decrypt_block(inout: &mut [u8], key: &AesKey) {
    let p = inout.as_mut_ptr();
    unsafe { AES_decrypt(p, p, key) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::aes::{generic, BlockExpanded};

    #[test]
    fn ttable_matches_generic() {
        for key_len in [16usize, 24, 32] {
            let mut key = vec![0u8; key_len];
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
}

use core::arch::global_asm;

use crown_derive::jsasm_file;

use super::ChaCha20Poly1305;
use crate::error::{CryptoError, CryptoResult};

global_asm!(
    jsasm_file!("crown/src/aead/chacha20poly1305/x86_64.js", "{}"),
    options(att_syntax)
);

extern "C" {
    fn chacha20_poly1305_seal_sse41(
        plaintext: *const u8,
        ciphertext: *mut u8,
        plaintext_len: usize,
        ad: *const u8,
        ad_len: usize,
        key: *const u8,
        nonce: *const u8,
        tag: *mut u8,
    ) -> i32;

    fn chacha20_poly1305_open_sse41(
        ciphertext: *const u8,
        plaintext: *mut u8,
        ciphertext_len: usize,
        ad: *const u8,
        ad_len: usize,
        key: *const u8,
        nonce: *const u8,
        tag: *const u8,
    ) -> i32;

    fn chacha20_poly1305_seal_avx2(
        plaintext: *const u8,
        ciphertext: *mut u8,
        plaintext_len: usize,
        ad: *const u8,
        ad_len: usize,
        key: *const u8,
        nonce: *const u8,
        tag: *mut u8,
    ) -> i32;

    fn chacha20_poly1305_open_avx2(
        ciphertext: *const u8,
        plaintext: *mut u8,
        ciphertext_len: usize,
        ad: *const u8,
        ad_len: usize,
        key: *const u8,
        nonce: *const u8,
        tag: *const u8,
    ) -> i32;
}

impl ChaCha20Poly1305 {
    pub(super) fn seal_x86_64(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; 16]> {
        let mut tag = [0u8; 16];

        let result = if is_x86_feature_detected!("avx2") {
            unsafe {
                chacha20_poly1305_seal_avx2(
                    inout.as_ptr(),
                    inout.as_mut_ptr(),
                    inout.len(),
                    additional_data.as_ptr(),
                    additional_data.len(),
                    self.key.as_ptr(),
                    nonce.as_ptr(),
                    tag.as_mut_ptr(),
                )
            }
        } else if is_x86_feature_detected!("sse4.1") {
            unsafe {
                chacha20_poly1305_seal_sse41(
                    inout.as_ptr(),
                    inout.as_mut_ptr(),
                    inout.len(),
                    additional_data.as_ptr(),
                    additional_data.len(),
                    self.key.as_ptr(),
                    nonce.as_ptr(),
                    tag.as_mut_ptr(),
                )
            }
        } else {
            return self.seal_generic(inout, nonce, additional_data);
        };

        if result == 0 {
            Ok(tag)
        } else {
            Err(CryptoError::InvalidHasher)
        }
    }

    pub(super) fn open_x86_64(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        if tag.len() != 16 {
            return Err(CryptoError::InvalidTagSize {
                expected: "16",
                actual: tag.len(),
            });
        }

        let result = if is_x86_feature_detected!("avx2") {
            unsafe {
                chacha20_poly1305_open_avx2(
                    inout.as_ptr(),
                    inout.as_mut_ptr(),
                    inout.len(),
                    additional_data.as_ptr(),
                    additional_data.len(),
                    self.key.as_ptr(),
                    nonce.as_ptr(),
                    tag.as_ptr(),
                )
            }
        } else if is_x86_feature_detected!("sse4.1") {
            unsafe {
                chacha20_poly1305_open_sse41(
                    inout.as_ptr(),
                    inout.as_mut_ptr(),
                    inout.len(),
                    additional_data.as_ptr(),
                    additional_data.len(),
                    self.key.as_ptr(),
                    nonce.as_ptr(),
                    tag.as_ptr(),
                )
            }
        } else {
            return self.open_generic(inout, tag, nonce, additional_data);
        };

        if result == 0 {
            Ok(())
        } else {
            Err(CryptoError::AuthenticationFailed)
        }
    }
}

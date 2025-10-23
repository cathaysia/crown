use super::ChaCha20Poly1305;
use crate::error::{CryptoError, CryptoResult};
use core::arch::global_asm;

global_asm!(
    include_str!("./chacha20_poly1305_x86_64-linux.S"),
    options(att_syntax)
);

#[repr(C)]
#[derive(Copy, Clone)]
union ChaCha20Poly1305SealData {
    input: ChaCha20Poly1305SealInput,
    output: ChaCha20Poly1305SealOutput,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ChaCha20Poly1305SealInput {
    key: [u8; 32],
    counter: u32,
    nonce: [u8; 12],
    extra_ciphertext: *const u8,
    extra_ciphertext_len: usize,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ChaCha20Poly1305SealOutput {
    tag: [u8; 16],
}

extern "C" {
    fn chacha20_poly1305_seal_sse41(
        out_ciphertext: *mut u8,
        plaintext: *const u8,
        plaintext_len: usize,
        ad: *const u8,
        ad_len: usize,
        data: *mut ChaCha20Poly1305SealData,
    );

    fn chacha20_poly1305_seal_avx2(
        out_ciphertext: *mut u8,
        plaintext: *const u8,
        plaintext_len: usize,
        ad: *const u8,
        ad_len: usize,
        data: *mut ChaCha20Poly1305SealData,
    );

    fn chacha20_poly1305_open_sse41(
        plaintext: *mut u8,
        ciphertext: *const u8,
        ciphertext_len: usize,
        ad: *const u8,
        ad_len: usize,
        data: *mut ChaCha20Poly1305SealData,
    ) -> i32;

    fn chacha20_poly1305_open_avx2(
        plaintext: *mut u8,
        ciphertext: *const u8,
        ciphertext_len: usize,
        ad: *const u8,
        ad_len: usize,
        data: *mut ChaCha20Poly1305SealData,
    ) -> i32;
}

fn has_avx2() -> bool {
    std::arch::is_x86_feature_detected!("avx2")
}

impl ChaCha20Poly1305 {
    pub(crate) fn seal_asm(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; 16]> {
        let nonce_array: [u8; 12] = nonce.try_into().unwrap();

        let mut data = ChaCha20Poly1305SealData {
            input: ChaCha20Poly1305SealInput {
                key: self.key,
                counter: 1,
                nonce: nonce_array,
                extra_ciphertext: core::ptr::null(),
                extra_ciphertext_len: 0,
            },
        };

        unsafe {
            if has_avx2() {
                chacha20_poly1305_seal_avx2(
                    inout.as_mut_ptr(),
                    inout.as_ptr(),
                    inout.len(),
                    additional_data.as_ptr(),
                    additional_data.len(),
                    &mut data,
                );
            } else {
                chacha20_poly1305_seal_sse41(
                    inout.as_mut_ptr(),
                    inout.as_ptr(),
                    inout.len(),
                    additional_data.as_ptr(),
                    additional_data.len(),
                    &mut data,
                );
            }

            Ok(data.output.tag)
        }
    }

    pub(crate) fn open_asm(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        let nonce_array: [u8; 12] = nonce.try_into().unwrap();
        let mut expected_tag = [0u8; 16];
        expected_tag.copy_from_slice(tag);

        let mut data = ChaCha20Poly1305SealData {
            input: ChaCha20Poly1305SealInput {
                key: self.key,
                counter: 1,
                nonce: nonce_array,
                extra_ciphertext: core::ptr::null(),
                extra_ciphertext_len: 0,
            },
        };
        data.output.tag = expected_tag;

        let result = unsafe {
            if has_avx2() {
                chacha20_poly1305_open_avx2(
                    inout.as_mut_ptr(),
                    inout.as_ptr(),
                    inout.len(),
                    additional_data.as_ptr(),
                    additional_data.len(),
                    &mut data,
                )
            } else {
                chacha20_poly1305_open_sse41(
                    inout.as_mut_ptr(),
                    inout.as_ptr(),
                    inout.len(),
                    additional_data.as_ptr(),
                    additional_data.len(),
                    &mut data,
                )
            }
        };

        if result == 0 {
            Ok(())
        } else {
            Err(CryptoError::AuthenticationFailed)
        }
    }
}

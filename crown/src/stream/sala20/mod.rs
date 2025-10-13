//! Module salsa20 implements the Salsa20 stream cipher as specified in <https://cr.yp.to/snuffle/spec.pdf>.
//!
//! Salsa20 differs from many other stream ciphers in that it is message orientated
//! rather than byte orientated. Keystream blocks are not preserved between calls,
//! therefore each side must encrypt/decrypt data with the same segmentation.
//!
//! Another aspect of this difference is that part of the counter is exposed as
//! a nonce in each call. Encrypting two different messages with the same (key,
//! nonce) pair leads to trivial plaintext recovery. This is analogous to
//! encrypting two different messages with the same key with a traditional stream
//! cipher.
//!
//! This package also implements XSalsa20: a version of Salsa20 with a 24-byte
//! nonce as specified in <https://cr.yp.to/snuffle/xsalsa-20081128.pdf>. Simply
//! passing a 24-byte slice as the nonce triggers XSalsa20.

mod hsala20;
mod noasm;
mod sala20_ref;

pub use hsala20::SIGMA;

#[cfg(test)]
mod tests;

use crate::{
    error::{CryptoError, CryptoResult},
    stream::StreamCipher,
    utils::copy,
};
use hsala20::hsalsa20;
use noasm::xor_key_stream;

pub struct Sala20 {
    key: [u8; 32],
    nonce: [u8; 24],
    nonce_len: usize,
}

impl Sala20 {
    pub fn new(key: &[u8], nonce: &[u8]) -> CryptoResult<Sala20> {
        if nonce.len() != 8 && nonce.len() != 24 {
            return Err(CryptoError::InvalidNonceSize {
                expected: "8 | 24",
                actual: nonce.len(),
            });
        }
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeySize {
                expected: "32",
                actual: key.len(),
            });
        }
        let mut nonce2 = [0u8; 24];
        nonce2[..nonce.len()].copy_from_slice(nonce);

        Ok(Self {
            key: key.try_into().unwrap(),
            nonce: nonce2,
            nonce_len: nonce.len(),
        })
    }
}

impl StreamCipher for Sala20 {
    fn xor_key_stream(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
        let Self {
            key,
            nonce,
            nonce_len,
        } = &*self;

        let mut sub_nonce = [0u8; 16];
        let mut actual_key: [u8; 32] = [0u8; 32];

        match nonce_len {
            24 => {
                // XSalsa20 mode
                let mut sub_key = [0u8; 32];
                sub_key[..16].copy_from_slice(&nonce[..16]);

                hsalsa20(&mut sub_key, key, &SIGMA);
                copy(&mut sub_nonce, &nonce[16..]);
                actual_key = sub_key;
            }
            8 => {
                // Salsa20 mode
                sub_nonce[..8].copy_from_slice(&nonce[..8]);
                actual_key.copy_from_slice(key);
            }
            _ => {
                unreachable!()
            }
        }

        // Apply XOR keystream
        xor_key_stream(inout, &mut sub_nonce, &actual_key)?;

        Ok(())
    }
}

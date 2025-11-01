#![allow(dead_code)]

use super::ChaCha20Poly1305;
use crate::{
    error::{CryptoError, CryptoResult},
    stream::StreamCipher,
    utils::subtle::constant_time_eq,
};

type ChaCha20 = crate::stream::chacha20::Chacha20;
type Poly1305 = crate::mac::poly1305::Poly1305;

const POLY1305_TAG_SIZE: usize = 16;

impl ChaCha20Poly1305 {
    fn write_with_padding(poly: &mut Poly1305, data: &[u8]) {
        poly.write(data);
        let rem = data.len() % 16;
        if rem != 0 {
            let pad_len = 16 - rem;
            let padding = [0u8; 16];
            poly.write(&padding[..pad_len]);
        }
    }

    fn write_uint64(poly: &mut Poly1305, n: usize) {
        let bytes = (n as u64).to_le_bytes();
        poly.write(&bytes);
    }

    pub(crate) fn seal_generic(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; 16]> {
        // Generate poly1305 key using ChaCha20
        let mut poly_key = [0u8; 32];
        let mut cipher = ChaCha20::new(&self.key, nonce)?;
        cipher.xor_key_stream(&mut poly_key)?;

        // Set counter to 1, skipping first 32 bytes
        cipher.set_counter(1);
        cipher.xor_key_stream(inout)?;

        // Authenticate with Poly1305
        let mut poly = Poly1305::new(&poly_key);
        Self::write_with_padding(&mut poly, additional_data);
        Self::write_with_padding(&mut poly, inout);
        Self::write_uint64(&mut poly, additional_data.len());
        Self::write_uint64(&mut poly, inout.len());

        Ok(poly.sum())
    }

    pub(crate) fn open_generic(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        if tag.len() != POLY1305_TAG_SIZE {
            return Err(CryptoError::InvalidTagSize {
                expected: "16",
                actual: tag.len(),
            });
        }

        // Generate poly1305 key using ChaCha20
        let mut poly_key = [0u8; 32];
        let mut cipher = ChaCha20::new(&self.key, nonce)?;
        cipher.xor_key_stream(&mut poly_key)?;

        // Set counter to 1, skipping first 32 bytes
        cipher.set_counter(1);

        // Verify authentication tag
        let mut poly = Poly1305::new(&poly_key);
        Self::write_with_padding(&mut poly, additional_data);
        Self::write_with_padding(&mut poly, inout);
        Self::write_uint64(&mut poly, additional_data.len());
        Self::write_uint64(&mut poly, inout.len());

        let computed_tag = poly.sum();
        if !constant_time_eq(&computed_tag, tag) {
            return Err(CryptoError::AuthenticationFailed);
        }

        cipher.xor_key_stream(inout)?;

        Ok(())
    }
}

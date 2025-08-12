use crate::{
    chacha20ploy1305::ChaCha20Poly1305,
    cipher::StreamCipher,
    error::{CryptoError, CryptoResult},
    utils::constant_time_eq,
};

type ChaCha20 = crate::chacha20::Chacha20;
type Poly1305 = crate::ploy1305::MAC;

const POLY1305_TAG_SIZE: usize = 16;

impl ChaCha20Poly1305 {
    fn write_with_padding(poly: &mut Poly1305, data: &[u8]) {
        poly.write(data);
        let rem = data.len() % 16;
        if rem != 0 {
            let pad_len = 16 - rem;
            let padding = vec![0u8; pad_len];
            poly.write(&padding);
        }
    }

    fn write_uint64(poly: &mut Poly1305, n: usize) {
        let bytes = (n as u64).to_le_bytes();
        poly.write(&bytes);
    }

    fn slice_for_append(dst: &mut Vec<u8>, n: usize) -> usize {
        let start = dst.len();
        dst.resize(start + n, 0);
        start
    }

    pub(crate) fn seal_generic(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        let start = Self::slice_for_append(dst, plaintext.len() + POLY1305_TAG_SIZE);
        let (ciphertext, tag) = dst[start..].split_at_mut(plaintext.len());

        // Generate poly1305 key using ChaCha20
        let mut poly_key = [0u8; 32];
        let mut cipher = ChaCha20::new_unauthenticated_cipher(&self.key, nonce)?;
        let src = poly_key;
        cipher.xor_key_stream(&mut poly_key, &src)?;

        // Set counter to 1, skipping first 32 bytes
        cipher.set_counter(1);
        cipher.xor_key_stream(ciphertext, plaintext)?;

        // Authenticate with Poly1305
        let mut poly = Poly1305::new(&poly_key);
        Self::write_with_padding(&mut poly, additional_data);
        Self::write_with_padding(&mut poly, ciphertext);
        Self::write_uint64(&mut poly, additional_data.len());
        Self::write_uint64(&mut poly, plaintext.len());

        let mut computed_tag = unsafe { std::mem::zeroed() };
        poly.sum(&mut computed_tag);
        tag[..POLY1305_TAG_SIZE].copy_from_slice(&computed_tag);

        Ok(())
    }

    pub(crate) fn open_generic(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        ciphertext_with_tag: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        if ciphertext_with_tag.len() < POLY1305_TAG_SIZE {
            return Err(CryptoError::InvalidLength);
        }

        let (ciphertext, tag) =
            ciphertext_with_tag.split_at(ciphertext_with_tag.len() - POLY1305_TAG_SIZE);

        // Generate poly1305 key using ChaCha20
        let mut poly_key = [0u8; 32];
        let mut cipher = ChaCha20::new_unauthenticated_cipher(&self.key, nonce)?;
        let src = poly_key;
        cipher.xor_key_stream(&mut poly_key, &src)?;

        // Set counter to 1, skipping first 32 bytes
        cipher.set_counter(1);

        // Verify authentication tag
        let mut poly = Poly1305::new(&poly_key);
        Self::write_with_padding(&mut poly, additional_data);
        Self::write_with_padding(&mut poly, ciphertext);
        Self::write_uint64(&mut poly, additional_data.len());
        Self::write_uint64(&mut poly, ciphertext.len());

        let mut computed_tag = unsafe { std::mem::zeroed() };
        poly.sum(&mut computed_tag);
        if !constant_time_eq(&computed_tag, tag) {
            return Err(CryptoError::AuthenticationFailed);
        }

        // Decrypt
        let start = Self::slice_for_append(dst, ciphertext.len());
        let plaintext = &mut dst[start..];
        cipher.xor_key_stream(plaintext, ciphertext)?;

        Ok(())
    }
}

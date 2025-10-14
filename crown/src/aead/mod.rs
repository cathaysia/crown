//! # Authenticated Encryption with Associated Data (AEAD)
//!
//! This module provides AEAD cipher implementations that combine encryption and authentication
//! in a single operation. AEAD ciphers ensure both confidentiality and authenticity of data.
//!
//! The module includes native AEAD algorithms like ChaCha20-Poly1305, as well as modes like
//! GCM and OCB3 that can transform block ciphers and stream ciphers into AEAD constructions.

pub mod chacha20poly1305;
#[cfg(feature = "alloc")]
pub mod gcm;
pub mod ocb3;

use crate::error::CryptoResult;

pub trait AeadUser {
    /// nonce_size returns the size of the nonce that must be passed to Seal
    /// and Open.
    fn nonce_size(&self) -> usize;

    /// tag_size returns the size of the tag.
    fn tag_size(&self) -> usize;
}

/// AEAD is a cipher mode providing authenticated encryption with associated
/// data. For a description of the methodology, see
/// <https://en.wikipedia.org/wiki/Authenticated_encryption>.
pub trait Aead<const N: usize>: AeadUser {
    /// Seal encrypts and authenticates plaintext, authenticates the
    /// additional data and appends the result to dst, returning the updated
    /// slice. The nonce must be NonceSize() bytes long and unique for all
    /// time, for a given key.
    ///
    /// To reuse plaintext's storage for the encrypted output, use `plaintext[:0]`
    /// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
    /// dst and additionalData may not overlap.
    fn seal_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; N]>;

    fn seal_in_place_append_tag<T>(
        &self,
        inout: &mut T,
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()>
    where
        T: Extend<u8> + AsMut<[u8]> + ?Sized,
    {
        let tag = self.seal_in_place_separate_tag(inout.as_mut(), nonce, additional_data)?;
        inout.extend(tag);
        Ok(())
    }
    /// Open decrypts and authenticates ciphertext, authenticates the
    /// additional data and, if successful, appends the resulting plaintext
    /// to dst, returning the updated slice. The nonce must be NonceSize()
    /// bytes long and both it and the additional data must match the
    /// value passed to Seal.
    ///
    /// To reuse ciphertext's storage for the decrypted output, use `ciphertext[:0]`
    /// as dst. Otherwise, the remaining capacity of dst must not overlap ciphertext.
    /// dst and additionalData may not overlap.
    ///
    /// Even if the function fails, the contents of dst, up to its capacity,
    /// may be overwritten.
    fn open_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()>;

    fn open_in_place<'a>(
        &self,
        inout: &'a mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<&'a mut [u8]> {
        let pos = inout.len() - N;
        let (inout, tag) = inout.split_at_mut(pos);
        self.open_in_place_separate_tag(inout, tag, nonce, additional_data)?;
        Ok(inout)
    }
}

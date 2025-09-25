pub mod chacha20poly1305;
#[cfg(feature = "std")]
pub mod gcm;
pub mod ocb;

use crate::error::CryptoResult;

pub trait AeadUser {
    /// NonceSize returns the size of the nonce that must be passed to Seal
    /// and Open.
    fn nonce_size(&self) -> usize;

    /// Overhead returns the maximum difference between the lengths of a
    /// plaintext and its ciphertext.
    fn overhead(&self) -> usize;
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

    #[cfg(feature = "alloc")]
    fn seal_in_place_append_tag(
        &self,
        inout: &mut alloc::vec::Vec<u8>,
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        let tag = self.seal_in_place_separate_tag(inout, nonce, additional_data)?;
        inout.extend_from_slice(&tag);
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

    #[cfg(feature = "alloc")]
    fn open_in_place(
        &self,
        inout: &mut alloc::vec::Vec<u8>,
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        let pos = inout.len() - N;
        let (inout1, tag) = inout.split_at_mut(pos);
        self.open_in_place_separate_tag(inout1, tag, nonce, additional_data)?;
        inout.truncate(pos);
        Ok(())
    }
}

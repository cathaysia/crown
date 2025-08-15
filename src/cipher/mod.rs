pub mod cbc;
pub mod cfb;
pub mod ctr;
pub mod erased;
pub mod marker;
pub mod ofb;

#[cfg(test)]
pub mod common_test;

use crate::error::CryptoResult;

/// A Block represents an implementation of block cipher
/// using a given key. It provides the capability to encrypt
/// or decrypt individual blocks. The mode implementations
/// extend that capability to streams of blocks.
pub trait BlockCipher {
    /// BlockSize returns the cipher's block size.
    fn block_size(&self) -> usize;

    /// Encrypt encrypts the first block in src into dst.
    /// Dst and src must overlap entirely or not at all.
    fn encrypt(&self, inout: &mut [u8]);

    /// Decrypt decrypts the first block in src into dst.
    /// Dst and src must overlap entirely or not at all.
    fn decrypt(&self, inout: &mut [u8]);
}

/// A Stream represents a stream cipher.
pub trait StreamCipher {
    /// XORKeyStream XORs each byte in the given slice with a byte from the
    /// cipher's key stream. Dst and src must overlap entirely or not at all.
    ///
    /// If len(dst) < len(src), XORKeyStream should panic. It is acceptable
    /// to pass a dst bigger than src, and in that case, XORKeyStream will
    /// only update dst[:len(src)] and will not touch the rest of dst.
    ///
    /// Multiple calls to XORKeyStream behave as if the concatenation of
    /// the src buffers was passed in a single run. That is, Stream
    /// maintains state and does not reset at each XORKeyStream call.
    fn xor_key_stream(&mut self, inout: &mut [u8]) -> CryptoResult<()>;
}

/// A BlockMode represents a block cipher running in a block-based mode (CBC,
/// ECB etc).
pub trait BlockMode {
    /// BlockSize returns the mode's block size.
    fn block_size(&self) -> usize;

    /// CryptBlocks encrypts or decrypts a number of blocks. The length of
    /// src must be a multiple of the block size. Dst and src must overlap
    /// entirely or not at all.
    ///
    /// If len(dst) < len(src), CryptBlocks should panic. It is acceptable
    /// to pass a dst bigger than src, and in that case, CryptBlocks will
    /// only update dst[:len(src)] and will not touch the rest of dst.
    ///
    /// Multiple calls to CryptBlocks behave as if the concatenation of
    /// the src buffers was passed in a single run. That is, BlockMode
    /// maintains state and does not reset at each CryptBlocks call.
    fn crypt_blocks(self, inout: &mut [u8]);
}

pub trait AeadUser {
    /// NonceSize returns the size of the nonce that must be passed to Seal
    /// and Open.
    fn nonce_size() -> usize;

    /// Overhead returns the maximum difference between the lengths of a
    /// plaintext and its ciphertext.
    fn overhead() -> usize;
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

    fn seal_in_place_append_tag(
        &self,
        inout: &mut Vec<u8>,
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

    fn open_in_place(
        &self,
        inout: &mut Vec<u8>,
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

pub mod cmac;
pub mod ctrkdf;
pub mod generic;
pub mod ghash;
pub mod nonces;

mod noasm;
pub use noasm::*;

use crate::aes::Block;
use crate::cipher::BlockCipher;
use crate::error::{CryptoError, CryptoResult};
use crate::utils::{any_overlap, inexact_overlap};

// GCM represents a Galois Counter Mode with a specific key.
pub struct GCM {
    cipher: Block,
    nonce_size: usize,
    tag_size: usize,
}

// Constants
pub const GCM_BLOCK_SIZE: usize = 16;
pub const GCM_TAG_SIZE: usize = 16;
pub const GCM_MINIMUM_TAG_SIZE: usize = 12; // NIST SP 800-38D recommends tags with 12 or more bytes.
pub const GCM_STANDARD_NONCE_SIZE: usize = 12;

impl GCM {
    /// Create a new GCM instance with the given cipher, nonce size, and tag size.
    pub fn new(cipher: Block, nonce_size: usize, tag_size: usize) -> CryptoResult<Self> {
        // This function is outlined to let the allocation happen on the parent stack.
        Self::new_gcm(cipher, nonce_size, tag_size)
    }

    /// Internal function to create a new GCM instance.
    /// This is marked as a separate function to avoid inlining complexity.
    fn new_gcm(cipher: Block, nonce_size: usize, tag_size: usize) -> CryptoResult<Self> {
        if !(GCM_MINIMUM_TAG_SIZE..=GCM_BLOCK_SIZE).contains(&tag_size) {
            return Err(CryptoError::InvalidParameter(
                "incorrect tag size given to GCM".to_string(),
            ));
        }
        if nonce_size == 0 {
            return Err(CryptoError::InvalidParameter(
                "the nonce can't have zero length".to_string(),
            ));
        }
        if cipher.block_size() != GCM_BLOCK_SIZE {
            return Err(CryptoError::InvalidParameter(
                "NewGCM requires 128-bit block cipher".to_string(),
            ));
        }

        Ok(GCM {
            cipher,
            nonce_size,
            tag_size,
        })
    }

    /// Returns the size of the nonce that must be passed to Seal and Open.
    pub fn nonce_size(&self) -> usize {
        self.nonce_size
    }

    /// Returns the maximum difference between the lengths of a plaintext
    /// and its ciphertext.
    pub fn overhead(&self) -> usize {
        self.tag_size
    }

    /// Encrypts and authenticates plaintext, authenticates the additional data and
    /// appends the result to dst, returning the updated slice. The nonce must be
    /// NonceSize() bytes long and unique for all time, for a given key.
    pub fn seal(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        plaintext: &[u8],
        data: &[u8],
    ) -> CryptoResult<()> {
        self.seal_after_indicator(dst, nonce, plaintext, data)
    }

    fn seal_after_indicator(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        plaintext: &[u8],
        data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != self.nonce_size {
            return Err(CryptoError::InvalidParameter(
                "incorrect nonce length given to GCM".to_string(),
            ));
        }
        if self.nonce_size == 0 {
            return Err(CryptoError::InvalidParameter(
                "incorrect GCM nonce size".to_string(),
            ));
        }
        if plaintext.len() as u64 > (1u64 << 32) - 2 * GCM_BLOCK_SIZE as u64 {
            return Err(CryptoError::InvalidParameter(
                "message too large for GCM".to_string(),
            ));
        }

        dst.resize(plaintext.len() + self.tag_size, 0);

        // Check for buffer overlaps
        if inexact_overlap(&dst[..plaintext.len()], plaintext) {
            return Err(CryptoError::InvalidBufferOverlap);
        }
        if any_overlap(dst, data) {
            return Err(CryptoError::InvalidBufferOverlap);
        }

        // Call the seal implementation
        seal(dst, self, nonce, plaintext, data);

        Ok(())
    }

    /// Decrypts and authenticates ciphertext, authenticates the additional data and,
    /// if successful, appends the resulting plaintext to dst, returning the updated
    /// slice. The nonce must be NonceSize() bytes long and the ciphertext must
    /// be longer than Overhead() bytes.
    pub fn open(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        ciphertext: &[u8],
        data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != self.nonce_size {
            return Err(CryptoError::InvalidParameter(
                "incorrect nonce length given to GCM".to_string(),
            ));
        }
        // Sanity check to prevent the authentication from always succeeding if an
        // implementation leaves tag_size uninitialized, for example.
        if self.tag_size < GCM_MINIMUM_TAG_SIZE {
            return Err(CryptoError::InvalidParameter(
                "incorrect GCM tag size".to_string(),
            ));
        }

        if ciphertext.len() < self.tag_size {
            return Err(CryptoError::AuthenticationFailed);
        }
        if ciphertext.len() as u64 > (1u64 << 32) - 2 * GCM_BLOCK_SIZE as u64 + self.tag_size as u64
        {
            return Err(CryptoError::AuthenticationFailed);
        }

        dst.shrink_to(ciphertext.len() - self.tag_size);

        // Check for buffer overlaps
        if inexact_overlap(dst, ciphertext) {
            return Err(CryptoError::InvalidBufferOverlap);
        }
        if any_overlap(dst, data) {
            return Err(CryptoError::InvalidBufferOverlap);
        }

        match open(dst, self, nonce, ciphertext, data) {
            Ok(()) => Ok(()),
            Err(err) => {
                // We sometimes decrypt and authenticate concurrently, so we overwrite
                // dst in the event of a tag mismatch. To be consistent across platforms
                // and to avoid releasing unauthenticated plaintext, we clear the buffer
                // in the event of an error.
                dst.fill(0);
                Err(err)
            }
        }
    }
}

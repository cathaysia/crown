pub mod cmac;
pub mod ctrkdf;
pub mod generic;
pub mod ghash;
pub mod nonces;

mod noasm;
pub use noasm::*;

use crate::aead::{Aead, AeadUser};
use crate::block::aes::Aes;
use crate::block::BlockCipher;
use crate::error::{CryptoError, CryptoResult};
use crate::utils::{any_overlap, copy};

// GCM represents a Galois Counter Mode with a specific key.
pub struct Gcm<const N: usize = 12, const T: usize = 16> {
    cipher: Aes,
}

// Constants
pub const GCM_BLOCK_SIZE: usize = 16;
pub const GCM_TAG_SIZE: usize = 16;
pub const GCM_MINIMUM_TAG_SIZE: usize = 12; // NIST SP 800-38D recommends tags with 12 or more bytes.
pub const GCM_STANDARD_NONCE_SIZE: usize = 12;

impl<const N: usize, const T: usize> Gcm<N, T> {
    const _NONCE_ASSERT: () = assert!(N != 0);
    const _TAG_ASSERT: () = assert!(T >= GCM_MINIMUM_TAG_SIZE);

    pub fn new(cipher: Aes) -> CryptoResult<Self> {
        if !(GCM_MINIMUM_TAG_SIZE..=GCM_BLOCK_SIZE).contains(&T) {
            return Err(CryptoError::InvalidTagSize {
                expected: "12..=16",
                actual: T,
            });
        }
        if cipher.block_size() != GCM_BLOCK_SIZE {
            return Err(CryptoError::InvalidBlockSize(cipher.block_size()));
        }

        Ok(Gcm { cipher })
    }

    fn seal_after_indicator(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> CryptoResult<[u8; GCM_TAG_SIZE]> {
        if nonce.len() != N {
            return Err(CryptoError::InvalidNonceSize {
                expected: stringify!(N),
                actual: nonce.len(),
            });
        }

        if inout.len() as u64 > (1u64 << 32) - 2 * GCM_BLOCK_SIZE as u64 {
            return Err(CryptoError::MessageTooLarge);
        }

        if any_overlap(inout, aad) {
            return Err(CryptoError::InvalidBufferOverlap);
        }

        // Call the seal implementation
        Ok(seal(inout, self, nonce, aad))
    }
}

impl<const N: usize, const T: usize> AeadUser for Gcm<N, T> {
    fn nonce_size(&self) -> usize {
        N
    }

    fn overhead(&self) -> usize {
        T
    }
}

impl<const N: usize, const T: usize> Aead<T> for Gcm<N, T> {
    fn seal_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> CryptoResult<[u8; T]> {
        let tag = self.seal_after_indicator(inout, nonce, aad)?;
        let mut tag2 = [0u8; T];
        copy(&mut tag2, &tag);
        Ok(tag2)
    }

    fn open_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != N {
            return Err(CryptoError::InvalidNonceSize {
                expected: stringify!(N),
                actual: nonce.len(),
            });
        }

        if inout.len() as u64 > (1u64 << 32) - 2 * GCM_BLOCK_SIZE as u64 + T as u64 {
            return Err(CryptoError::AuthenticationFailed);
        }

        if any_overlap(inout, aad) {
            return Err(CryptoError::InvalidBufferOverlap);
        }

        match open::<N, T>(inout, self, nonce, aad, tag) {
            Ok(()) => Ok(()),
            Err(err) => {
                // We sometimes decrypt and authenticate concurrently, so we overwrite
                // dst in the event of a tag mismatch. To be consistent across platforms
                // and to avoid releasing unauthenticated plaintext, we clear the buffer
                // in the event of an error.
                inout.fill(0);
                Err(err)
            }
        }
    }
}

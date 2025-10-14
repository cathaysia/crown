#[cfg(test)]
mod tests;

use crate::aead::{Aead, AeadUser};
use crate::block::aes;
use crate::block::aes::gcm as aes_gcm;
use crate::block::BlockCipher;
use crate::block::BlockCipherMarker;
use crate::error::{CryptoError, CryptoResult};
use crate::utils::subtle::xor::xor_bytes;
use crate::utils::{copy, subtle::constant_time_eq};
use core::convert::TryInto;

// Constants
const GCM_BLOCK_SIZE: usize = 16;
const GCM_STANDARD_NONCE_SIZE: usize = 12;
const GCM_TAG_SIZE: usize = 16;
const GCM_MINIMUM_TAG_SIZE: usize = 12; // NIST SP 800-38D recommends tags with 12 or more bytes.

// GcmAble trait for types that can be converted to GCM mode
pub trait Gcm {
    fn to_gcm(self) -> CryptoResult<impl Aead<GCM_TAG_SIZE>>;
    fn to_gcm_with_params<const NONCE_SIZE: usize, const TAG_SIZE: usize>(
        self,
    ) -> CryptoResult<impl Aead<TAG_SIZE>>;
}

// Marker trait for type system
pub trait GcmMarker {}
impl<T: BlockCipherMarker> GcmMarker for T {}

// AES-specific GCM implementation
impl Gcm for aes::Aes {
    fn to_gcm(self) -> CryptoResult<impl Aead<GCM_TAG_SIZE>> {
        aes_gcm::Gcm::<GCM_STANDARD_NONCE_SIZE, GCM_TAG_SIZE>::new(self)
    }

    fn to_gcm_with_params<const NONCE_SIZE: usize, const TAG_SIZE: usize>(
        self,
    ) -> CryptoResult<impl Aead<TAG_SIZE>> {
        if !(GCM_MINIMUM_TAG_SIZE..=GCM_BLOCK_SIZE).contains(&TAG_SIZE) {
            return Err(CryptoError::InvalidTagSize {
                expected: "12..=16",
                actual: TAG_SIZE,
            });
        }

        aes_gcm::Gcm::<NONCE_SIZE, TAG_SIZE>::new(self)
    }
}

// Generic GCM implementation for any block cipher
impl<T> Gcm for T
where
    T: BlockCipher + GcmMarker + 'static,
{
    fn to_gcm(self) -> CryptoResult<impl Aead<GCM_TAG_SIZE>> {
        self.to_gcm_with_params::<GCM_STANDARD_NONCE_SIZE, GCM_TAG_SIZE>()
    }

    fn to_gcm_with_params<const NONCE_SIZE: usize, const TAG_SIZE: usize>(
        self,
    ) -> CryptoResult<impl Aead<TAG_SIZE>> {
        GcmGeneric::<Self, TAG_SIZE, NONCE_SIZE>::new(self)
    }
}

// Generic GCM implementation for non-AES ciphers
struct GcmGeneric<B: BlockCipher, const NONCE_SIZE: usize, const TAG_SIZE: usize> {
    cipher: B,
}

impl<B: BlockCipher, const NONCE_SIZE: usize, const TAG_SIZE: usize>
    GcmGeneric<B, TAG_SIZE, NONCE_SIZE>
{
    const _NONCE_ASSERT: () = assert!(NONCE_SIZE != 0);
    const _TAG_ASSERT_LOW: () = assert!(TAG_SIZE > GCM_MINIMUM_TAG_SIZE);
    const _TAG_ASSERT_HIGH: () = assert!(TAG_SIZE <= GCM_BLOCK_SIZE);

    fn new(cipher: B) -> CryptoResult<Self> {
        if cipher.block_size() != GCM_BLOCK_SIZE {
            return Err(CryptoError::UnsupportedBlockSize(cipher.block_size()));
        }

        Ok(Self { cipher })
    }
}

impl<B: BlockCipher, const NONCE_SIZE: usize, const TAG_SIZE: usize> AeadUser
    for GcmGeneric<B, NONCE_SIZE, TAG_SIZE>
{
    fn nonce_size(&self) -> usize {
        NONCE_SIZE
    }

    fn overhead(&self) -> usize {
        TAG_SIZE
    }
}

impl<B: BlockCipher, const NONCE_SIZE: usize, const TAG_SIZE: usize> Aead<NONCE_SIZE>
    for GcmGeneric<B, NONCE_SIZE, TAG_SIZE>
{
    fn seal_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; NONCE_SIZE]> {
        if nonce.len() != self.nonce_size() {
            return Err(CryptoError::InvalidNonceSize {
                expected: stringify!(N),
                actual: nonce.len(),
            });
        }

        if u64::try_from(inout.len()).unwrap()
            > ((1u64 << 32) - 2) * u64::try_from(GCM_BLOCK_SIZE).unwrap()
        {
            return Err(CryptoError::MessageTooLarge);
        }

        let mut h = [0u8; GCM_BLOCK_SIZE];
        let mut counter = [0u8; GCM_BLOCK_SIZE];
        let mut tag_mask = [0u8; GCM_BLOCK_SIZE];

        // Initialize H
        self.cipher.encrypt(&mut h);

        // Derive counter
        Self::derive_counter(&mut h, &mut counter, nonce);

        // Generate tag mask
        let tag_mask_copy = tag_mask;
        self.gcm_counter_crypt_generic(&mut tag_mask, &tag_mask_copy, &mut counter);

        // Encrypt data
        let src = inout.to_vec();
        self.gcm_counter_crypt_generic(inout, &src, &mut counter);

        // Compute authentication tag
        let mut tag = [0u8; GCM_TAG_SIZE];
        Self::gcm_auth(&mut tag, &mut h, &tag_mask, inout, additional_data);

        // Return the tag
        let mut result = [0u8; NONCE_SIZE];
        result.copy_from_slice(&tag[..NONCE_SIZE]);

        Ok(result)
    }

    fn open_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != self.nonce_size() {
            return Err(CryptoError::InvalidNonceSize {
                expected: stringify!(N),
                actual: nonce.len(),
            });
        }

        if tag.len() < TAG_SIZE {
            return Err(CryptoError::InvalidTagSize {
                expected: stringify!(T),
                actual: tag.len(),
            });
        }

        if u64::try_from(inout.len()).unwrap()
            > ((1u64 << 32) - 2) * u64::try_from(GCM_BLOCK_SIZE).unwrap()
                + u64::try_from(NONCE_SIZE).unwrap()
        {
            return Err(CryptoError::MessageTooLarge);
        }

        let mut h = [0u8; GCM_BLOCK_SIZE];
        let mut counter = [0u8; GCM_BLOCK_SIZE];
        let mut tag_mask = [0u8; GCM_BLOCK_SIZE];

        // Initialize H
        self.cipher.encrypt(&mut h);

        // Derive counter
        Self::derive_counter(&mut h, &mut counter, nonce);

        // Generate tag mask
        let tag_mask_copy = tag_mask;
        self.gcm_counter_crypt_generic(&mut tag_mask, &tag_mask_copy, &mut counter);

        // Compute expected tag
        let mut expected_tag = [0u8; GCM_TAG_SIZE];
        Self::gcm_auth(&mut expected_tag, &mut h, &tag_mask, inout, additional_data);

        // Verify tag
        if !constant_time_eq(&expected_tag[..NONCE_SIZE], tag) {
            // Clear output in case of tag mismatch
            for byte in inout.iter_mut() {
                *byte = 0;
            }
            return Err(CryptoError::AuthenticationFailed);
        }

        // Decrypt data
        let src = inout.to_vec();
        self.gcm_counter_crypt_generic(inout, &src, &mut counter);

        Ok(())
    }
}

impl<B: BlockCipher, const NONCE_SIZE: usize, const TAG_SIZE: usize>
    GcmGeneric<B, TAG_SIZE, NONCE_SIZE>
{
    // Helper functions for GCM operations
    fn derive_counter(
        h: &mut [u8; GCM_BLOCK_SIZE],
        counter: &mut [u8; GCM_BLOCK_SIZE],
        nonce: &[u8],
    ) {
        if nonce.len() == GCM_STANDARD_NONCE_SIZE {
            copy(counter, nonce);
            counter[GCM_BLOCK_SIZE - 1] = 1;
        } else {
            let mut len_block = [0u8; 16];
            let nonce_bits = (nonce.len() as u64) * 8;
            len_block[8..].copy_from_slice(&nonce_bits.to_be_bytes());

            aes_gcm::ghash::ghash(h, nonce.try_into().unwrap(), &[&len_block]);
            copy(counter, h);
        }
    }

    fn gcm_counter_crypt_generic(
        &self,
        out: &mut [u8],
        src: &[u8],
        counter: &mut [u8; GCM_BLOCK_SIZE],
    ) {
        let mut mask = [0u8; GCM_BLOCK_SIZE];
        let mut src_idx = 0;
        let mut out_idx = 0;

        while src_idx + GCM_BLOCK_SIZE <= src.len() {
            mask.copy_from_slice(&counter[..]);
            self.cipher.encrypt(&mut mask);
            Self::gcm_inc32(counter);

            for i in 0..GCM_BLOCK_SIZE {
                out[out_idx + i] = src[src_idx + i] ^ mask[i];
            }

            src_idx += GCM_BLOCK_SIZE;
            out_idx += GCM_BLOCK_SIZE;
        }

        if src_idx < src.len() {
            mask.copy_from_slice(&counter[..]);
            self.cipher.encrypt(&mut mask);
            Self::gcm_inc32(counter);

            for i in 0..(src.len() - src_idx) {
                out[out_idx + i] = src[src_idx + i] ^ mask[i];
            }
        }
    }

    fn gcm_inc32(counter_block: &mut [u8; GCM_BLOCK_SIZE]) {
        let mut ctr = u32::from_be_bytes([
            counter_block[GCM_BLOCK_SIZE - 4],
            counter_block[GCM_BLOCK_SIZE - 3],
            counter_block[GCM_BLOCK_SIZE - 2],
            counter_block[GCM_BLOCK_SIZE - 1],
        ]);

        ctr = ctr.wrapping_add(1);

        let ctr_bytes = ctr.to_be_bytes();
        counter_block[GCM_BLOCK_SIZE - 4] = ctr_bytes[0];
        counter_block[GCM_BLOCK_SIZE - 3] = ctr_bytes[1];
        counter_block[GCM_BLOCK_SIZE - 2] = ctr_bytes[2];
        counter_block[GCM_BLOCK_SIZE - 1] = ctr_bytes[3];
    }

    fn gcm_auth(
        out: &mut [u8],
        h: &mut [u8; GCM_BLOCK_SIZE],
        tag_mask: &[u8; GCM_BLOCK_SIZE],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) {
        let mut len_block = [0u8; 16];
        let ad_bits = (additional_data.len() as u64) * 8;
        let ct_bits = (ciphertext.len() as u64) * 8;

        len_block[..8].copy_from_slice(&ad_bits.to_be_bytes());
        len_block[8..].copy_from_slice(&ct_bits.to_be_bytes());

        // Compute GHASH(H, additional_data, ciphertext, len_block)
        aes_gcm::ghash::ghash(h, &additional_data.try_into().unwrap(), &[&len_block]);

        copy(out, h);
        xor_bytes(out, tag_mask);
    }
}

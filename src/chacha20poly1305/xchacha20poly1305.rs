use crate::{
    chacha20::h_chacha20,
    chacha20poly1305::ChaCha20Poly1305,
    cipher::{Aead, AeadUser},
    error::{CryptoError, CryptoResult},
};

/// XChacha20Ploy1305 is a ChaCha20-Poly1305 variant that takes a longer nonce,
/// suitable to be generated randomly without risk of collisions. It should be
/// preferred when nonce uniqueness cannot be trivially ensured, or whenever
/// nonces are randomly generated.
pub struct XChaCha20Poly1305 {
    key: [u8; Self::KEY_SIZE],
}

impl XChaCha20Poly1305 {
    pub const KEY_SIZE: usize = ChaCha20Poly1305::KEY_SIZE;
    pub const NONCE_SIZE: usize = 24;
    pub const OVERHEAD: usize = 16;

    /// returns a XChaCha20-Poly1305 AEAD that uses the given 256-bit key.
    ///
    /// XChaCha20-Poly1305 is a ChaCha20-Poly1305 variant that takes a longer nonce,
    /// suitable to be generated randomly without risk of collisions. It should be
    /// preferred when nonce uniqueness cannot be trivially ensured, or whenever
    /// nonces are randomly generated.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(CryptoError::InvalidKeySize(key.len()));
        }

        Ok(Self {
            key: key.try_into().unwrap(),
        })
    }
}

impl AeadUser for XChaCha20Poly1305 {
    fn nonce_size(&self) -> usize {
        Self::NONCE_SIZE
    }

    fn overhead(&self) -> usize {
        Self::OVERHEAD
    }
}

impl Aead<16> for XChaCha20Poly1305 {
    fn seal_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; 16]> {
        if nonce.len() != Self::NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize(nonce.len()));
        }

        // XChaCha20-Poly1305 technically supports a 64-bit counter, so there is no
        // size limit. However, since we reuse the ChaCha20-Poly1305 implementation,
        // the second half of the counter is not available. This is unlikely to be
        // an issue because the cipher.AEAD API requires the entire message to be in
        // memory, and the counter overflows at 256 GB.
        if inout.len() as u64 > (1u64 << 38) - 64 {
            panic!("chacha20poly1305: plaintext too large");
        }

        // Use HChaCha20 to derive a subkey from the first 16 bytes of the nonce
        let h_key = h_chacha20(&self.key, &nonce[0..16])?;
        let c = ChaCha20Poly1305::new(&h_key)?;

        // The first 4 bytes of the final nonce are unused counter space.
        let mut c_nonce = [0u8; ChaCha20Poly1305::NONCE_SIZE];
        c_nonce[4..12].copy_from_slice(&nonce[16..24]);

        c.seal_in_place_separate_tag(inout, &c_nonce, additional_data)
    }

    fn open_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != Self::NONCE_SIZE {
            panic!("chacha20poly1305: bad nonce length passed to Open");
        }
        if tag.len() < 16 {
            return Err(CryptoError::AuthenticationFailed);
        }
        if inout.len() as u64 > (1u64 << 38) - 48 {
            panic!("chacha20poly1305: ciphertext too large");
        }

        // Use HChaCha20 to derive a subkey from the first 16 bytes of the nonce
        let h_key = h_chacha20(&self.key, &nonce[0..16])?;
        let c = ChaCha20Poly1305::new(&h_key)?;

        // The first 4 bytes of the final nonce are unused counter space.
        let mut c_nonce = [0u8; ChaCha20Poly1305::NONCE_SIZE];
        c_nonce[4..12].copy_from_slice(&nonce[16..24]);

        c.open_in_place_separate_tag(inout, tag, &c_nonce, additional_data)
    }
}

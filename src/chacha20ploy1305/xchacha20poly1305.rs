use crate::{
    chacha20::h_chacha20,
    chacha20ploy1305::ChaCha20Poly1305,
    cipher::Aead,
    error::{CryptoError, CryptoResult},
};

/// XChacha20Ploy1305 is a ChaCha20-Poly1305 variant that takes a longer nonce,
/// suitable to be generated randomly without risk of collisions. It should be
/// preferred when nonce uniqueness cannot be trivially ensured, or whenever
/// nonces are randomly generated.
pub struct XChaCha20Ploy1305 {
    key: [u8; Self::KEY_SIZE],
}

impl XChaCha20Ploy1305 {
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

impl Aead for XChaCha20Ploy1305 {
    fn seal(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != Self::NONCE_SIZE {
            panic!("chacha20poly1305: bad nonce length passed to Seal");
        }

        // XChaCha20-Poly1305 technically supports a 64-bit counter, so there is no
        // size limit. However, since we reuse the ChaCha20-Poly1305 implementation,
        // the second half of the counter is not available. This is unlikely to be
        // an issue because the cipher.AEAD API requires the entire message to be in
        // memory, and the counter overflows at 256 GB.
        if plaintext.len() as u64 > (1u64 << 38) - 64 {
            panic!("chacha20poly1305: plaintext too large");
        }

        // Use HChaCha20 to derive a subkey from the first 16 bytes of the nonce
        let h_key = h_chacha20(&self.key, &nonce[0..16])?;
        let c = ChaCha20Poly1305::new(&h_key)?;

        // The first 4 bytes of the final nonce are unused counter space.
        let mut c_nonce = vec![0u8; ChaCha20Poly1305::NONCE_SIZE];
        c_nonce[4..12].copy_from_slice(&nonce[16..24]);

        c.seal(dst, &c_nonce, plaintext, additional_data)
    }

    fn open(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != Self::NONCE_SIZE {
            panic!("chacha20poly1305: bad nonce length passed to Open");
        }
        if ciphertext.len() < 16 {
            return Err(CryptoError::AuthenticationFailed);
        }
        if ciphertext.len() as u64 > (1u64 << 38) - 48 {
            panic!("chacha20poly1305: ciphertext too large");
        }

        // Use HChaCha20 to derive a subkey from the first 16 bytes of the nonce
        let h_key = h_chacha20(&self.key, &nonce[0..16])?;
        let c = ChaCha20Poly1305::new(&h_key)?;

        // The first 4 bytes of the final nonce are unused counter space.
        let mut c_nonce = vec![0u8; ChaCha20Poly1305::NONCE_SIZE];
        c_nonce[4..12].copy_from_slice(&nonce[16..24]);

        c.open(dst, &c_nonce, ciphertext, additional_data)
    }

    fn nonce_size() -> usize {
        Self::NONCE_SIZE
    }

    fn overhead() -> usize {
        Self::OVERHEAD
    }
}

//! Unified XTS interface (IEEE 1619 / NIST SP 800-38E).

use crate::block::aes::Aes;
use crate::block::sm4::Sm4;
use crate::error::{CryptoError, CryptoResult};
use crate::modes::xts::Xts;

/// XTS instance with type-erased cipher, keyed by the combined key.
pub struct EvpXts {
    inner: XtsInner,
}

enum XtsInner {
    Aes(Xts<Aes>),
    Sm4(Xts<Sm4>),
    Sm4Gb(Xts<Sm4>),
}

impl EvpXts {
    /// AES-XTS. Combined key is 32 bytes (AES-128-XTS) or 64 bytes (AES-256-XTS).
    pub fn new_aes_xts(key: &[u8]) -> CryptoResult<Self> {
        match key.len() {
            32 | 64 => Ok(Self {
                inner: XtsInner::Aes(Xts::<Aes>::new(key)?),
            }),
            len => Err(CryptoError::InvalidKeySize {
                expected: "32 | 64",
                actual: len,
            }),
        }
    }

    /// SM4-XTS (IEEE variant). Combined key is 32 bytes.
    pub fn new_sm4_xts(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeySize {
                expected: "32",
                actual: key.len(),
            });
        }
        Ok(Self {
            inner: XtsInner::Sm4(Xts::<Sm4>::new(key)?),
        })
    }

    /// SM4-XTS GB/T 17964-2021 variant. Combined key is 32 bytes.
    pub fn new_sm4_xts_gb(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeySize {
                expected: "32",
                actual: key.len(),
            });
        }
        Ok(Self {
            inner: XtsInner::Sm4Gb(Xts::<Sm4>::new(key)?),
        })
    }

    /// Encrypt `inout` in place under the 16-byte `tweak`.
    pub fn encrypt(&self, tweak: &[u8], inout: &mut [u8]) -> CryptoResult<()> {
        match &self.inner {
            XtsInner::Aes(x) => x.encrypt(tweak, inout),
            XtsInner::Sm4(x) => x.encrypt(tweak, inout),
            XtsInner::Sm4Gb(x) => x.encrypt_gb(tweak, inout),
        }
    }

    /// Decrypt `inout` in place under the 16-byte `tweak`.
    pub fn decrypt(&self, tweak: &[u8], inout: &mut [u8]) -> CryptoResult<()> {
        match &self.inner {
            XtsInner::Aes(x) => x.decrypt(tweak, inout),
            XtsInner::Sm4(x) => x.decrypt(tweak, inout),
            XtsInner::Sm4Gb(x) => x.decrypt_gb(tweak, inout),
        }
    }
}

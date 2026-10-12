use crate::crypto_err;
use crown::envelope::EvpXts;
use napi::bindgen_prelude::*;

#[napi]
pub struct Xts(EvpXts);

#[napi]
impl Xts {
    #[napi]
    pub fn new_aes(key: &[u8]) -> Result<Xts> {
        EvpXts::new_aes_xts(key)
            .map(Xts)
            .map_err(|e| crypto_err("Failed to create Xts", e))
    }

    #[napi]
    pub fn new_sm4(key: &[u8]) -> Result<Xts> {
        EvpXts::new_sm4_xts(key)
            .map(Xts)
            .map_err(|e| crypto_err("Failed to create Xts", e))
    }

    #[napi]
    pub fn new_sm4_gb(key: &[u8]) -> Result<Xts> {
        EvpXts::new_sm4_xts_gb(key)
            .map(Xts)
            .map_err(|e| crypto_err("Failed to create Xts", e))
    }

    #[napi]
    pub fn encrypt(&self, tweak: &[u8], mut data: Buffer) -> Result<()> {
        self.0
            .encrypt(tweak, &mut data)
            .map_err(|e| crypto_err("Encryption failed", e))
    }

    #[napi]
    pub fn decrypt(&self, tweak: &[u8], mut data: Buffer) -> Result<()> {
        self.0
            .decrypt(tweak, &mut data)
            .map_err(|e| crypto_err("Decryption failed", e))
    }
}

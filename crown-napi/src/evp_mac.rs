use crate::crypto_err;
use crown::envelope::EvpMac;
use napi::bindgen_prelude::*;

#[napi]
pub struct Mac(EvpMac);

#[napi]
impl Mac {
    #[napi]
    pub fn new_siphash(key: &[u8], output_len: u32) -> Result<Mac> {
        EvpMac::new_siphash(key, output_len as usize)
            .map(Mac)
            .map_err(|e| crypto_err("Failed to create Mac", e))
    }

    #[napi]
    pub fn new_kmac128(key: &[u8], custom: &[u8], output_len: u32) -> Result<Mac> {
        EvpMac::new_kmac128(key, custom, output_len as usize)
            .map(Mac)
            .map_err(|e| crypto_err("Failed to create Mac", e))
    }

    #[napi]
    pub fn new_kmac256(key: &[u8], custom: &[u8], output_len: u32) -> Result<Mac> {
        EvpMac::new_kmac256(key, custom, output_len as usize)
            .map(Mac)
            .map_err(|e| crypto_err("Failed to create Mac", e))
    }

    #[napi]
    pub fn new_cmac_aes(key: &[u8]) -> Result<Mac> {
        EvpMac::new_cmac_aes(key)
            .map(Mac)
            .map_err(|e| crypto_err("Failed to create Mac", e))
    }

    #[napi]
    pub fn new_gmac_aes(key: &[u8], iv: &[u8]) -> Result<Mac> {
        EvpMac::new_gmac_aes(key, iv)
            .map(Mac)
            .map_err(|e| crypto_err("Failed to create Mac", e))
    }

    #[napi]
    pub fn write(&mut self, data: &[u8]) {
        self.0.write(data);
    }

    #[napi]
    pub fn sum(&mut self) -> Buffer {
        Buffer::from(self.0.sum())
    }
}

use crown::envelope::EvpMac;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Mac(EvpMac);

#[wasm_bindgen]
impl Mac {
    #[wasm_bindgen]
    pub fn new_siphash(key: &[u8], output_len: usize) -> Result<Mac, JsValue> {
        EvpMac::new_siphash(key, output_len)
            .map(Mac)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    #[wasm_bindgen]
    pub fn new_kmac128(key: &[u8], custom: &[u8], output_len: usize) -> Result<Mac, JsValue> {
        EvpMac::new_kmac128(key, custom, output_len)
            .map(Mac)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    #[wasm_bindgen]
    pub fn new_kmac256(key: &[u8], custom: &[u8], output_len: usize) -> Result<Mac, JsValue> {
        EvpMac::new_kmac256(key, custom, output_len)
            .map(Mac)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    #[wasm_bindgen]
    pub fn new_cmac_aes(key: &[u8]) -> Result<Mac, JsValue> {
        EvpMac::new_cmac_aes(key)
            .map(Mac)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    #[wasm_bindgen]
    pub fn new_gmac_aes(key: &[u8], iv: &[u8]) -> Result<Mac, JsValue> {
        EvpMac::new_gmac_aes(key, iv)
            .map(Mac)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    #[wasm_bindgen]
    pub fn write(&mut self, data: &[u8]) {
        self.0.write(data);
    }

    #[wasm_bindgen]
    pub fn sum(&mut self) -> Vec<u8> {
        self.0.sum()
    }
}

use crown::envelope::EvpXts;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Xts(EvpXts);

#[wasm_bindgen]
impl Xts {
    #[wasm_bindgen]
    pub fn new_aes(key: &[u8]) -> Result<Xts, JsValue> {
        EvpXts::new_aes_xts(key)
            .map(Xts)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    #[wasm_bindgen]
    pub fn new_sm4(key: &[u8]) -> Result<Xts, JsValue> {
        EvpXts::new_sm4_xts(key)
            .map(Xts)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    #[wasm_bindgen]
    pub fn new_sm4_gb(key: &[u8]) -> Result<Xts, JsValue> {
        EvpXts::new_sm4_xts_gb(key)
            .map(Xts)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    #[wasm_bindgen]
    pub fn encrypt(&self, tweak: &[u8], data: &mut [u8]) -> Result<(), JsValue> {
        self.0
            .encrypt(tweak, data)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    #[wasm_bindgen]
    pub fn decrypt(&self, tweak: &[u8], data: &mut [u8]) -> Result<(), JsValue> {
        self.0
            .decrypt(tweak, data)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }
}

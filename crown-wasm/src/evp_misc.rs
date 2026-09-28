use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn aes_key_wrap(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
    crown::envelope::aes_key_wrap(key, plaintext)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn aes_key_unwrap(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
    crown::envelope::aes_key_unwrap(key, ciphertext)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn aes_key_wrap_padded(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
    crown::envelope::aes_key_wrap_padded(key, plaintext)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn aes_key_unwrap_padded(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
    crown::envelope::aes_key_unwrap_padded(key, ciphertext)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn ff1_encrypt_decimal(key: &[u8], tweak: &[u8], input: &str) -> Result<String, JsValue> {
    crown::envelope::ff1_encrypt_decimal(key, tweak, input)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn ff1_decrypt_decimal(key: &[u8], tweak: &[u8], input: &str) -> Result<String, JsValue> {
    crown::envelope::ff1_decrypt_decimal(key, tweak, input)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

use crown::core::{CoreRead, CoreWrite};
use crown::envelope::EvpHash;
use crown::hash::HashUser;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Hash(EvpHash);

macro_rules! impl_hash_methods {
    (
        normal: [$($normal:ident),* $(,)?],
        variant: [$($variant:ident),* $(,)?] $(,)?
    ) => {
        $(
            paste::paste! {
                #[wasm_bindgen]
                impl Hash {
                    #[wasm_bindgen]
                    pub fn [<new_ $normal:lower>]() -> Result<Hash, JsValue> {
                        match EvpHash::[<new_ $normal:lower>]() {
                            Ok(hash) => Ok(Hash(hash)),
                            Err(e) => Err(JsValue::from_str(&format!("Failed to create hash: {:?}", e))),
                        }
                    }

                    #[wasm_bindgen]
                    pub fn [<new_ $normal:lower _hmac>](key: &[u8]) -> Result<Hash, JsValue> {
                        match EvpHash::[<new_ $normal:lower _hmac>](key) {
                            Ok(hash) => Ok(Hash(hash)),
                            Err(e) => Err(JsValue::from_str(&format!("Failed to create HMAC: {:?}", e))),
                        }
                    }
                }
            }
        )*
        $(
            paste::paste! {
                #[wasm_bindgen]
                impl Hash {
                    #[wasm_bindgen]
                    pub fn [<new_ $variant:lower>](key: Option<Vec<u8>>, output_len: usize) -> Result<Hash, JsValue> {
                        let key_opt = key.as_ref().map(|k| k.as_slice());
                        match EvpHash::[<new_ $variant:lower>](key_opt, output_len) {
                            Ok(hash) => Ok(Hash(hash)),
                            Err(e) => Err(JsValue::from_str(&format!("Failed to create hash: {:?}", e))),
                        }
                    }
                }
            }
        )*
    };
}

impl_hash_methods!(
    normal: [
        md2, md4, md5, sha1, sha224, sha256, sha384, sha512,
        sha512_224, sha512_256, sha3_224, sha3_256, sha3_384,
        sha3_512, shake128, shake256, sm3
    ],
    variant: [blake2s, blake2b],
);

#[wasm_bindgen]
impl Hash {
    #[wasm_bindgen]
    pub fn write(&mut self, data: &[u8]) -> Result<usize, JsValue> {
        match self.0.write(data) {
            Ok(written) => Ok(written),
            Err(e) => Err(JsValue::from_str(&format!("Write failed: {:?}", e))),
        }
    }

    #[wasm_bindgen]
    pub fn flush(&mut self) -> Result<(), JsValue> {
        match self.0.flush() {
            Ok(_) => Ok(()),
            Err(e) => Err(JsValue::from_str(&format!("Flush failed: {:?}", e))),
        }
    }

    #[wasm_bindgen]
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, JsValue> {
        match self.0.read(buf) {
            Ok(read) => Ok(read),
            Err(e) => Err(JsValue::from_str(&format!("Read failed: {:?}", e))),
        }
    }

    #[wasm_bindgen]
    pub fn sum(&mut self) -> Vec<u8> {
        self.0.sum()
    }

    #[wasm_bindgen]
    pub fn reset(&mut self) {
        self.0.reset();
    }

    #[wasm_bindgen]
    pub fn size(&self) -> usize {
        self.0.size()
    }

    #[wasm_bindgen]
    pub fn block_size(&self) -> usize {
        self.0.block_size()
    }
}

use crown::envelope::EvpAeadCipher;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct AeadCipher(EvpAeadCipher);

macro_rules! impl_aead_cipher {
    (
        basic: [$($basic:ident),* $(,)?],
        rounds: [$($rc:ident),* $(,)?],
        special: [$($special:ident),* $(,)?] $(,)?
    ) => {
        $(
            paste::paste! {
                #[wasm_bindgen]
                impl AeadCipher {
                    #[wasm_bindgen]
                    pub fn [<new_ $basic:lower _gcm>](key: &[u8]) -> Result<AeadCipher, JsValue> {
                        match EvpAeadCipher::[<new_ $basic:lower _gcm>](key) {
                            Ok(cipher) => Ok(AeadCipher(cipher)),
                            Err(e) => Err(JsValue::from_str(&format!("Failed to create cipher: {:?}", e))),
                        }
                    }
                }

                #[wasm_bindgen]
                impl AeadCipher {
                    #[wasm_bindgen]
                    pub fn [<new_ $basic:lower _ocb3>](key: &[u8], tag_size: usize, nonce_size: usize) -> Result<AeadCipher, JsValue> {
                        let result = match (tag_size, nonce_size) {
                            (16, 12) => EvpAeadCipher::[<new_ $basic:lower _ocb3>]::<16, 12>(key),
                            (16, 15) => EvpAeadCipher::[<new_ $basic:lower _ocb3>]::<16, 15>(key),
                            _ => return Err(JsValue::from_str("Unsupported tag_size/nonce_size combination")),
                        };

                        match result {
                            Ok(cipher) => Ok(AeadCipher(cipher)),
                            Err(e) => Err(JsValue::from_str(&format!("Failed to create cipher: {:?}", e))),
                        }
                    }
                }
            }
        )*
        $(
            paste::paste! {
                #[wasm_bindgen]
                impl AeadCipher {
                    #[wasm_bindgen]
                    pub fn [<new_ $rc:lower _gcm>](key: &[u8], rounds: Option<usize>) -> Result<AeadCipher, JsValue> {
                        match EvpAeadCipher::[<new_ $rc:lower _gcm>](key, rounds) {
                            Ok(cipher) => Ok(AeadCipher(cipher)),
                            Err(e) => Err(JsValue::from_str(&format!("Failed to create cipher: {:?}", e))),
                        }
                    }
                }
            }
        )*
        $(
            impl_aead_cipher!(@special $special);
        )*
    };
    (@special chacha20_poly1305) => {
        #[wasm_bindgen]
        impl AeadCipher {
            #[wasm_bindgen]
            pub fn new_chacha20_poly1305(key: &[u8]) -> Result<AeadCipher, JsValue> {
                match EvpAeadCipher::new_chacha20_poly1305(key) {
                    Ok(cipher) => Ok(AeadCipher(cipher)),
                    Err(e) => Err(JsValue::from_str(&format!("Failed to create cipher: {:?}", e))),
                }
            }
        }
    };
    (@special xchacha20_poly1305) => {
        #[wasm_bindgen]
        impl AeadCipher {
            #[wasm_bindgen]
            pub fn new_xchacha20_poly1305(key: &[u8]) -> Result<AeadCipher, JsValue> {
                match EvpAeadCipher::new_xchacha20_poly1305(key) {
                    Ok(cipher) => Ok(AeadCipher(cipher)),
                    Err(e) => Err(JsValue::from_str(&format!("Failed to create cipher: {:?}", e))),
                }
            }
        }
    };
}

impl_aead_cipher!(
    basic: [Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Rc6, Sm4, Skipjack],
    rounds: [Rc2, Rc5, Camellia],
    special: [chacha20_poly1305, xchacha20_poly1305],
);

#[wasm_bindgen]
impl AeadCipher {
    #[wasm_bindgen]
    pub fn nonce_size(&self) -> usize {
        self.0.nonce_size()
    }

    #[wasm_bindgen]
    pub fn tag_size(&self) -> usize {
        self.0.tag_size()
    }

    #[wasm_bindgen]
    pub fn seal_in_place_separate_tag(
        &self,
        data: &mut [u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        match self.0.seal_in_place_separate_tag(data, nonce, aad) {
            Ok(tag) => Ok(tag),
            Err(e) => Err(JsValue::from_str(&format!("Encryption failed: {:?}", e))),
        }
    }

    #[wasm_bindgen]
    pub fn open_in_place_separate_tag(
        &self,
        data: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), JsValue> {
        match self.0.open_in_place_separate_tag(data, tag, nonce, aad) {
            Ok(_) => Ok(()),
            Err(e) => Err(JsValue::from_str(&format!("Decryption failed: {:?}", e))),
        }
    }
}

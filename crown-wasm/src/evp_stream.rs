use crown::envelope::EvpStreamCipher;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct StreamCipher(EvpStreamCipher);

macro_rules! impl_stream_cipher {
    (
        basic: [$($basic:ident),* $(,)?],
        rounds: [$($rc:ident),* $(,)?],
        special: [$($special:ident),* $(,)?] $(,)?
    ) => {
        $(
            paste::paste! {
                #[wasm_bindgen]
                impl StreamCipher {
                    #[wasm_bindgen]
                    pub fn [<new_ $basic:lower _cfb>](key: &[u8], iv: &[u8]) -> Result<StreamCipher, JsValue> {
                        match EvpStreamCipher::[<new_ $basic:lower _cfb>](key, iv) {
                            Ok(cipher) => Ok(StreamCipher(cipher)),
                            Err(e) => Err(JsValue::from_str(&format!("Failed to create cipher: {:?}", e))),
                        }
                    }

                    #[wasm_bindgen]
                    pub fn [<new_ $basic:lower _ctr>](key: &[u8], iv: &[u8]) -> Result<StreamCipher, JsValue> {
                        match EvpStreamCipher::[<new_ $basic:lower _ctr>](key, iv) {
                            Ok(cipher) => Ok(StreamCipher(cipher)),
                            Err(e) => Err(JsValue::from_str(&format!("Failed to create cipher: {:?}", e))),
                        }
                    }

                    #[wasm_bindgen]
                    pub fn [<new_ $basic:lower _ofb>](key: &[u8], iv: &[u8]) -> Result<StreamCipher, JsValue> {
                        match EvpStreamCipher::[<new_ $basic:lower _ofb>](key, iv) {
                            Ok(cipher) => Ok(StreamCipher(cipher)),
                            Err(e) => Err(JsValue::from_str(&format!("Failed to create cipher: {:?}", e))),
                        }
                    }
                }
            }
        )*
        $(
            paste::paste! {
                #[wasm_bindgen]
                impl StreamCipher {
                    #[wasm_bindgen]
                    pub fn [<new_ $rc:lower _cfb>](key: &[u8], iv: &[u8], rounds: Option<usize>) -> Result<StreamCipher, JsValue> {
                        match EvpStreamCipher::[<new_ $rc:lower _cfb>](key, iv, rounds) {
                            Ok(cipher) => Ok(StreamCipher(cipher)),
                            Err(e) => Err(JsValue::from_str(&format!("Failed to create cipher: {:?}", e))),
                        }
                    }

                    #[wasm_bindgen]
                    pub fn [<new_ $rc:lower _ctr>](key: &[u8], iv: &[u8], rounds: Option<usize>) -> Result<StreamCipher, JsValue> {
                        match EvpStreamCipher::[<new_ $rc:lower _ctr>](key, iv, rounds) {
                            Ok(cipher) => Ok(StreamCipher(cipher)),
                            Err(e) => Err(JsValue::from_str(&format!("Failed to create cipher: {:?}", e))),
                        }
                    }

                    #[wasm_bindgen]
                    pub fn [<new_ $rc:lower _ofb>](key: &[u8], iv: &[u8], rounds: Option<usize>) -> Result<StreamCipher, JsValue> {
                        match EvpStreamCipher::[<new_ $rc:lower _ofb>](key, iv, rounds) {
                            Ok(cipher) => Ok(StreamCipher(cipher)),
                            Err(e) => Err(JsValue::from_str(&format!("Failed to create cipher: {:?}", e))),
                        }
                    }
                }
            }
        )*
        $(
            impl_stream_cipher!(@special $special);
        )*
    };
    (@special rc4) => {
        #[wasm_bindgen]
        impl StreamCipher {
            #[wasm_bindgen]
            pub fn new_rc4(key: &[u8]) -> Result<StreamCipher, JsValue> {
                match EvpStreamCipher::new_rc4(key) {
                    Ok(cipher) => Ok(StreamCipher(cipher)),
                    Err(e) => Err(JsValue::from_str(&format!("Failed to create cipher: {:?}", e))),
                }
            }
        }
    };
    (@special salsa20) => {
        #[wasm_bindgen]
        impl StreamCipher {
            #[wasm_bindgen]
            pub fn new_salsa20(key: &[u8], iv: &[u8]) -> Result<StreamCipher, JsValue> {
                match EvpStreamCipher::new_salsa20(key, iv) {
                    Ok(cipher) => Ok(StreamCipher(cipher)),
                    Err(e) => Err(JsValue::from_str(&format!("Failed to create cipher: {:?}", e))),
                }
            }
        }
    };
    (@special chacha20) => {
        #[wasm_bindgen]
        impl StreamCipher {
            #[wasm_bindgen]
            pub fn new_chacha20(key: &[u8], iv: &[u8]) -> Result<StreamCipher, JsValue> {
                match EvpStreamCipher::new_chacha20(key, iv) {
                    Ok(cipher) => Ok(StreamCipher(cipher)),
                    Err(e) => Err(JsValue::from_str(&format!("Failed to create cipher: {:?}", e))),
                }
            }
        }
    };
}

impl_stream_cipher!(
    basic: [Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6, Sm4, Skipjack],
    rounds: [Rc2, Rc5, Camellia],
    special: [rc4, salsa20, chacha20],
);

#[wasm_bindgen]
impl StreamCipher {
    #[wasm_bindgen]
    pub fn encrypt(&mut self, data: &mut [u8]) -> Result<(), JsValue> {
        match self.0.encrypt(data) {
            Ok(_) => Ok(()),
            Err(e) => Err(JsValue::from_str(&format!("Encryption failed: {:?}", e))),
        }
    }

    #[wasm_bindgen]
    pub fn decrypt(&mut self, data: &mut [u8]) -> Result<(), JsValue> {
        match self.0.decrypt(data) {
            Ok(_) => Ok(()),
            Err(e) => Err(JsValue::from_str(&format!("Decryption failed: {:?}", e))),
        }
    }
}

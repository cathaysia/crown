use crown::envelope::EvpBlockCipher;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct BlockCipher(EvpBlockCipher);

macro_rules! impl_block_cipher {
    (
        basic: [$($basic:ident),* $(,)?],
        rounds: [$($rc:ident),* $(,)?] $(,)?
    ) => {
        $(
            paste::paste! {
                #[wasm_bindgen]
                impl BlockCipher {
                    #[wasm_bindgen]
                    pub fn [<new_ $basic:lower _cbc>](key: &[u8], iv: &[u8]) -> Result<BlockCipher, JsValue> {
                        match EvpBlockCipher::[<new_ $basic:lower _cbc>](key, iv) {
                            Ok(cipher) => Ok(BlockCipher(cipher)),
                            Err(e) => Err(JsValue::from_str(&format!("Failed to create cipher: {:?}", e))),
                        }
                    }
                }
            }
        )*
        $(
            paste::paste! {
                #[wasm_bindgen]
                impl BlockCipher {
                    #[wasm_bindgen]
                    pub fn [<new_ $rc:lower _cbc>](key: &[u8], iv: &[u8], rounds: Option<usize>) -> Result<BlockCipher, JsValue> {
                        match EvpBlockCipher::[<new_ $rc:lower _cbc>](key, iv, rounds) {
                            Ok(cipher) => Ok(BlockCipher(cipher)),
                            Err(e) => Err(JsValue::from_str(&format!("Failed to create cipher: {:?}", e))),
                        }
                    }
                }
            }
        )*
    };
}

impl_block_cipher!(
    basic: [Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6, Sm4, Skipjack],
    rounds: [Rc2, Rc5, Camellia],
);

#[wasm_bindgen]
impl BlockCipher {
    #[wasm_bindgen]
    pub fn encrypt(&mut self, data: &mut [u8], pos: usize) -> Result<usize, JsValue> {
        match self.0.encrypt(data, pos) {
            Ok(len) => Ok(len),
            Err(e) => Err(JsValue::from_str(&format!("Encryption failed: {:?}", e))),
        }
    }

    #[wasm_bindgen]
    pub fn decrypt(&mut self, data: &mut [u8]) -> Result<usize, JsValue> {
        match self.0.decrypt(data) {
            Ok(len) => Ok(len),
            Err(e) => Err(JsValue::from_str(&format!("Decryption failed: {:?}", e))),
        }
    }
}

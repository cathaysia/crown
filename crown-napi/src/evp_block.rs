use crate::crypto_err;
use crown::envelope::EvpBlockCipher;
use napi::bindgen_prelude::*;

#[napi]
pub struct BlockCipher(EvpBlockCipher);

macro_rules! impl_block_cipher {
    (
        basic: [$($basic:ident),* $(,)?],
        rounds: [$($rc:ident),* $(,)?] $(,)?
    ) => {
        $(
            paste::paste! {
                #[napi]
                impl BlockCipher {
                    #[napi]
                    pub fn [<new_ $basic:lower _cbc>](key: &[u8], iv: &[u8]) -> Result<BlockCipher> {
                        match EvpBlockCipher::[<new_ $basic:lower _cbc>](key, iv) {
                            Ok(cipher) => Ok(BlockCipher(cipher)),
                            Err(e) => Err(crypto_err("Failed to create cipher", e)),
                        }
                    }
                }
            }
        )*
        $(
            paste::paste! {
                #[napi]
                impl BlockCipher {
                    #[napi]
                    pub fn [<new_ $rc:lower _cbc>](key: &[u8], iv: &[u8], rounds: Option<u32>) -> Result<BlockCipher> {
                        match EvpBlockCipher::[<new_ $rc:lower _cbc>](key, iv, rounds.map(|r| r as usize)) {
                            Ok(cipher) => Ok(BlockCipher(cipher)),
                            Err(e) => Err(crypto_err("Failed to create cipher", e)),
                        }
                    }
                }
            }
        )*
    };
}

impl_block_cipher!(
    basic: [
        Aes, Aria, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6, Sm4, Skipjack,
        Kasumi, Kseed, Anubis, Noekeon, Khazad, Serpent, Desx
    ],
    rounds: [Rc2, Rc5, Camellia, Multi2],
);

#[napi]
impl BlockCipher {
    #[napi]
    pub fn encrypt(&mut self, mut data: Buffer, pos: u32) -> Result<u32> {
        match self.0.encrypt(&mut data, pos as usize) {
            Ok(len) => Ok(len as u32),
            Err(e) => Err(crypto_err("Encryption failed", e)),
        }
    }

    #[napi]
    pub fn decrypt(&mut self, mut data: Buffer) -> Result<u32> {
        match self.0.decrypt(&mut data) {
            Ok(len) => Ok(len as u32),
            Err(e) => Err(crypto_err("Decryption failed", e)),
        }
    }
}

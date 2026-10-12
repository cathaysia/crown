use crate::crypto_err;
use crown::envelope::EvpStreamCipher;
use napi::bindgen_prelude::*;

#[napi]
pub struct StreamCipher(EvpStreamCipher);

macro_rules! impl_stream_cipher {
    (
        basic: [$($basic:ident),* $(,)?],
        rounds: [$($rc:ident),* $(,)?],
        special: [$($special:ident),* $(,)?] $(,)?
    ) => {
        $(
            paste::paste! {
                #[napi]
                impl StreamCipher {
                    #[napi]
                    pub fn [<new_ $basic:lower _cfb>](key: &[u8], iv: &[u8]) -> Result<StreamCipher> {
                        match EvpStreamCipher::[<new_ $basic:lower _cfb>](key, iv) {
                            Ok(cipher) => Ok(StreamCipher(cipher)),
                            Err(e) => Err(crypto_err("Failed to create cipher", e)),
                        }
                    }

                    #[napi]
                    pub fn [<new_ $basic:lower _ctr>](key: &[u8], iv: &[u8]) -> Result<StreamCipher> {
                        match EvpStreamCipher::[<new_ $basic:lower _ctr>](key, iv) {
                            Ok(cipher) => Ok(StreamCipher(cipher)),
                            Err(e) => Err(crypto_err("Failed to create cipher", e)),
                        }
                    }

                    #[napi]
                    pub fn [<new_ $basic:lower _ofb>](key: &[u8], iv: &[u8]) -> Result<StreamCipher> {
                        match EvpStreamCipher::[<new_ $basic:lower _ofb>](key, iv) {
                            Ok(cipher) => Ok(StreamCipher(cipher)),
                            Err(e) => Err(crypto_err("Failed to create cipher", e)),
                        }
                    }
                }
            }
        )*
        $(
            paste::paste! {
                #[napi]
                impl StreamCipher {
                    #[napi]
                    pub fn [<new_ $rc:lower _cfb>](key: &[u8], iv: &[u8], rounds: Option<u32>) -> Result<StreamCipher> {
                        match EvpStreamCipher::[<new_ $rc:lower _cfb>](key, iv, rounds.map(|r| r as usize)) {
                            Ok(cipher) => Ok(StreamCipher(cipher)),
                            Err(e) => Err(crypto_err("Failed to create cipher", e)),
                        }
                    }

                    #[napi]
                    pub fn [<new_ $rc:lower _ctr>](key: &[u8], iv: &[u8], rounds: Option<u32>) -> Result<StreamCipher> {
                        match EvpStreamCipher::[<new_ $rc:lower _ctr>](key, iv, rounds.map(|r| r as usize)) {
                            Ok(cipher) => Ok(StreamCipher(cipher)),
                            Err(e) => Err(crypto_err("Failed to create cipher", e)),
                        }
                    }

                    #[napi]
                    pub fn [<new_ $rc:lower _ofb>](key: &[u8], iv: &[u8], rounds: Option<u32>) -> Result<StreamCipher> {
                        match EvpStreamCipher::[<new_ $rc:lower _ofb>](key, iv, rounds.map(|r| r as usize)) {
                            Ok(cipher) => Ok(StreamCipher(cipher)),
                            Err(e) => Err(crypto_err("Failed to create cipher", e)),
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
        #[napi]
        impl StreamCipher {
            #[napi]
            pub fn new_rc4(key: &[u8]) -> Result<StreamCipher> {
                match EvpStreamCipher::new_rc4(key) {
                    Ok(cipher) => Ok(StreamCipher(cipher)),
                    Err(e) => Err(crypto_err("Failed to create cipher", e)),
                }
            }
        }
    };
    (@special salsa20) => {
        #[napi]
        impl StreamCipher {
            #[napi]
            pub fn new_salsa20(key: &[u8], iv: &[u8]) -> Result<StreamCipher> {
                match EvpStreamCipher::new_salsa20(key, iv) {
                    Ok(cipher) => Ok(StreamCipher(cipher)),
                    Err(e) => Err(crypto_err("Failed to create cipher", e)),
                }
            }
        }
    };
    (@special chacha20) => {
        #[napi]
        impl StreamCipher {
            #[napi]
            pub fn new_chacha20(key: &[u8], iv: &[u8]) -> Result<StreamCipher> {
                match EvpStreamCipher::new_chacha20(key, iv) {
                    Ok(cipher) => Ok(StreamCipher(cipher)),
                    Err(e) => Err(crypto_err("Failed to create cipher", e)),
                }
            }
        }
    };
    (@special rabbit) => {
        #[napi]
        impl StreamCipher {
            #[napi]
            pub fn new_rabbit(key: &[u8], iv: &[u8]) -> Result<StreamCipher> {
                match EvpStreamCipher::new_rabbit(key, iv) {
                    Ok(cipher) => Ok(StreamCipher(cipher)),
                    Err(e) => Err(crypto_err("Failed to create cipher", e)),
                }
            }
        }
    };
    (@special sosemanuk) => {
        #[napi]
        impl StreamCipher {
            #[napi]
            pub fn new_sosemanuk(key: &[u8], iv: &[u8]) -> Result<StreamCipher> {
                match EvpStreamCipher::new_sosemanuk(key, iv) {
                    Ok(cipher) => Ok(StreamCipher(cipher)),
                    Err(e) => Err(crypto_err("Failed to create cipher", e)),
                }
            }
        }
    };
    (@special sober128) => {
        #[napi]
        impl StreamCipher {
            #[napi]
            pub fn new_sober128(key: &[u8], iv: &[u8]) -> Result<StreamCipher> {
                match EvpStreamCipher::new_sober128(key, iv) {
                    Ok(cipher) => Ok(StreamCipher(cipher)),
                    Err(e) => Err(crypto_err("Failed to create cipher", e)),
                }
            }
        }
    };
}

impl_stream_cipher!(
    basic: [
        Aes, Aria, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6, Sm4, Skipjack,
        Kasumi, Kseed, Anubis, Noekeon, Khazad, Serpent
    ],
    rounds: [Rc2, Rc5, Camellia, Multi2],
    special: [rc4, salsa20, chacha20, rabbit, sosemanuk, sober128],
);

#[napi]
impl StreamCipher {
    #[napi]
    pub fn encrypt(&mut self, mut data: Buffer) -> Result<()> {
        match self.0.encrypt(&mut data) {
            Ok(_) => Ok(()),
            Err(e) => Err(crypto_err("Encryption failed", e)),
        }
    }

    #[napi]
    pub fn decrypt(&mut self, mut data: Buffer) -> Result<()> {
        match self.0.decrypt(&mut data) {
            Ok(_) => Ok(()),
            Err(e) => Err(crypto_err("Decryption failed", e)),
        }
    }
}

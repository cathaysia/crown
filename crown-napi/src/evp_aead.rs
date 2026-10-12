use crate::crypto_err;
use crown::envelope::EvpAeadCipher;
use napi::bindgen_prelude::*;

#[napi]
pub struct AeadCipher(EvpAeadCipher);

macro_rules! dispatch_eax {
    ($method:ident, $key:expr, $tag_size:expr, $nonce_size:expr $(, $rounds:expr)?) => {
        match $tag_size {
            1 => EvpAeadCipher::$method::<1>($key, $nonce_size as usize $(, $rounds)?),
            2 => EvpAeadCipher::$method::<2>($key, $nonce_size as usize $(, $rounds)?),
            3 => EvpAeadCipher::$method::<3>($key, $nonce_size as usize $(, $rounds)?),
            4 => EvpAeadCipher::$method::<4>($key, $nonce_size as usize $(, $rounds)?),
            5 => EvpAeadCipher::$method::<5>($key, $nonce_size as usize $(, $rounds)?),
            6 => EvpAeadCipher::$method::<6>($key, $nonce_size as usize $(, $rounds)?),
            7 => EvpAeadCipher::$method::<7>($key, $nonce_size as usize $(, $rounds)?),
            8 => EvpAeadCipher::$method::<8>($key, $nonce_size as usize $(, $rounds)?),
            9 => EvpAeadCipher::$method::<9>($key, $nonce_size as usize $(, $rounds)?),
            10 => EvpAeadCipher::$method::<10>($key, $nonce_size as usize $(, $rounds)?),
            11 => EvpAeadCipher::$method::<11>($key, $nonce_size as usize $(, $rounds)?),
            12 => EvpAeadCipher::$method::<12>($key, $nonce_size as usize $(, $rounds)?),
            13 => EvpAeadCipher::$method::<13>($key, $nonce_size as usize $(, $rounds)?),
            14 => EvpAeadCipher::$method::<14>($key, $nonce_size as usize $(, $rounds)?),
            15 => EvpAeadCipher::$method::<15>($key, $nonce_size as usize $(, $rounds)?),
            16 => EvpAeadCipher::$method::<16>($key, $nonce_size as usize $(, $rounds)?),
            _ => return Err(crypto_err("Unsupported tag size", "tag size must be 1..=16")),
        }
    };
}

macro_rules! dispatch_ccm {
    ($method:ident, $key:expr, $tag_size:expr, $nonce_size:expr $(, $rounds:expr)?) => {
        match ($tag_size, $nonce_size) {
            (4, 7) => EvpAeadCipher::$method::<4, 7>($key $(, $rounds)?),
            (4, 8) => EvpAeadCipher::$method::<4, 8>($key $(, $rounds)?),
            (4, 9) => EvpAeadCipher::$method::<4, 9>($key $(, $rounds)?),
            (4, 10) => EvpAeadCipher::$method::<4, 10>($key $(, $rounds)?),
            (4, 11) => EvpAeadCipher::$method::<4, 11>($key $(, $rounds)?),
            (4, 12) => EvpAeadCipher::$method::<4, 12>($key $(, $rounds)?),
            (4, 13) => EvpAeadCipher::$method::<4, 13>($key $(, $rounds)?),
            (6, 7) => EvpAeadCipher::$method::<6, 7>($key $(, $rounds)?),
            (6, 8) => EvpAeadCipher::$method::<6, 8>($key $(, $rounds)?),
            (6, 9) => EvpAeadCipher::$method::<6, 9>($key $(, $rounds)?),
            (6, 10) => EvpAeadCipher::$method::<6, 10>($key $(, $rounds)?),
            (6, 11) => EvpAeadCipher::$method::<6, 11>($key $(, $rounds)?),
            (6, 12) => EvpAeadCipher::$method::<6, 12>($key $(, $rounds)?),
            (6, 13) => EvpAeadCipher::$method::<6, 13>($key $(, $rounds)?),
            (8, 7) => EvpAeadCipher::$method::<8, 7>($key $(, $rounds)?),
            (8, 8) => EvpAeadCipher::$method::<8, 8>($key $(, $rounds)?),
            (8, 9) => EvpAeadCipher::$method::<8, 9>($key $(, $rounds)?),
            (8, 10) => EvpAeadCipher::$method::<8, 10>($key $(, $rounds)?),
            (8, 11) => EvpAeadCipher::$method::<8, 11>($key $(, $rounds)?),
            (8, 12) => EvpAeadCipher::$method::<8, 12>($key $(, $rounds)?),
            (8, 13) => EvpAeadCipher::$method::<8, 13>($key $(, $rounds)?),
            (10, 7) => EvpAeadCipher::$method::<10, 7>($key $(, $rounds)?),
            (10, 8) => EvpAeadCipher::$method::<10, 8>($key $(, $rounds)?),
            (10, 9) => EvpAeadCipher::$method::<10, 9>($key $(, $rounds)?),
            (10, 10) => EvpAeadCipher::$method::<10, 10>($key $(, $rounds)?),
            (10, 11) => EvpAeadCipher::$method::<10, 11>($key $(, $rounds)?),
            (10, 12) => EvpAeadCipher::$method::<10, 12>($key $(, $rounds)?),
            (10, 13) => EvpAeadCipher::$method::<10, 13>($key $(, $rounds)?),
            (12, 7) => EvpAeadCipher::$method::<12, 7>($key $(, $rounds)?),
            (12, 8) => EvpAeadCipher::$method::<12, 8>($key $(, $rounds)?),
            (12, 9) => EvpAeadCipher::$method::<12, 9>($key $(, $rounds)?),
            (12, 10) => EvpAeadCipher::$method::<12, 10>($key $(, $rounds)?),
            (12, 11) => EvpAeadCipher::$method::<12, 11>($key $(, $rounds)?),
            (12, 12) => EvpAeadCipher::$method::<12, 12>($key $(, $rounds)?),
            (12, 13) => EvpAeadCipher::$method::<12, 13>($key $(, $rounds)?),
            (14, 7) => EvpAeadCipher::$method::<14, 7>($key $(, $rounds)?),
            (14, 8) => EvpAeadCipher::$method::<14, 8>($key $(, $rounds)?),
            (14, 9) => EvpAeadCipher::$method::<14, 9>($key $(, $rounds)?),
            (14, 10) => EvpAeadCipher::$method::<14, 10>($key $(, $rounds)?),
            (14, 11) => EvpAeadCipher::$method::<14, 11>($key $(, $rounds)?),
            (14, 12) => EvpAeadCipher::$method::<14, 12>($key $(, $rounds)?),
            (14, 13) => EvpAeadCipher::$method::<14, 13>($key $(, $rounds)?),
            (16, 7) => EvpAeadCipher::$method::<16, 7>($key $(, $rounds)?),
            (16, 8) => EvpAeadCipher::$method::<16, 8>($key $(, $rounds)?),
            (16, 9) => EvpAeadCipher::$method::<16, 9>($key $(, $rounds)?),
            (16, 10) => EvpAeadCipher::$method::<16, 10>($key $(, $rounds)?),
            (16, 11) => EvpAeadCipher::$method::<16, 11>($key $(, $rounds)?),
            (16, 12) => EvpAeadCipher::$method::<16, 12>($key $(, $rounds)?),
            (16, 13) => EvpAeadCipher::$method::<16, 13>($key $(, $rounds)?),
            _ => return Err(crypto_err("Unsupported tag_size/nonce_size combination", "no matching CCM parameters")),
        }
    };
}

macro_rules! impl_aead_cipher {
    (
        basic: [$($basic:ident),* $(,)?],
        rounds: [$($rc:ident),* $(,)?],
        special: [$($special:ident),* $(,)?] $(,)?
    ) => {
        $(
            paste::paste! {
                #[napi]
                impl AeadCipher {
                    #[napi]
                    pub fn [<new_ $basic:lower _gcm>](key: &[u8]) -> Result<AeadCipher> {
                        match EvpAeadCipher::[<new_ $basic:lower _gcm>](key) {
                            Ok(cipher) => Ok(AeadCipher(cipher)),
                            Err(e) => Err(crypto_err("Failed to create cipher", e)),
                        }
                    }
                }

                #[napi]
                impl AeadCipher {
                    #[napi]
                    pub fn [<new_ $basic:lower _ocb3>](key: &[u8], tag_size: u32, nonce_size: u32) -> Result<AeadCipher> {
                        let result = match (tag_size, nonce_size) {
                            (16, 12) => EvpAeadCipher::[<new_ $basic:lower _ocb3>]::<16, 12>(key),
                            (16, 15) => EvpAeadCipher::[<new_ $basic:lower _ocb3>]::<16, 15>(key),
                            _ => return Err(crypto_err("Unsupported tag_size/nonce_size combination", "OCB3 needs (16, 12) or (16, 15)")),
                        };

                        match result {
                            Ok(cipher) => Ok(AeadCipher(cipher)),
                            Err(e) => Err(crypto_err("Failed to create cipher", e)),
                        }
                    }
                }

                #[napi]
                impl AeadCipher {
                    #[napi]
                    pub fn [<new_ $basic:lower _ccm>](key: &[u8], tag_size: u32, nonce_size: u32) -> Result<AeadCipher> {
                        let result = dispatch_ccm!([<new_ $basic:lower _ccm>], key, tag_size, nonce_size);

                        match result {
                            Ok(cipher) => Ok(AeadCipher(cipher)),
                            Err(e) => Err(crypto_err("Failed to create cipher", e)),
                        }
                    }
                }

                #[napi]
                impl AeadCipher {
                    #[napi]
                    pub fn [<new_ $basic:lower _eax>](key: &[u8], tag_size: u32, nonce_size: u32) -> Result<AeadCipher> {
                        let result = dispatch_eax!([<new_ $basic:lower _eax>], key, tag_size, nonce_size);

                        match result {
                            Ok(cipher) => Ok(AeadCipher(cipher)),
                            Err(e) => Err(crypto_err("Failed to create cipher", e)),
                        }
                    }
                }
            }
        )*
        $(
            paste::paste! {
                #[napi]
                impl AeadCipher {
                    #[napi]
                    pub fn [<new_ $rc:lower _gcm>](key: &[u8], rounds: Option<u32>) -> Result<AeadCipher> {
                        match EvpAeadCipher::[<new_ $rc:lower _gcm>](key, rounds.map(|r| r as usize)) {
                            Ok(cipher) => Ok(AeadCipher(cipher)),
                            Err(e) => Err(crypto_err("Failed to create cipher", e)),
                        }
                    }
                }

                #[napi]
                impl AeadCipher {
                    #[napi]
                    pub fn [<new_ $rc:lower _ccm>](key: &[u8], tag_size: u32, nonce_size: u32, rounds: Option<u32>) -> Result<AeadCipher> {
                        let result = dispatch_ccm!([<new_ $rc:lower _ccm>], key, tag_size, nonce_size, rounds.map(|r| r as usize));

                        match result {
                            Ok(cipher) => Ok(AeadCipher(cipher)),
                            Err(e) => Err(crypto_err("Failed to create cipher", e)),
                        }
                    }
                }

                #[napi]
                impl AeadCipher {
                    #[napi]
                    pub fn [<new_ $rc:lower _eax>](key: &[u8], tag_size: u32, nonce_size: u32, rounds: Option<u32>) -> Result<AeadCipher> {
                        let result = dispatch_eax!([<new_ $rc:lower _eax>], key, tag_size, nonce_size, rounds.map(|r| r as usize));

                        match result {
                            Ok(cipher) => Ok(AeadCipher(cipher)),
                            Err(e) => Err(crypto_err("Failed to create cipher", e)),
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
        #[napi]
        impl AeadCipher {
            #[napi]
            pub fn new_chacha20_poly1305(key: &[u8]) -> Result<AeadCipher> {
                match EvpAeadCipher::new_chacha20_poly1305(key) {
                    Ok(cipher) => Ok(AeadCipher(cipher)),
                    Err(e) => Err(crypto_err("Failed to create cipher", e)),
                }
            }
        }
    };
    (@special xchacha20_poly1305) => {
        #[napi]
        impl AeadCipher {
            #[napi]
            pub fn new_xchacha20_poly1305(key: &[u8]) -> Result<AeadCipher> {
                match EvpAeadCipher::new_xchacha20_poly1305(key) {
                    Ok(cipher) => Ok(AeadCipher(cipher)),
                    Err(e) => Err(crypto_err("Failed to create cipher", e)),
                }
            }
        }
    };
    (@special aes_gcm_siv) => {
        #[napi]
        impl AeadCipher {
            #[napi]
            pub fn new_aes_gcm_siv(key: &[u8]) -> Result<AeadCipher> {
                match EvpAeadCipher::new_aes_gcm_siv(key) {
                    Ok(cipher) => Ok(AeadCipher(cipher)),
                    Err(e) => Err(crypto_err("Failed to create cipher", e)),
                }
            }
        }
    };
    (@special ascon_aead128) => {
        #[napi]
        impl AeadCipher {
            #[napi]
            pub fn new_ascon_aead128(key: &[u8]) -> Result<AeadCipher> {
                match EvpAeadCipher::new_ascon_aead128(key) {
                    Ok(cipher) => Ok(AeadCipher(cipher)),
                    Err(e) => Err(crypto_err("Failed to create cipher", e)),
                }
            }
        }
    };
    (@special aes_siv) => {
        #[napi]
        impl AeadCipher {
            #[napi]
            pub fn new_aes_siv(key: &[u8]) -> Result<AeadCipher> {
                match EvpAeadCipher::new_aes_siv(key) {
                    Ok(cipher) => Ok(AeadCipher(cipher)),
                    Err(e) => Err(crypto_err("Failed to create cipher", e)),
                }
            }
        }
    };
}

impl_aead_cipher!(
    basic: [
        Aes, Aria, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Rc6, Sm4, Skipjack, Kasumi,
        Kseed, Anubis, Noekeon, Khazad, Serpent, Idea
    ],
    rounds: [Rc2, Rc5, Camellia, Multi2],
    special: [chacha20_poly1305, xchacha20_poly1305, aes_gcm_siv, ascon_aead128, aes_siv],
);

#[napi]
impl AeadCipher {
    #[napi]
    pub fn nonce_size(&self) -> u32 {
        self.0.nonce_size() as u32
    }

    #[napi]
    pub fn tag_size(&self) -> u32 {
        self.0.tag_size() as u32
    }

    #[napi]
    pub fn seal_in_place_separate_tag(
        &self,
        mut data: Buffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Buffer> {
        match self.0.seal_in_place_separate_tag(&mut data, nonce, aad) {
            Ok(tag) => Ok(Buffer::from(tag)),
            Err(e) => Err(crypto_err("Encryption failed", e)),
        }
    }

    #[napi]
    pub fn open_in_place_separate_tag(
        &self,
        mut data: Buffer,
        tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<()> {
        match self
            .0
            .open_in_place_separate_tag(&mut data, tag, nonce, aad)
        {
            Ok(_) => Ok(()),
            Err(e) => Err(crypto_err("Decryption failed", e)),
        }
    }
}

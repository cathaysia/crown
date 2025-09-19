use crate::aes::Aes;
use crate::blowfish::Blowfish;
use crate::cast5::Cast5;
use crate::chacha20::Chacha20;
use crate::cipher::cfb::CfbAble;
use crate::cipher::ctr::CtrAble;
use crate::cipher::ofb::OfbAble;
use crate::des::Des;
use crate::des::TripleDes;
use crate::rc2::Rc2;
use crate::rc4::Rc4;
use crate::rc5::Rc5;
use crate::rc6::Rc6;
use crate::sala20::Sala20;
use crate::tea::Tea;
use crate::twofish::Twofish;
use crate::xtea::Xtea;
use crate::{cipher::StreamCipher, error::CryptoResult};

trait EvpStreamInner {
    fn encrypt(&mut self, inout: &mut [u8]) -> CryptoResult<()>;
    fn decrypt(&mut self, inout: &mut [u8]) -> CryptoResult<()>;
}

pub struct EvpStreamCipher(Box<dyn EvpStreamInner>);

macro_rules! impl_stream_cipher {
    (
        basic: [$($basic:ident),* $(,)?],
        rounds: [$(($rc:ident, $default_rounds:expr)),* $(,)?],
        special: [$($special:ident),* $(,)?] $(,)?
    ) => {
        $(
            paste::paste! {
                pub fn [<new_ $basic:lower _cfb>](key: &[u8], iv: &[u8]) -> CryptoResult<Self> {
                    Self::new_cfb_mode($basic::new(key)?, $basic::new(key)?, iv)
                }

                pub fn [<new_ $basic:lower _ctr>](key: &[u8], iv: &[u8]) -> CryptoResult<Self> {
                    Self::new_impl($basic::new(key)?.to_ctr(iv)?)
                }

                pub fn [<new_ $basic:lower _ofb>](key: &[u8], iv: &[u8]) -> CryptoResult<Self> {
                    Self::new_impl($basic::new(key)?.to_ofb(iv)?)
                }
            }
        )*
        $(
            paste::paste! {
                pub fn [<new_ $rc:lower _cfb>](key: &[u8], iv: &[u8], rounds: Option<usize>) -> CryptoResult<Self> {
                    Self::new_cfb_mode($rc::new(key, rounds.unwrap_or(20))?, $rc::new(key, rounds.unwrap_or(20))?, iv)
                }

                pub fn [<new_ $rc:lower _ctr>](key: &[u8], iv: &[u8], rounds: Option<usize>) -> CryptoResult<Self> {
                    Self::new_impl($rc::new(key, rounds.unwrap_or(20))?.to_ctr(iv)?)
                }

                pub fn [<new_ $rc:lower _ofb>](key: &[u8], iv: &[u8], rounds: Option<usize>) -> CryptoResult<Self> {
                    Self::new_impl($rc::new(key, rounds.unwrap_or(20))?.to_ofb(iv)?)
                }
            }
        )*
        $(
            impl_stream_cipher!(@special $special);
        )*
    };
    (@special rc4) => {
        pub fn new_rc4(key: &[u8]) -> CryptoResult<Self> {
            Self::new_impl(Rc4::new(key)?)
        }
    };
    (@special salsa20) => {
        pub fn new_salsa20(key: &[u8], iv: &[u8]) -> CryptoResult<Self> {
            Self::new_impl(Sala20::new(key, iv)?)
        }
    };
    (@special chacha20) => {
        pub fn new_chacha20(key: &[u8], iv: &[u8]) -> CryptoResult<Self> {
            Self::new_impl(Chacha20::new_unauthenticated_cipher(key, iv)?)
        }
    };
}

impl EvpStreamCipher {
    impl_stream_cipher!(
        basic: [Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea],
        rounds: [(Rc2, 20), (Rc5, 20), (Rc6, 20)],
        special: [rc4, salsa20, chacha20],
    );

    fn new_cfb_mode<T: CfbAble>(cipher: T, decyrpter: T, iv: &[u8]) -> CryptoResult<Self> {
        let encryptoer = cipher.to_cfb_encrypter(iv)?;
        let decryptoer = decyrpter.to_cfb_decrypter(iv)?;

        struct Wrapper<A, B> {
            encryptoer: A,
            decryptoer: B,
        }
        impl<A, B> EvpStreamInner for Wrapper<A, B>
        where
            A: StreamCipher + 'static,
            B: StreamCipher + 'static,
        {
            fn encrypt(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
                self.encryptoer.xor_key_stream(inout)
            }
            fn decrypt(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
                self.decryptoer.xor_key_stream(inout)
            }
        }

        Ok(Self(Box::new(Wrapper {
            encryptoer,
            decryptoer,
        })))
    }

    fn new_impl(stream_cipher: impl StreamCipher + 'static) -> CryptoResult<Self> {
        struct Wrapper<T>(T);

        impl<T> EvpStreamInner for Wrapper<T>
        where
            T: StreamCipher + 'static,
        {
            fn encrypt(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
                self.0.xor_key_stream(inout)
            }
            fn decrypt(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
                self.0.xor_key_stream(inout)
            }
        }
        Ok(Self(Box::new(Wrapper(stream_cipher))))
    }

    pub fn encrypt(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
        self.0.encrypt(inout)
    }

    pub fn decrypt(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
        self.0.decrypt(inout)
    }
}

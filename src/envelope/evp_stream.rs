use crate::block::aes::Aes;
use crate::block::blowfish::Blowfish;
use crate::block::camellia::Camellia;
use crate::block::cast5::Cast5;
use crate::block::des::Des;
use crate::block::des::TripleDes;
use crate::block::idea::Idea;
use crate::block::rc2::Rc2;
use crate::block::rc5::Rc5;
use crate::block::rc6::Rc6;
use crate::block::sm4::Sm4;
use crate::block::tea::Tea;
use crate::block::twofish::Twofish;
use crate::block::xtea::Xtea;
use crate::modes::cfb::Cfb;
use crate::modes::ctr::Ctr;
use crate::modes::ofb::Ofb;
use crate::stream::chacha20::Chacha20;
use crate::stream::rc4::Rc4;
use crate::stream::sala20::Sala20;
use crate::{error::CryptoResult, stream::StreamCipher};
use alloc::boxed::Box;

trait EvpStreamInner {
    fn encrypt(&mut self, inout: &mut [u8]) -> CryptoResult<()>;
    fn decrypt(&mut self, inout: &mut [u8]) -> CryptoResult<()>;
}

pub struct EvpStreamCipher(Box<dyn EvpStreamInner>);

macro_rules! impl_stream_cipher {
    (
        basic: [$($basic:ident),* $(,)?],
        rounds: [$($rc:ident),* $(,)?],
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
                    Self::new_cfb_mode($rc::new(key, rounds)?, $rc::new(key, rounds)?, iv)
                }

                pub fn [<new_ $rc:lower _ctr>](key: &[u8], iv: &[u8], rounds: Option<usize>) -> CryptoResult<Self> {
                    Self::new_impl($rc::new(key, rounds)?.to_ctr(iv)?)
                }

                pub fn [<new_ $rc:lower _ofb>](key: &[u8], iv: &[u8], rounds: Option<usize>) -> CryptoResult<Self> {
                    Self::new_impl($rc::new(key, rounds)?.to_ofb(iv)?)
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
        basic: [Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6, Sm4],
        rounds: [Rc2, Rc5, Camellia],
        special: [rc4, salsa20, chacha20],
    );

    fn new_cfb_mode<T: Cfb>(cipher: T, decyrpter: T, iv: &[u8]) -> CryptoResult<Self> {
        let encryptoer = cipher.to_cfb_encryptor(iv)?;
        let decryptoer = decyrpter.to_cfb_decryptor(iv)?;

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

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

macro_rules! impl_cfb_mode_a {
    ($($name:ident,)*) => {
        paste::paste!{
            $(
                pub fn [<new_ $name:lower _cfb>](key: &[u8], iv: &[u8]) ->CryptoResult<Self> {
                    Self::new_cfb_mode($name::new(&key)?, $name::new(&key)?, &iv)
                }

                pub fn [<new_ $name:lower _ctr>](key: &[u8], iv: &[u8]) ->CryptoResult<Self> {
                    Self::new_impl($name::new(&key)?.to_ctr(&iv)?)
                }

                pub fn [<new_ $name:lower _ofb>](key: &[u8], iv: &[u8]) ->CryptoResult<Self> {
                   Self::new_impl($name::new(&key)?.to_ofb(&iv)?)
                }
            )*
        }
    };
    (#rc $($name:ident,)*) => {
        paste::paste!{
            $(
                pub fn [<new_ $name:lower _cfb>](key: &[u8], iv: &[u8], rounds: usize) ->CryptoResult<Self> {
                    Self::new_cfb_mode($name::new(&key, rounds)?, $name::new(&key, rounds)?, &iv)
                }

                pub fn [<new_ $name:lower _ctr>](key: &[u8], iv: &[u8], rounds: usize) ->CryptoResult<Self> {
                    Self::new_impl($name::new(&key, rounds)?.to_ctr(&iv)?)
                }

                pub fn [<new_ $name:lower _ofb>](key: &[u8], iv: &[u8], rounds: usize) ->CryptoResult<Self> {
                    Self::new_impl($name::new(&key, rounds)?.to_ofb(&iv)?)
                }
            )*
        }
    }
}

impl EvpStreamCipher {
    impl_cfb_mode_a!(Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea,);
    impl_cfb_mode_a!(#rc Rc2, Rc5, Rc6,);

    pub fn new_rc4(key: &[u8]) -> CryptoResult<Self> {
        Self::new_impl(Rc4::new(key)?)
    }

    pub fn new_salsa20(key: &[u8], iv: &[u8]) -> CryptoResult<Self> {
        Self::new_impl(Sala20::new(key, iv)?)
    }

    pub fn new_chacha20(key: &[u8], iv: &[u8]) -> CryptoResult<Self> {
        Self::new_impl(Chacha20::new_unauthenticated_cipher(key, iv)?)
    }

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

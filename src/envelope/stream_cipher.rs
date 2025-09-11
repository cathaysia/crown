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

trait SelfInner {
    fn encrypt(&mut self, inout: &mut [u8]) -> CryptoResult<()>;
    fn decrypt(&mut self, inout: &mut [u8]) -> CryptoResult<()>;
}

macro_rules! stream_cipher_algorithm {
        ($($name:ident,)*) => {
            paste::paste! {
                pub enum StreamCipherAlgorithm {
                    Rc4,
                    Salsa20,
                    Chacha20,
                    $(
                        [<$name Cfb>],
                        [<$name Ctr>],
                        [<$name Ofb>],
                    )*
                }

            }
        };
    }

stream_cipher_algorithm!(Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Rc2, Rc5, Rc6,);

pub struct EvpStreamCipher(Box<dyn SelfInner>);

impl EvpStreamCipher {
    fn new_cfb_mode<T: CfbAble>(cipher: T, decyrpter: T, iv: &[u8]) -> CryptoResult<Self> {
        let encryptoer = cipher.to_cfb_encrypter(iv)?;
        let decryptoer = decyrpter.to_cfb_decrypter(iv)?;

        struct Wrapper<A, B> {
            encryptoer: A,
            decryptoer: B,
        }
        impl<A, B> SelfInner for Wrapper<A, B>
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

    pub fn new(
        algorithm: StreamCipherAlgorithm,
        key: &[u8],
        iv: &[u8],
        rounds: Option<usize>,
    ) -> CryptoResult<Self> {
        macro_rules! stream_cipher {
        ($($name:ident,)*) => {
            paste::paste! {
                match algorithm {
                    StreamCipherAlgorithm::Rc4 =>Self::new_impl(Rc4::new(&key)?),
                    StreamCipherAlgorithm::Salsa20 => Self::new_impl(Sala20::new(&key, &iv)?),
                    StreamCipherAlgorithm::Chacha20 => Self::new_impl(
                        Chacha20::new_unauthenticated_cipher(&key, &iv)?,
                    ),
                    $(
                        StreamCipherAlgorithm::[<$name Cfb>] => Self::new_cfb_mode($name::new(&key)?, $name::new(&key)?, &iv)?,
                        StreamCipherAlgorithm::[<$name Ctr>] => Self::new_impl($name::new(&key)?.to_ctr(&iv)?),
                        StreamCipherAlgorithm::[<$name Ofb>] => Self::new_impl($name::new(&key)?.to_ofb(&iv)?),
                    )*
                    StreamCipherAlgorithm::Rc2Cfb => Self::new_cfb_mode(Rc2::new(&key, rounds.unwrap())?, Rc2::new(&key, rounds.unwrap())?, &iv)?,
                    StreamCipherAlgorithm::Rc2Ctr => Self::new_impl(Rc2::new(&key, rounds.unwrap())?.to_ctr(&iv)?),
                    StreamCipherAlgorithm::Rc2Ofb => Self::new_impl(Rc2::new(&key, rounds.unwrap())?.to_ofb(&iv)?),
                    StreamCipherAlgorithm::Rc5Cfb => Self::new_cfb_mode(Rc5::new(&key, rounds.unwrap())?, Rc5::new(&key, rounds.unwrap())?, &iv)?,
                    StreamCipherAlgorithm::Rc5Ctr => Self::new_impl(Rc5::new(&key, rounds.unwrap())?.to_ctr(&iv)?),
                    StreamCipherAlgorithm::Rc5Ofb => Self::new_impl(Rc5::new(&key, rounds.unwrap())?.to_ofb(&iv)?),
                    StreamCipherAlgorithm::Rc6Cfb => Self::new_cfb_mode(Rc6::new(&key, rounds.unwrap())?, Rc6::new(&key, rounds.unwrap())?, &iv)?,
                    StreamCipherAlgorithm::Rc6Ctr => Self::new_impl(Rc6::new(&key, rounds.unwrap())?.to_ctr(&iv)?),
                    StreamCipherAlgorithm::Rc6Ofb => Self::new_impl(Rc6::new(&key, rounds.unwrap())?.to_ofb(&iv)?),
                }

            }
        };
    }

        Ok(stream_cipher!(
            Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea,
        ))
    }
    fn new_impl(stream_cipher: impl StreamCipher + 'static) -> Self {
        struct Wrapper<T>(T);

        impl<T> SelfInner for Wrapper<T>
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
        Self(Box::new(Wrapper(stream_cipher)))
    }

    pub fn encrypt(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
        self.0.encrypt(inout)
    }
    pub fn decrypt(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
        self.0.decrypt(inout)
    }
}

use crate::aes::Aes;
use crate::blowfish::Blowfish;
use crate::cast5::Cast5;
use crate::cipher::gcm::GcmAble;
use crate::des::Des;
use crate::des::TripleDes;
use crate::tea::Tea;
use crate::twofish::Twofish;
use crate::xtea::Xtea;
use crate::{cipher::Aead, error::CryptoResult};

trait ErasedAeadInner {
    fn overhead(&self) -> usize;
    fn nonce_size(&self) -> usize;

    fn open_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()>;

    fn seal_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<Vec<u8>>;
}

macro_rules! aead_cipher {
        ($($name:ident,)*) => {
            paste::paste! {
                pub enum AeadAlgorithm {
                    Chacha20Poly1305,
                    XChacha20Poly1305,
                    $(
                        [<$name Gcm>],
                    )*
                    Rc2Gcm,
                    Rc5Gcm,
                    Rc6Gcm,
                }

            }
        };

    }

aead_cipher!(Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea,);

pub struct EvpAeadCipher(Box<dyn ErasedAeadInner>);

impl EvpAeadCipher {
    pub fn new(algorithm: AeadAlgorithm, key: &[u8], rounds: Option<usize>) -> CryptoResult<Self> {
        macro_rules! aead_cipher {
        ($($name:ident,)*) => {
            paste::paste! {
                Ok(match algorithm {
                    AeadAlgorithm::Chacha20Poly1305 =>Self::new_impl(
                        crate::chacha20poly1305::ChaCha20Poly1305::new(&key)?,
                    ),
                    AeadAlgorithm::XChacha20Poly1305 =>Self::new_impl(
                        crate::chacha20poly1305::XChaCha20Poly1305::new(&key)?,
                    ),
                    $(
                        AeadAlgorithm::[<$name Gcm>] =>Self::new_impl($name::new(&key)?.to_gcm()?),
                    )*
                    AeadAlgorithm::Rc2Gcm =>Self::new_impl(crate::rc2::Rc2::new(&key, rounds.unwrap_or(20))?.to_gcm()?),
                    AeadAlgorithm::Rc5Gcm =>Self::new_impl(crate::rc5::Rc5::new(&key, rounds.unwrap_or(20))?.to_gcm()?),
                    AeadAlgorithm::Rc6Gcm =>Self::new_impl(crate::rc6::Rc6::new(&key, rounds.unwrap_or(20))?.to_gcm()?),
                })

            }
        };

    }

        aead_cipher!(Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea,)
    }

    fn new_impl<const N: usize>(aead: impl Aead<N> + 'static) -> Self {
        struct Wrapper<T, const N: usize>(T);

        impl<const N: usize, T> ErasedAeadInner for Wrapper<T, N>
        where
            T: Aead<N> + 'static,
        {
            fn nonce_size(&self) -> usize {
                self.0.nonce_size()
            }

            fn overhead(&self) -> usize {
                self.0.overhead()
            }

            fn open_in_place_separate_tag(
                &self,
                inout: &mut [u8],
                tag: &[u8],
                nonce: &[u8],
                additional_data: &[u8],
            ) -> CryptoResult<()> {
                self.0
                    .open_in_place_separate_tag(inout, tag, nonce, additional_data)
            }

            fn seal_in_place_separate_tag(
                &self,
                inout: &mut [u8],
                nonce: &[u8],
                additional_data: &[u8],
            ) -> CryptoResult<Vec<u8>> {
                self.0
                    .seal_in_place_separate_tag(inout, nonce, additional_data)
                    .map(|v| v.to_vec())
            }
        }
        Self(Box::new(Wrapper(aead)))
    }

    pub fn nonce_size(&self) -> usize {
        self.0.nonce_size()
    }

    pub fn overhead(&self) -> usize {
        self.0.overhead()
    }

    pub fn seal_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        self.0
            .seal_in_place_separate_tag(inout, nonce, additional_data)
    }

    pub fn seal_in_place_append_tag(
        &self,
        inout: &mut Vec<u8>,
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        let tag = self.seal_in_place_separate_tag(inout, nonce, additional_data)?;
        inout.extend_from_slice(&tag);
        Ok(())
    }

    pub fn open_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        self.0
            .open_in_place_separate_tag(inout, tag, nonce, additional_data)
    }

    pub fn open_in_place(
        &self,
        inout: &mut Vec<u8>,
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        let pos = inout.len() - self.0.overhead();
        let (inout1, tag) = inout.split_at_mut(pos);
        self.open_in_place_separate_tag(inout1, tag, nonce, additional_data)?;
        inout.truncate(pos);
        Ok(())
    }
}

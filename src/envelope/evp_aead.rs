use crate::aead::gcm::Gcm;
use crate::aead::ocb::Ocb;
use crate::aead::ocb3::Ocb3;
use crate::block::aes::Aes;
use crate::block::blowfish::Blowfish;
use crate::block::camellia::Camellia;
use crate::block::cast5::Cast5;
use crate::block::des::Des;
use crate::block::des::TripleDes;
use crate::block::rc2::Rc2;
use crate::block::rc5::Rc5;
use crate::block::rc6::Rc6;
use crate::block::tea::Tea;
use crate::block::twofish::Twofish;
use crate::block::xtea::Xtea;
use crate::{aead::Aead, error::CryptoResult};
use alloc::boxed::Box;
use alloc::vec::Vec;

trait ErasedAeadInner {
    fn tag_size(&self) -> usize;
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

pub struct EvpAeadCipher(Box<dyn ErasedAeadInner>);

macro_rules! impl_aead_cipher {
    (
        basic: [$($basic:ident),* $(,)?],
        rounds: [$($rc:ident),* $(,)?],
        special: [$($special:ident),* $(,)?] $(,)?
    ) => {
        $(
            paste::paste! {
                pub fn [<new_ $basic:lower _gcm>](key: &[u8]) -> CryptoResult<Self> {
                    Ok(Self::new_impl($basic::new(key)?.to_gcm()?))
                }
                pub fn [<new_ $basic:lower _ocb>]<const TAG_SIZE: usize, const NONCE_SIZE: usize>(key: &[u8]) -> CryptoResult<Self> {
                    Ok(Self::new_impl($basic::new(key)?.to_ocb::<TAG_SIZE, NONCE_SIZE>()?))
                }
                pub fn [<new_ $basic:lower _ocb3>]<const TAG_SIZE: usize, const NONCE_SIZE: usize>(key: &[u8]) -> CryptoResult<Self> {
                    Ok(Self::new_impl($basic::new(key)?.to_ocb3::<TAG_SIZE, NONCE_SIZE>()?))
                }
            }
        )*
        $(
            paste::paste! {
                pub fn [<new_ $rc:lower _gcm>](key: &[u8], rounds: Option<usize>) -> CryptoResult<Self> {
                    Ok(Self::new_impl($rc::new(key, rounds)?.to_gcm()?))
                }
            }
        )*
        $(
            impl_aead_cipher!(@special $special);
        )*
    };
    (@special chacha20_poly1305) => {
        pub fn new_chacha20_poly1305(key: &[u8]) -> CryptoResult<Self> {
            Ok(Self::new_impl(crate::aead::chacha20poly1305::ChaCha20Poly1305::new(key)?))
        }
    };
    (@special xchacha20_poly1305) => {
        pub fn new_xchacha20_poly1305(key: &[u8]) -> CryptoResult<Self> {
            Ok(Self::new_impl(crate::aead::chacha20poly1305::XChaCha20Poly1305::new(key)?))
        }
    };
}
impl EvpAeadCipher {
    impl_aead_cipher!(
        basic: [Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Rc6],
        rounds: [Rc2, Rc5, Camellia],
        special: [chacha20_poly1305, xchacha20_poly1305],
    );

    fn new_impl<const N: usize>(aead: impl Aead<N> + 'static) -> Self {
        struct Wrapper<T, const N: usize>(T);

        impl<const N: usize, T> ErasedAeadInner for Wrapper<T, N>
        where
            T: Aead<N> + 'static,
        {
            fn nonce_size(&self) -> usize {
                self.0.nonce_size()
            }

            fn tag_size(&self) -> usize {
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

    pub fn tag_size(&self) -> usize {
        self.0.tag_size()
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
        let pos = inout.len() - self.0.tag_size();
        let (inout1, tag) = inout.split_at_mut(pos);
        self.open_in_place_separate_tag(inout1, tag, nonce, additional_data)?;
        inout.truncate(pos);
        Ok(())
    }
}

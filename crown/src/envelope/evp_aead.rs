use crate::aead::ascon::AsconAead128;
use crate::aead::ccm::Ccm;
use crate::aead::eax::Eax;
use crate::aead::gcm::Gcm;
use crate::aead::gcm_siv::AesGcmSiv;
use crate::aead::ocb3::Ocb3;
use crate::aead::siv::AesSiv;
use crate::block::aes::Aes;
use crate::block::anubis::Anubis;
use crate::block::aria::Aria;
use crate::block::blowfish::Blowfish;
use crate::block::camellia::Camellia;
use crate::block::cast5::Cast5;
use crate::block::des::Des;
use crate::block::des::TripleDes;
use crate::block::idea::Idea;
use crate::block::kasumi::Kasumi;
use crate::block::khazad::Khazad;
use crate::block::kseed::Kseed;
use crate::block::multi2::Multi2;
use crate::block::noekeon::Noekeon;
use crate::block::rc2::Rc2;
use crate::block::rc5::Rc5;
use crate::block::rc6::Rc6;
use crate::block::serpent::Serpent;
use crate::block::skipjack::Skipjack;
use crate::block::sm4::Sm4;
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
                pub fn [<new_ $basic:lower _ocb3>]<const TAG_SIZE: usize, const NONCE_SIZE: usize>(key: &[u8]) -> CryptoResult<Self> {
                    Ok(Self::new_impl($basic::new(key)?.to_ocb3::<TAG_SIZE, NONCE_SIZE>()?))
                }
                pub fn [<new_ $basic:lower _ccm>]<const TAG_SIZE: usize, const NONCE_SIZE: usize>(key: &[u8]) -> CryptoResult<Self> {
                    Ok(Self::new_impl($basic::new(key)?.to_ccm::<TAG_SIZE, NONCE_SIZE>()?))
                }
                pub fn [<new_ $basic:lower _eax>]<const TAG_SIZE: usize>(key: &[u8], nonce_size: usize) -> CryptoResult<Self> {
                    Ok(Self::new_impl($basic::new(key)?.to_eax::<TAG_SIZE>(nonce_size)?))
                }
            }
        )*
        $(
            paste::paste! {
                pub fn [<new_ $rc:lower _gcm>](key: &[u8], rounds: Option<usize>) -> CryptoResult<Self> {
                    Ok(Self::new_impl($rc::new(key, rounds)?.to_gcm()?))
                }
                pub fn [<new_ $rc:lower _ccm>]<const TAG_SIZE: usize, const NONCE_SIZE: usize>(key: &[u8], rounds: Option<usize>) -> CryptoResult<Self> {
                    Ok(Self::new_impl($rc::new(key, rounds)?.to_ccm::<TAG_SIZE, NONCE_SIZE>()?))
                }
                pub fn [<new_ $rc:lower _eax>]<const TAG_SIZE: usize>(key: &[u8], nonce_size: usize, rounds: Option<usize>) -> CryptoResult<Self> {
                    Ok(Self::new_impl($rc::new(key, rounds)?.to_eax::<TAG_SIZE>(nonce_size)?))
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
    (@special aes_gcm_siv) => {
        pub fn new_aes_gcm_siv(key: &[u8]) -> CryptoResult<Self> {
            Ok(Self::new_impl(AesGcmSiv::new(key)?))
        }
    };
    (@special ascon_aead128) => {
        pub fn new_ascon_aead128(key: &[u8]) -> CryptoResult<Self> {
            if key.len() != 16 {
                return Err(crate::error::CryptoError::InvalidKeySize {
                    expected: "16",
                    actual: key.len(),
                });
            }
            let mut k = [0u8; 16];
            k.copy_from_slice(key);
            Ok(Self::new_impl(AsconAead128::new(&k)))
        }
    };
    (@special aes_siv) => {
        /// AES-SIV (RFC 5297). The `nonce` is passed as the first S2V
        /// associated-data component, matching OpenSSL; `additional_data`
        /// becomes the second component when non-empty.
        pub fn new_aes_siv(key: &[u8]) -> CryptoResult<Self> {
            Ok(Self::new_siv_impl(AesSiv::new(key)?))
        }
    };
}

impl EvpAeadCipher {
    impl_aead_cipher!(
        basic: [Aes, Aria, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6, Sm4, Skipjack, Kasumi, Kseed, Anubis, Noekeon, Khazad, Serpent],
        rounds: [Rc2, Rc5, Camellia, Multi2],
        special: [chacha20_poly1305, xchacha20_poly1305, aes_gcm_siv, ascon_aead128, aes_siv],
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
                self.0.tag_size()
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

    fn new_siv_impl(siv: AesSiv) -> Self {
        use alloc::rc::Rc;
        use core::cell::RefCell;

        struct SivWrapper(Rc<RefCell<AesSiv>>);

        impl ErasedAeadInner for SivWrapper {
            fn nonce_size(&self) -> usize {
                // SIV has no fixed nonce size; any non-negative length works.
                0
            }

            fn tag_size(&self) -> usize {
                AesSiv::tag_size()
            }

            fn open_in_place_separate_tag(
                &self,
                inout: &mut [u8],
                tag: &[u8],
                nonce: &[u8],
                additional_data: &[u8],
            ) -> CryptoResult<()> {
                let mut aads: Vec<&[u8]> = Vec::new();
                if !nonce.is_empty() {
                    aads.push(nonce);
                }
                if !additional_data.is_empty() {
                    aads.push(additional_data);
                }
                self.0.borrow_mut().open_in_place(inout, tag, &aads)
            }

            fn seal_in_place_separate_tag(
                &self,
                inout: &mut [u8],
                nonce: &[u8],
                additional_data: &[u8],
            ) -> CryptoResult<Vec<u8>> {
                let mut aads: Vec<&[u8]> = Vec::new();
                if !nonce.is_empty() {
                    aads.push(nonce);
                }
                if !additional_data.is_empty() {
                    aads.push(additional_data);
                }
                let tag = self.0.borrow_mut().seal_in_place(inout, &aads)?;
                Ok(tag.to_vec())
            }
        }

        Self(Box::new(SivWrapper(Rc::new(RefCell::new(siv)))))
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

    pub fn seal_in_place_append_tag<T>(
        &self,
        inout: &mut T,
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()>
    where
        T: Extend<u8> + AsMut<[u8]> + ?Sized,
    {
        let tag = self.seal_in_place_separate_tag(inout.as_mut(), nonce, additional_data)?;
        inout.extend(tag);
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

    pub fn open_in_place<'a>(
        &self,
        inout: &'a mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<&'a mut [u8]> {
        let pos = inout.len() - self.tag_size();
        let (inout, tag) = inout.split_at_mut(pos);
        self.open_in_place_separate_tag(inout, tag, nonce, additional_data)?;
        Ok(inout)
    }
}

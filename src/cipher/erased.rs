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

pub struct ErasedAead(Box<dyn ErasedAeadInner>);

impl ErasedAead {
    pub fn new<const N: usize>(aead: impl Aead<N> + 'static) -> Self {
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

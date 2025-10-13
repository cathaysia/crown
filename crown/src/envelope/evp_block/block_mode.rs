use crate::block::BlockCipher;
use crate::modes::cbc::{CbcDecryptor, CbcEncryptor};
use crate::modes::BlockMode;
use alloc::boxed::Box;

trait ErasedBlockModeInner {
    fn block_size(&self) -> usize;
    fn encrypt(&mut self, inout: &mut [u8]);
    fn decrypt(&mut self, inout: &mut [u8]);
}

pub struct ErasedBlockMode(Box<dyn ErasedBlockModeInner>);

impl ErasedBlockMode {
    pub fn new_cbc<D: BlockCipher>(
        enc: impl CbcEncryptor<D> + 'static,
        dec: impl CbcDecryptor<D> + 'static,
        iv: &[u8],
    ) -> Self {
        let enc = Box::new(enc.to_cbc_enc(iv));
        let dec = Box::new(dec.to_cbc_dec(iv));

        pub struct Wrapper<T, U> {
            enc: Box<T>,
            dec: Box<U>,
        }

        impl<T, U> ErasedBlockModeInner for Wrapper<U, T>
        where
            T: BlockMode + 'static,
            U: BlockMode + 'static,
        {
            fn block_size(&self) -> usize {
                self.enc.block_size()
            }

            fn encrypt(&mut self, inout: &mut [u8]) {
                self.enc.encrypt(inout)
            }

            fn decrypt(&mut self, inout: &mut [u8]) {
                self.dec.encrypt(inout)
            }
        }
        Self(Box::new(Wrapper { enc, dec }))
    }

    pub fn block_size(&self) -> usize {
        self.0.block_size()
    }

    pub fn encrypt(&mut self, inout: &mut [u8]) {
        self.0.encrypt(inout)
    }

    pub fn decrypt(&mut self, inout: &mut [u8]) {
        self.0.decrypt(inout)
    }
}

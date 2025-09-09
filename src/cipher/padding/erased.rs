use crate::{cipher::BlockMode, error::CryptoResult};

use super::{BlockPadding, Padding};

trait ErasedBlockPaddingInner {
    fn block_size(&self) -> usize;
    fn encrypt(&mut self, inout: &mut [u8], pos: usize) -> CryptoResult<usize>;
    fn decrypt(&mut self, inout: &mut [u8]) -> CryptoResult<usize>;

    #[cfg(feature = "alloc")]
    fn encrypt_alloc(&mut self, inout: &mut alloc::vec::Vec<u8>) -> CryptoResult<()>;

    #[cfg(feature = "alloc")]
    fn decrypt_alloc(&mut self, inout: &mut alloc::vec::Vec<u8>) -> CryptoResult<()>;
}

pub struct ErasedBlockPadding(Box<dyn ErasedBlockPaddingInner>);

impl ErasedBlockPadding {
    pub fn new<C, P>(block_padding: BlockPadding<C, P>) -> Self
    where
        C: BlockMode + 'static,
        P: Padding + 'static,
    {
        struct Wrapper<C, P>(BlockPadding<C, P>);

        impl<C, P> ErasedBlockPaddingInner for Wrapper<C, P>
        where
            C: BlockMode + 'static,
            P: Padding + 'static,
        {
            fn block_size(&self) -> usize {
                self.0.block_size()
            }

            fn encrypt(&mut self, inout: &mut [u8], pos: usize) -> CryptoResult<usize> {
                self.0.encrypt(inout, pos)
            }

            fn decrypt(&mut self, inout: &mut [u8]) -> CryptoResult<usize> {
                self.0.decrypt(inout)
            }

            #[cfg(feature = "alloc")]
            fn encrypt_alloc(&mut self, inout: &mut alloc::vec::Vec<u8>) -> CryptoResult<()> {
                self.0.encrypt_alloc(inout)
            }

            #[cfg(feature = "alloc")]
            fn decrypt_alloc(&mut self, inout: &mut alloc::vec::Vec<u8>) -> CryptoResult<()> {
                self.0.decrypt_alloc(inout)
            }
        }

        Self(Box::new(Wrapper(block_padding)))
    }

    pub fn block_size(&self) -> usize {
        self.0.block_size()
    }

    pub fn encrypt(&mut self, inout: &mut [u8], pos: usize) -> CryptoResult<usize> {
        self.0.encrypt(inout, pos)
    }

    pub fn decrypt(&mut self, inout: &mut [u8]) -> CryptoResult<usize> {
        self.0.decrypt(inout)
    }

    #[cfg(feature = "alloc")]
    pub fn encrypt_alloc(&mut self, inout: &mut alloc::vec::Vec<u8>) -> CryptoResult<()> {
        self.0.encrypt_alloc(inout)
    }

    #[cfg(feature = "alloc")]
    pub fn decrypt_alloc(&mut self, inout: &mut alloc::vec::Vec<u8>) -> CryptoResult<()> {
        self.0.decrypt_alloc(inout)
    }
}

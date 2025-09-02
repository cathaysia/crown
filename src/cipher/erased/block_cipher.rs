use crate::cipher::BlockCipher;

trait ErasedBlockCipherInner {
    fn block_size(&self) -> usize;
    fn encrypt(&self, inout: &mut [u8]);
    fn decrypt(&self, inout: &mut [u8]);
}

pub struct ErasedBlockCipher(Box<dyn ErasedBlockCipherInner>);

impl ErasedBlockCipher {
    pub fn new(block_cipher: impl BlockCipher + 'static) -> Self {
        struct Wrapper<T>(T);

        impl<T> ErasedBlockCipherInner for Wrapper<T>
        where
            T: BlockCipher + 'static,
        {
            fn block_size(&self) -> usize {
                self.0.block_size()
            }

            fn encrypt(&self, inout: &mut [u8]) {
                self.0.encrypt(inout)
            }

            fn decrypt(&self, inout: &mut [u8]) {
                self.0.decrypt(inout)
            }
        }
        Self(Box::new(Wrapper(block_cipher)))
    }

    pub fn block_size(&self) -> usize {
        self.0.block_size()
    }

    pub fn encrypt(&self, inout: &mut [u8]) {
        self.0.encrypt(inout)
    }

    pub fn decrypt(&self, inout: &mut [u8]) {
        self.0.decrypt(inout)
    }
}

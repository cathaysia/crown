use crate::cipher::BlockMode;

trait ErasedBlockModeInner {
    fn block_size(&self) -> usize;
    fn crypt_blocks(self: Box<Self>, inout: &mut [u8]);
}

pub struct ErasedBlockMode(Box<dyn ErasedBlockModeInner>);

impl ErasedBlockMode {
    pub fn new(block_mode: impl BlockMode + 'static) -> Self {
        struct Wrapper<T>(T);

        impl<T> ErasedBlockModeInner for Wrapper<T>
        where
            T: BlockMode + 'static,
        {
            fn block_size(&self) -> usize {
                self.0.block_size()
            }

            fn crypt_blocks(self: Box<Self>, inout: &mut [u8]) {
                self.0.crypt_blocks(inout)
            }
        }
        Self(Box::new(Wrapper(block_mode)))
    }

    pub fn block_size(&self) -> usize {
        self.0.block_size()
    }

    pub fn crypt_blocks(self, inout: &mut [u8]) {
        self.0.crypt_blocks(inout)
    }
}

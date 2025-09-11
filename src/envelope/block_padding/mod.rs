mod block_mode;
use block_mode::ErasedBlockMode;

use crate::{
    cipher::{padding::Padding, BlockMode},
    error::{CryptoError, CryptoResult},
};

pub struct BlockPadding {
    cipher: ErasedBlockMode,
    padding: Box<dyn Padding>,
}

impl BlockPadding {
    pub fn new(cipher: impl BlockMode + 'static, padding: Box<dyn Padding>) -> Self {
        BlockPadding {
            cipher: ErasedBlockMode::new(cipher),
            padding,
        }
    }

    pub fn set_padding(&mut self, padding: Box<dyn Padding>) {
        self.padding = padding;
    }

    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    /// Encrypts the input data with padding
    ///
    /// ```svgbob
    /// |<------------ inout ----------->|
    /// +----------------+---------+-----+
    /// |   plaintext    | padding |     |
    /// +----------------+---------+-----+
    /// |<------- returns -------->|
    /// ```
    ///
    pub fn encrypt(&mut self, inout: &mut [u8], pos: usize) -> CryptoResult<usize> {
        let mut end = pos.div_ceil(self.block_size()) * self.block_size();

        let start = (pos / self.block_size()) * self.block_size();
        if start == end {
            end = start + self.block_size();
        }
        if end > inout.len() {
            return Err(CryptoError::InvalidLength);
        }
        self.padding.pad(&mut inout[start..end], pos - start);
        self.cipher.crypt_blocks(&mut inout[..end]);

        Ok(end)
    }

    /// Decrypts the input data with padding
    ///
    /// ```svgbob
    /// |<------- inout ---------->|
    /// +----------------+---------+
    /// |   plaintext    | padding |
    /// +----------------+---------+
    /// |<-- returns --->|
    /// ```
    ///
    pub fn decrypt(&mut self, inout: &mut [u8]) -> CryptoResult<usize> {
        if inout.len() % self.block_size() != 0 {
            return Err(CryptoError::InvalidLength);
        }

        self.cipher.crypt_blocks(inout);
        let start = inout.len() - self.block_size();
        let end = inout.len();

        let new_array = self.padding.unpad(&inout[start..end])?;
        let len = new_array.len();

        Ok(start + len)
    }

    #[cfg(feature = "alloc")]
    pub fn encrypt_alloc(&mut self, inout: &mut alloc::vec::Vec<u8>) -> CryptoResult<()> {
        let pos = inout.len();
        let mut len = inout.len().div_ceil(self.block_size()) * self.block_size();
        if pos == len {
            len += self.block_size();
        }
        #[cfg(debug_assertions)]
        assert!(len > pos);

        inout.resize(len, 0);
        self.encrypt(inout, pos).unwrap();
        Ok(())
    }

    #[cfg(feature = "alloc")]
    pub fn decrypt_alloc(&mut self, inout: &mut alloc::vec::Vec<u8>) -> CryptoResult<()> {
        let len = self.decrypt(inout)?;
        inout.truncate(len);
        Ok(())
    }
}

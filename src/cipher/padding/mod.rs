mod pkcs7;
pub use pkcs7::Pkcs7;

mod block_padding;
pub use block_padding::*;

use core::marker::PhantomData;

use crate::{
    cipher::BlockMode,
    error::{CryptoError, CryptoResult},
};

pub trait Padding {
    /// pad a block
    fn pad(block: &mut [u8], pos: usize);
    /// unpad a block
    fn unpad(block: &[u8]) -> CryptoResult<&[u8]>;
}

pub trait ToPaddingCrypt<C> {
    fn to_padding_crypt<P: Padding>(self) -> BlockPadding<C, P>;
}

impl<C> ToPaddingCrypt<C> for C
where
    C: BlockMode,
{
    fn to_padding_crypt<P>(self) -> BlockPadding<C, P>
    where
        P: Padding,
    {
        BlockPadding {
            cipher: self,
            padding: PhantomData,
        }
    }
}

pub struct BlockPadding<C, P> {
    cipher: C,
    padding: PhantomData<P>,
}

impl<C, P> BlockPadding<C, P>
where
    C: BlockMode,
    P: Padding,
{
    pub fn new(cipher: C) -> Self {
        BlockPadding {
            cipher,
            padding: PhantomData,
        }
    }

    pub fn block_size(&self) -> usize {
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
        P::pad(&mut inout[start..end], pos - start);
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

        let new_array = P::unpad(&inout[start..end])?;
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

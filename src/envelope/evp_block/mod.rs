mod block_mode;

#[cfg(test)]
mod tests;

use crate::block::idea::Idea;
use crate::block::BlockCipher;
use crate::modes::cbc::{CbcDecryptor, CbcEncryptor};
use crate::{
    block::aes::Aes,
    block::blowfish::Blowfish,
    block::camellia::Camellia,
    block::cast5::Cast5,
    block::des::{Des, TripleDes},
    block::rc2::Rc2,
    block::rc5::Rc5,
    block::rc6::Rc6,
    block::tea::Tea,
    block::twofish::Twofish,
    block::xtea::Xtea,
    padding::Pkcs7,
};
use block_mode::ErasedBlockMode;

use crate::{
    error::{CryptoError, CryptoResult},
    padding::Padding,
};

pub struct EvpBlockCipher {
    cipher: ErasedBlockMode,
    padding: Box<dyn Padding>,
}

macro_rules! impl_newer {
    (
        basic: [$($name:ident),* $(,)?],
        rounds: [$($rc:ident),* $(,)?]
    ) => {
        $(
            paste::paste! {
                pub fn [<new_ $name:lower _cbc>](key: &[u8], iv: &[u8]) -> CryptoResult<Self> {
                    Ok(Self::new_impl($name::new(key)?, $name::new(key)?, iv, Box::new(Pkcs7)))
                }
            }
        )*
        $(
            paste::paste! {
                 pub fn [<new_ $rc:lower _cbc>](key: &[u8], iv: &[u8], rounds: Option<usize>) -> CryptoResult<Self> {
                    Ok(Self::new_impl($rc::new(key, rounds)?, $rc::new(key, rounds)?, iv, Box::new(Pkcs7)))
                }
            }
        )*
    };
}

impl EvpBlockCipher {
    impl_newer!(
        basic: [Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6],
        rounds: [Rc2, Rc5, Camellia]
    );

    fn new_impl<D: BlockCipher>(
        enc: impl CbcEncryptor<D> + 'static,
        dec: impl CbcDecryptor<D> + 'static,
        iv: &[u8],
        padding: Box<dyn Padding>,
    ) -> Self {
        EvpBlockCipher {
            cipher: ErasedBlockMode::new_cbc(enc, dec, iv),
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
        self.cipher.encrypt(&mut inout[..end]);

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

        self.cipher.decrypt(inout);
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

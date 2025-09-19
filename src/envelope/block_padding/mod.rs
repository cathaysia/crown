mod block_mode;

#[cfg(test)]
mod tests;

use crate::cipher::cbc::{CbcDecAble, CbcEncAble};
use crate::cipher::BlockCipher;
use crate::{
    aes::Aes,
    blowfish::Blowfish,
    cast5::Cast5,
    cipher::padding::Pkcs7,
    des::{Des, TripleDes},
    rc2::Rc2,
    rc5::Rc5,
    rc6::Rc6,
    tea::Tea,
    twofish::Twofish,
    xtea::Xtea,
};
use block_mode::ErasedBlockMode;

use crate::{
    cipher::padding::Padding,
    error::{CryptoError, CryptoResult},
};

pub struct EvpBlockCipher {
    cipher: ErasedBlockMode,
    padding: Box<dyn Padding>,
}

macro_rules! impl_newer {
    ($($name:ident,)*) => {
        paste::paste! {
            $(
                pub fn [<new_ $name:lower _cbc>](key: &[u8], iv: &[u8]) -> CryptoResult<Self> {
                    Ok(Self::new_impl($name::new(key)?, $name::new(key)?, iv, Box::new(Pkcs7)))
                }
            )*

            pub fn new_rc2_cbc(key: &[u8], iv: &[u8], rounds: Option<usize>)->CryptoResult<Self> {
                Ok(Self::new_impl(Rc2::new(key, rounds.unwrap_or(20))?, Rc2::new(key, rounds.unwrap_or(20))?, iv, Box::new(Pkcs7)))
            }

            pub fn new_rc5_cbc(key: &[u8], iv: &[u8], rounds: Option<usize>)->CryptoResult<Self> {
                Ok(Self::new_impl(Rc5::new(key, rounds.unwrap_or(20))?, Rc5::new(key, rounds.unwrap_or(20))?, iv, Box::new(Pkcs7)))
            }

            pub fn new_rc6_cbc(key: &[u8], iv: &[u8], rounds: Option<usize>)->CryptoResult<Self> {
                Ok(Self::new_impl(Rc6::new(key, rounds.unwrap_or(20))?, Rc6::new(key, rounds.unwrap_or(20))?, iv, Box::new(Pkcs7)))
            }
        }
    };
}

impl EvpBlockCipher {
    impl_newer!(Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea,);

    fn new_impl<D: BlockCipher>(
        enc: impl CbcEncAble<D> + 'static,
        dec: impl CbcDecAble<D> + 'static,
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

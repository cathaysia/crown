use crate::error::CryptoError;

impl<T> super::Padding for T
where
    T: block_padding::RawPadding,
{
    fn pad(&self, block: &mut [u8], pos: usize) {
        Self::raw_pad(block, pos);
    }

    fn unpad<'a>(&self, block: &'a [u8]) -> crate::error::CryptoResult<&'a [u8]> {
        Self::raw_unpad(block).map_err(|_| CryptoError::UnpadError)
    }
}

pub use block_padding::{AnsiX923, Iso10126, Iso7816, NoPadding, ZeroPadding};

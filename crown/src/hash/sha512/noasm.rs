use super::block::block_generic;
use super::*;
use crate::error::CryptoResult;

impl<const N: usize> Sha512<N> {
    pub(crate) fn block(&mut self, p: &[u8]) -> CryptoResult<()> {
        block_generic(self, p)
    }
}

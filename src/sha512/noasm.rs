use super::*;
use crate::{error::CryptoResult, sha512::block::block_generic};

impl<const N: usize> Sha512<N> {
    pub(crate) fn block(&mut self, p: &[u8]) -> CryptoResult<()> {
        block_generic(self, p)
    }
}

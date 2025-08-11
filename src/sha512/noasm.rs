use super::*;
use crate::{error::CryptoResult, sha512::block::block_generic};

impl Sha512 {
    pub(crate) fn block(&mut self, p: &[u8]) -> CryptoResult<()> {
        block_generic(self, p)
    }
}

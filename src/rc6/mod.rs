//! Module rc6 implements the Rc6 stream cipher algorithm.
#[cfg(test)]
mod tests;

mod imp;
use crate::{
    cipher::{marker::BlockCipherMarker, BlockCipher},
    error::CryptoResult,
};
use imp::*;

pub struct Rc6 {
    skey: Rc6Key,
}

impl BlockCipherMarker for Rc6 {}

impl Rc6 {
    pub fn new(key: &[u8], num_rounds: usize) -> CryptoResult<Self> {
        let mut skey: Rc6Key = unsafe { core::mem::zeroed() };

        rc6_setup(key, key.len(), num_rounds, &mut skey)?;

        Ok(Self { skey })
    }
}

impl BlockCipher for Rc6 {
    fn block_size(&self) -> usize {
        16
    }

    fn encrypt(&self, inout: &mut [u8]) {
        let ret = rc6_ecb_encrypt(inout, &self.skey);
        assert!(ret.is_ok());
    }

    fn decrypt(&self, inout: &mut [u8]) {
        let ret = rc6_ecb_decrypt(inout, &self.skey);
        assert!(ret.is_ok());
    }
}

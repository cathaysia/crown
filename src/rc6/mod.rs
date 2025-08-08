#[cfg(test)]
mod tests;

mod imp;
use crate::cipher::{marker::BlockCipherMarker, BlockCipher};
use imp::*;

use std::mem::MaybeUninit;

pub struct Rc6 {
    skey: Rc6Key,
}

impl BlockCipherMarker for Rc6 {}

impl Rc6 {
    pub fn new(key: &[u8], num_rounds: usize) -> Self {
        unsafe {
            let skey = MaybeUninit::<Rc6Key>::uninit();
            let mut skey = skey.assume_init();

            let err = rc6_setup(key, key.len(), num_rounds, &mut skey);
            assert!(err.is_ok());

            Self { skey }
        }
    }
}

impl BlockCipher for Rc6 {
    fn block_size(&self) -> usize {
        16
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
        let ret = rc6_ecb_encrypt(src, dst, &self.skey);
        assert!(ret.is_ok());
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
        let ret = rc6_ecb_decrypt(src, dst, &self.skey);
        assert!(ret.is_ok());
    }
}

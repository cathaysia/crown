#[cfg(test)]
mod tests;

mod imp;
use crate::cipher::BlockCipher;
use imp::*;

use std::{fmt, mem::MaybeUninit};

pub struct Rc6 {
    skey: Rc6Key,
}

impl BlockCipher for Rc6 {
    fn block_size(&self) -> usize {
        16
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
        let ret = unsafe { rc6_ecb_encrypt(src.as_ptr(), dst.as_mut_ptr(), &self.skey) };
        assert!(ret.is_ok());
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
        let ret = unsafe { rc6_ecb_decrypt(src.as_ptr(), dst.as_mut_ptr(), &self.skey) };
        assert!(ret.is_ok());
    }
}

impl Rc6 {
    pub fn new(key: &[u8], num_rounds: usize) -> Self {
        unsafe {
            let skey = MaybeUninit::<Rc6Key>::uninit();
            let mut skey = skey.assume_init();

            let err = rc6_setup(key.as_ptr(), key.len(), num_rounds, &mut skey);
            assert!(err.is_ok());

            Self { skey }
        }
    }
}

impl fmt::Debug for Rc6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Rc6 { ... }")
    }
}

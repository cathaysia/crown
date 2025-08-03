#[cfg(test)]
mod tests;

mod imp;
use imp::*;

use std::{fmt, mem::MaybeUninit};

use crate::error::CryptoResult;

pub struct Rc6 {
    skey: Rc6Key,
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

    ///
    /// Encrypts a block of text with LTC_RC6
    /// * `pt`: The input plaintext (16 bytes)
    /// * `ct`: The output ciphertext (16 bytes)
    /// * `skey`: The key as scheduled
    ///
    pub fn encrypt(&self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut buf = plaintext.to_vec();
        let ret = unsafe { rc6_ecb_encrypt(plaintext.as_ptr(), buf.as_mut_ptr(), &self.skey) };
        assert!(ret.is_ok());
        Ok(buf)
    }

    ///
    ///  Decrypts a block of text with LTC_RC6
    ///  * `ct`: The input ciphertext (16 bytes)
    ///  * `pt`: The output plaintext (16 bytes)
    ///  * `skey`: The key as scheduled
    ///
    pub fn decrypt(&self, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut buf = vec![0u8; ciphertext.len()];

        let ret = unsafe { rc6_ecb_decrypt(ciphertext.as_ptr(), buf.as_mut_ptr(), &self.skey) };
        assert!(ret.is_ok());

        Ok(buf)
    }
}

impl fmt::Debug for Rc6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Rc6 { ... }")
    }
}

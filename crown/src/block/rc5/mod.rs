//! Module rc5 implements the RC5 cipher
//!
//! RC5 is a symmetric-key block cipher.
use crate::{
    block::{BlockCipher, BlockCipherMarker},
    error::CryptoResult,
};

mod generic;

#[cfg(test)]
mod tests;

pub struct Rc5 {
    key: [u32; 50],
    rounds: usize,
}

impl BlockCipherMarker for Rc5 {}

impl Rc5 {
    pub const BLOCK_SIZE: usize = 8;
    pub fn new(key: &[u8], rounds: Option<usize>) -> CryptoResult<Self> {
        let mut sk: Self = Self {
            key: [0; 50],
            rounds: 0,
        };
        sk.setup(key, rounds.unwrap_or(0))?;

        Ok(sk)
    }
}

impl BlockCipher for Rc5 {
    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    fn encrypt(&self, inout: &mut [u8]) {
        self.encrypt_generic(inout).unwrap();
    }

    fn decrypt(&self, inout: &mut [u8]) {
        self.decrypt_generic(inout).unwrap();
    }
}

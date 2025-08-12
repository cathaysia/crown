use crate::{
    cipher::{marker::BlockCipherMarker, BlockCipher},
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
    pub fn new(key: &[u8], rounds: usize) -> CryptoResult<Self> {
        let mut sk: Self = unsafe { std::mem::zeroed() };
        sk.setup(key, rounds)?;

        Ok(sk)
    }
}

impl BlockCipher for Rc5 {
    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
        self.encrypt_generic(src, dst).unwrap();
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
        self.decrypt_generic(src, dst).unwrap();
    }
}

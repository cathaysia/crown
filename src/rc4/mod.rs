//! Module rc4 implements RC4 encryption, as defined in Bruce Schneier's
//! Applied Cryptography.
//!
//! RC4 is cryptographically broken and should not be used for secure
//! applications.
#[cfg(test)]
mod tests;

use crate::{
    cipher::StreamCipher,
    error::{CryptoError, CryptoResult},
};

/// RC4 cipher instance using a particular key
pub struct Rc4 {
    s: [u32; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Creates and returns a new Cipher. The key argument should be the
    /// RC4 key, at least 1 byte and at most 256 bytes.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        let k = key.len();
        if !(1..=256).contains(&k) {
            return Err(CryptoError::InvalidKeySize(k));
        }

        let mut c = Rc4 {
            s: [0; 256],
            i: 0,
            j: 0,
        };

        // Initialize s array
        for i in 0..256 {
            c.s[i] = i as u32;
        }

        // Key scheduling algorithm
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(c.s[i] as u8).wrapping_add(key[i % k]);
            c.s.swap(i, j as usize);
        }

        Ok(c)
    }
}

impl StreamCipher for Rc4 {
    /// Sets dst to the result of XORing src with the key stream.
    /// Dst and src must overlap entirely or not at all.
    fn xor_key_stream(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
        if inout.is_empty() {
            return Ok(());
        }

        let mut i = self.i;
        let mut j = self.j;

        for v in inout.iter_mut() {
            i = i.wrapping_add(1);
            let x = self.s[i as usize];
            j = j.wrapping_add(x as u8);
            let y = self.s[j as usize];
            self.s[i as usize] = y;
            self.s[j as usize] = x;
            *v ^= self.s[(x.wrapping_add(y) as u8) as usize] as u8;
        }

        self.i = i;
        self.j = j;
        Ok(())
    }
}

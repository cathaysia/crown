#[cfg(test)]
mod tests;

use crate::{
    cipher::StreamCipher,
    error::{CryptoError, CryptoResult},
    utils::inexact_overlap,
};

/// RC4 cipher instance using a particular key
pub struct Rc4Cipher {
    s: [u32; 256],
    i: u8,
    j: u8,
}

impl Rc4Cipher {
    /// Creates and returns a new Cipher. The key argument should be the
    /// RC4 key, at least 1 byte and at most 256 bytes.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        let k = key.len();
        if !(1..=256).contains(&k) {
            return Err(CryptoError::InvalidKeySize(k));
        }

        let mut c = Rc4Cipher {
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

    /// Reset zeros the key data and makes the Cipher unusable.
    ///
    /// Deprecated: Reset can't guarantee that the key will be entirely removed from
    /// the process's memory.
    pub fn reset(&mut self) {
        for i in 0..256 {
            self.s[i] = 0;
        }
        self.i = 0;
        self.j = 0;
    }
}

impl StreamCipher for Rc4Cipher {
    /// Sets dst to the result of XORing src with the key stream.
    /// Dst and src must overlap entirely or not at all.
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) -> CryptoResult<()> {
        if src.is_empty() {
            return Ok(());
        }

        // Check for invalid buffer overlap
        if inexact_overlap(&dst[..src.len()], src) {
            return Err(CryptoError::InvalidBufferOverlap);
        }

        let mut i = self.i;
        let mut j = self.j;

        let dst = &mut dst[..src.len()]; // eliminate bounds check from loop

        for (k, &v) in src.iter().enumerate() {
            i = i.wrapping_add(1);
            let x = self.s[i as usize];
            j = j.wrapping_add(x as u8);
            let y = self.s[j as usize];
            self.s[i as usize] = y;
            self.s[j as usize] = x;
            dst[k] = v ^ (self.s[(x.wrapping_add(y) as u8) as usize] as u8);
        }

        self.i = i;
        self.j = j;
        Ok(())
    }
}

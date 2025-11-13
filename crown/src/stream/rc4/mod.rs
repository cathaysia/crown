//! Module rc4 implements RC4 encryption, as defined in Bruce Schneier's
//! Applied Cryptography.
//!
//! RC4 is cryptographically broken and should not be used for secure
//! applications.
#[cfg(test)]
mod tests;

mod xor_key_stream;

use crate::error::{CryptoError, CryptoResult};

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
            return Err(CryptoError::InvalidKeySize {
                expected: "1..=256",
                actual: k,
            });
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

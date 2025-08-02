#[cfg(test)]
mod tests;

use std::fmt;

/// RC4 cipher instance using a particular key
pub struct Cipher {
    s: [u32; 256],
    i: u8,
    j: u8,
}

/// Error type for invalid key sizes
#[derive(Debug, Clone, Copy)]
pub struct KeySizeError(usize);

impl fmt::Display for KeySizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "crypto/rc4: invalid key size {}", self.0)
    }
}

impl std::error::Error for KeySizeError {}

impl Cipher {
    /// Creates and returns a new Cipher. The key argument should be the
    /// RC4 key, at least 1 byte and at most 256 bytes.
    pub fn new(key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let k = key.len();
        if !(1..=256).contains(&k) {
            return Err(Box::new(KeySizeError(k)));
        }

        let mut c = Cipher {
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

    /// Sets dst to the result of XORing src with the key stream.
    /// Dst and src must overlap entirely or not at all.
    pub fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) {
        if src.is_empty() {
            return;
        }

        // Check for invalid buffer overlap
        if self.has_inexact_overlap(&dst[..src.len()], src) {
            panic!("crypto/rc4: invalid buffer overlap");
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
    }

    /// Check for inexact overlap between two byte slices
    fn has_inexact_overlap(&self, a: &[u8], b: &[u8]) -> bool {
        let a_start = a.as_ptr() as usize;
        let a_end = a_start + a.len();
        let b_start = b.as_ptr() as usize;
        let b_end = b_start + b.len();

        // Check if they overlap but not exactly
        if a_start == b_start && a.len() == b.len() {
            false // exact overlap is allowed
        } else {
            // Check for any overlap
            !(a_end <= b_start || b_end <= a_start)
        }
    }
}

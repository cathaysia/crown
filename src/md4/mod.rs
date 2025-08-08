//! Package md4 implements the MD4 hash algorithm as defined in RFC 1320.
//!
//! Deprecated: MD4 is cryptographically broken and should only be used
//! where compatibility with legacy systems, not security, is the goal. Instead,
//! use a secure hash like SHA-256 (from [sha256](crate::sha256::Digest)).

mod block;

#[cfg(test)]
mod tests;

use crate::hash::Hash;
use std::io::{self, Write};

// The size of an MD4 checksum in bytes.
pub const SIZE: usize = 16;

// The blocksize of MD4 in bytes.
pub const BLOCK_SIZE: usize = 64;

const CHUNK: usize = 64;
const INIT0: u32 = 0x67452301;
const INIT1: u32 = 0xEFCDAB89;
const INIT2: u32 = 0x98BADCFE;
const INIT3: u32 = 0x10325476;

pub struct Digest {
    pub s: [u32; 4],
    pub x: [u8; CHUNK],
    pub nx: usize,
    pub len: u64,
}

impl Digest {
    pub fn new() -> Self {
        let mut d = Digest {
            s: [0; 4],
            x: [0; CHUNK],
            nx: 0,
            len: 0,
        };
        d.reset();
        d
    }

    pub fn reset(&mut self) {
        self.s[0] = INIT0;
        self.s[1] = INIT1;
        self.s[2] = INIT2;
        self.s[3] = INIT3;
        self.nx = 0;
        self.len = 0;
    }

    pub fn size(&self) -> usize {
        SIZE
    }

    pub fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    pub fn sum(&mut self, input: &[u8]) -> Vec<u8> {
        // Make a copy of self, so that caller can keep writing and summing.
        let mut d = *self;

        // Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
        let len = d.len;
        let mut tmp = [0u8; 64];
        tmp[0] = 0x80;

        if len % 64 < 56 {
            let _ = d.write(&tmp[0..(56 - (len % 64) as usize)]);
        } else {
            let _ = d.write(&tmp[0..(64 + 56 - (len % 64) as usize)]);
        }

        // Length in bits.
        let len_bits = len << 3;
        (0..8).for_each(|i| {
            tmp[i] = (len_bits >> (8 * i)) as u8;
        });
        let _ = d.write(&tmp[0..8]);

        if d.nx != 0 {
            panic!("d.nx != 0");
        }

        let mut result = input.to_vec();
        for s in &d.s {
            result.push(*s as u8);
            result.push((s >> 8) as u8);
            result.push((s >> 16) as u8);
            result.push((s >> 24) as u8);
        }
        result
    }
}

impl Write for Digest {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        let nn = p.len();
        self.len += nn as u64;
        let mut p = p;

        if self.nx > 0 {
            let n = std::cmp::min(p.len(), CHUNK - self.nx);
            self.x[self.nx..self.nx + n].copy_from_slice(&p[..n]);
            self.nx += n;
            if self.nx == CHUNK {
                let x = self.x.to_vec();
                block::block(self, &x);
                self.nx = 0;
            }
            p = &p[n..];
        }

        let n = block::block(self, p);
        p = &p[n..];

        if !p.is_empty() {
            self.nx = p.len();
            self.x[..self.nx].copy_from_slice(p);
        }

        Ok(nn)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Hash for Digest {
    fn sum(&mut self, input: &[u8]) -> Vec<u8> {
        self.sum(input)
    }

    fn reset(&mut self) {
        self.reset();
    }

    fn size(&self) -> usize {
        self.size()
    }

    fn block_size(&self) -> usize {
        self.block_size()
    }
}

impl Default for Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Digest {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for Digest {}

/// Create a new MD4 hasher
pub fn new() -> Digest {
    Digest::new()
}

pub fn sum(input: &[u8]) -> [u8; 16] {
    let mut h = new();
    h.write_all(input).unwrap();
    h.sum(&[]).try_into().unwrap()
}

//! Module ripemd160 implements the RIPEMD-160 hash algorithm as defined in
//! "RIPEMD-160: A Strengthened Version of RIPEMD" (Dobbertin, Bosselaers,
//! Preneel) and used in Bitcoin and other legacy applications.
//!
//! RIPEMD-160 produces a 160-bit (20-byte) digest with a 64-byte block size,
//! processing each block with two independent parallel compression lines.
//!
//! Reference: <https://homes.esat.kuleuven.be/~bosselae/ripemd160.html>
//!
//! # WARNING
//!
//! RIPEMD-160 offers only a 80-bit collision resistance and should be
//! considered legacy; prefer SHA-256 or SHA-3 for new designs.

mod block;

#[cfg(test)]
mod tests;

use bytes::BufMut;
#[cfg(feature = "marshal")]
use crown_derive::Marshal;

use crate::{
    core::CoreWrite,
    error::CryptoResult,
    hash::{Hash, HashUser},
    utils::erase_ownership,
};

const CHUNK: usize = 64;
const INIT0: u32 = 0x67452301;
const INIT1: u32 = 0xEFCDAB89;
const INIT2: u32 = 0x98BADCFE;
const INIT3: u32 = 0x10325476;
const INIT4: u32 = 0xC3D2E1F0;

#[derive(Clone)]
#[cfg_attr(feature = "marshal", derive(Marshal))]
#[cfg_attr(feature = "marshal", marshal(magic = b"r160"))]
pub struct Ripemd160 {
    s: [u32; 5],
    x: [u8; CHUNK],
    nx: usize,
    len: u64,
}

impl Ripemd160 {
    /// The blocksize of RIPEMD-160 in bytes.
    const BLOCK_SIZE: usize = 64;
    /// The size of a RIPEMD-160 checksum in bytes.
    const SIZE: usize = 20;
}

impl CoreWrite for Ripemd160 {
    fn write(&mut self, p: &[u8]) -> CryptoResult<usize> {
        let nn = p.len();
        self.len += nn as u64;
        let mut p = p;

        if self.nx > 0 {
            let n = core::cmp::min(p.len(), CHUNK - self.nx);
            self.x[self.nx..self.nx + n].copy_from_slice(&p[..n]);
            self.nx += n;
            if self.nx == CHUNK {
                let src = unsafe { erase_ownership(&self.x) };
                block::block(self, src);
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

    fn flush(&mut self) -> CryptoResult<()> {
        Ok(())
    }
}

impl HashUser for Ripemd160 {
    fn reset(&mut self) {
        self.s[0] = INIT0;
        self.s[1] = INIT1;
        self.s[2] = INIT2;
        self.s[3] = INIT3;
        self.s[4] = INIT4;
        self.nx = 0;
        self.len = 0;
    }

    fn size(&self) -> usize {
        Self::SIZE
    }

    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }
}

impl Hash<20> for Ripemd160 {
    fn sum(&mut self) -> [u8; 20] {
        // Make a copy of self, so that caller can keep writing and summing.
        let mut d = self.clone();

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

        let mut result = [0u8; 20];
        {
            let mut result = result.as_mut_slice();
            result.put_u32_le(d.s[0]);
            result.put_u32_le(d.s[1]);
            result.put_u32_le(d.s[2]);
            result.put_u32_le(d.s[3]);
            result.put_u32_le(d.s[4]);
        }
        result
    }
}

/// Create a new [Hash] computing the RIPEMD-160 checksum.
pub fn new_ripemd160() -> Ripemd160 {
    let mut d = Ripemd160 {
        s: [0; 5],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
    };
    d.reset();
    d
}

/// Compute the RIPEMD-160 checksum of the input.
pub fn sum_ripemd160(input: &[u8]) -> [u8; 20] {
    let mut h = new_ripemd160();
    h.write_all(input).unwrap();
    h.sum()
}

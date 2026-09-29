//! Module whirlpool implements the Whirlpool hash algorithm as specified in
//! ISO/IEC 10118-3 (the final "Whirlpool" version with the corrected S-box).
//!
//! Whirlpool produces a 512-bit (64-byte) digest with a 64-byte block size
//! and ten rounds of the Whirlpool permutation combined through the
//! Miyaguchi–Preneel construction. Internals follow the OpenSSL
//! byte/quadword union layout: message lanes are loaded little-endian, the
//! combined S-box/circulant table is indexed per byte with byte-position
//! rotations, and the digest is the little-endian byte view of the state
//! lanes — exactly reproducing `openssl dgst -whirlpool` output.
//!
//! Reference: OpenSSL `crypto/whrlpool`; ISO/IEC 10118-3 test vector set.
//!
//! # WARNING
//!
//! Whirlpool is not widely deployed; prefer SHA-256/SHA-3 for new designs.

mod consts;
#[cfg(test)]
mod tests;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
mod asm;

use consts::TABLE;
#[cfg(feature = "marshal")]
use crown_derive::Marshal;


#[allow(unused_imports)]
use bytes::BufMut;

use crate::{
    core::CoreWrite,
    error::CryptoResult,
    hash::{Hash, HashUser},
};

const CHUNK: usize = 64;
const ROUNDS: usize = 10;
/// The 256-bit bit counter occupies the last 32 bytes of the final block.
const COUNTER: usize = 32;

#[derive(Clone)]
#[cfg_attr(feature = "marshal", derive(Marshal))]
#[cfg_attr(feature = "marshal", marshal(magic = b"whpl"))]
pub struct Whirlpool {
    h: [u64; 8],
    data: [u8; CHUNK],
    num: usize,
    /// Total input length in bytes.
    len: u64,
}

impl Whirlpool {
    /// The blocksize of Whirlpool in bytes.
    const BLOCK_SIZE: usize = CHUNK;
    /// The size of a Whirlpool checksum in bytes.
    const SIZE: usize = 64;
}

/// One Whirlpool compression: Miyaguchi–Preneel over the ten-round
/// permutation of `H` and the 64-byte message block.
fn block(h: &mut [u64; 8], p: &[u8]) {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        asm::block(h, p);
    }

    #[cfg(any(not(feature = "asm"), not(target_arch = "x86_64")))]
    {
        block_soft(h, p);
    }
}

#[allow(dead_code)]
fn block_soft(h: &mut [u64; 8], p: &[u8]) {
    let mut k = *h;
    let mut s = [0u64; 8];
    let mut m = [0u64; 8];

    for i in 0..8 {
        m[i] = u64::from_le_bytes(p[8 * i..8 * i + 8].try_into().unwrap());
        k[i] = h[i];
        s[i] = k[i] ^ m[i];
    }

    for r in 0..ROUNDS {
        // Round key update: theta-pi-gamma of K, plus the round constant in
        // lane 0.
        let mut l = [0u64; 8];
        for i in 0..8 {
            let mut v = 0u64;
            for n in 0..8 {
                let byte = (k[(i + 8 - n) & 7] >> (8 * n)) & 0xff;
                v ^= TABLE[byte as usize].rotate_left((8 * n) as u32);
            }
            l[i] = v;
        }
        l[0] ^= TABLE[256 + r];
        k = l;

        // State update: theta-pi-gamma of S, masked with the new key. All
        // lanes read the *old* S (the reference overwrites S only after the
        // full round), so stage the result before assigning.
        let mut t = [0u64; 8];
        for i in 0..8 {
            let mut v = l[i];
            for n in 0..8 {
                let byte = (s[(i + 8 - n) & 7] >> (8 * n)) & 0xff;
                v ^= TABLE[byte as usize].rotate_left((8 * n) as u32);
            }
            t[i] = v;
        }
        s = t;
    }

    for i in 0..8 {
        h[i] ^= s[i] ^ m[i];
    }
}

impl CoreWrite for Whirlpool {
    fn write(&mut self, p: &[u8]) -> CryptoResult<usize> {
        let nn = p.len();
        self.len = self.len.wrapping_add(nn as u64);
        let mut p = p;

        if self.num > 0 {
            let n = core::cmp::min(p.len(), CHUNK - self.num);
            self.data[self.num..self.num + n].copy_from_slice(&p[..n]);
            self.num += n;
            p = &p[n..];
            if self.num == CHUNK {
                let buf = self.data;
                block(&mut self.h, &buf);
                self.num = 0;
            }
        }

        let full = p.len() / CHUNK * CHUNK;
        for chunk in p[..full].as_chunks::<CHUNK>().0 {
            block(&mut self.h, chunk);
        }
        p = &p[full..];

        if !p.is_empty() {
            self.data[..p.len()].copy_from_slice(p);
            self.num = p.len();
        }

        Ok(nn)
    }

    fn flush(&mut self) -> CryptoResult<()> {
        Ok(())
    }
}

impl HashUser for Whirlpool {
    fn reset(&mut self) {
        self.h = [0; 8];
        self.data = [0; CHUNK];
        self.num = 0;
        self.len = 0;
    }

    fn size(&self) -> usize {
        Self::SIZE
    }

    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }
}

impl Hash<64> for Whirlpool {
    fn sum(&mut self) -> [u8; 64] {
        // Make a copy of self, so that caller can keep writing and summing.
        let mut d = self.clone();

        // Append the 0x80 byte, zero-fill, and store the 256-bit big-endian
        // bit length in the last 32 bytes (only the low 128 bits are
        // representable through the byte-oriented API).
        let bits = (d.len as u128).wrapping_mul(8);

        d.data[d.num] = 0x80;
        let mut off = d.num + 1;

        if off > CHUNK - COUNTER {
            d.data[off..CHUNK].fill(0);
            let buf = d.data;
            block(&mut d.h, &buf);
            off = 0;
        }

        d.data[off..CHUNK - COUNTER].fill(0);
        d.data[CHUNK - COUNTER..CHUNK - 16].fill(0);
        d.data[CHUNK - 16..].copy_from_slice(&bits.to_be_bytes());

        let buf = d.data;
        block(&mut d.h, &buf);

        let mut out = [0u8; 64];
        for (i, w) in d.h.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

/// Create a new [Hash] computing the Whirlpool checksum.
pub fn new_whirlpool() -> Whirlpool {
    let mut d = Whirlpool {
        h: [0; 8],
        data: [0; CHUNK],
        num: 0,
        len: 0,
    };
    d.reset();
    d
}

/// Compute the Whirlpool checksum of the input.
pub fn sum_whirlpool(input: &[u8]) -> [u8; 64] {
    let mut h = new_whirlpool();
    h.write_all(input).unwrap();
    h.sum()
}

#[cfg(test)]
mod debug_tests {
    use super::*;

    #[test]
    fn debug_empty_block() {
        let mut data = [0u8; 64];
        data[0] = 0x80;
        let mut h = [0u64; 8];
        block(&mut h, &data);
        println!("h after 1 block: {:016x?}", h);

        // round-by-round
        let mut k = [0u64; 8];
        let mut m = [0u64; 8];
        for i in 0..8 {
            m[i] = u64::from_le_bytes(data[8 * i..8 * i + 8].try_into().unwrap());
        }
        let mut s = [0u64; 8];
        for i in 0..8 {
            s[i] = k[i] ^ m[i];
        }
        for r in 0..3 {
            let mut l = [0u64; 8];
            for i in 0..8 {
                let mut v = 0u64;
                for n in 0..8 {
                    let byte = (k[(i + 8 - n) & 7] >> (8 * n)) & 0xff;
                    v ^= TABLE[byte as usize].rotate_left((8 * n) as u32);
                }
                l[i] = v;
            }
            l[0] ^= TABLE[256 + r];
            k = l;
            for i in 0..8 {
                let mut v = l[i];
                for n in 0..8 {
                    let byte = (s[(i + 8 - n) & 7] >> (8 * n)) & 0xff;
                    v ^= TABLE[byte as usize].rotate_left((8 * n) as u32);
                }
                s[i] = v;
            }
            println!("round {r}: k={k:016x?} s={s:016x?}");
        }
    }
}

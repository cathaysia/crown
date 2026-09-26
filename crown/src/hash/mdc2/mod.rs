//! Module mdc2 implements the MDC-2 (Modification Detection Code) hash
//! based on DES, per ISO/IEC 10118-2 (with the OpenSSL pad-type extension).
//!
//! MDC-2 runs two independent DES encryptions per 8-byte block — one keyed
//! by the `h` state (with bit 6 forced on) and one keyed by `hh` (with bit 5
//! forced on), both set to odd DES parity — and combines the results back
//! into the two states. The digest is `h || hh` (16 bytes).
//!
//! Padding follows the OpenSSL `MDC2_PAD_*` options:
//! - `PAD_1` (default): a trailing partial block is zero-filled; a
//!   block-aligned input gets no extra block.
//! - `PAD_2`: a `0x80 0x00...` block is always appended after zero-filling
//!   any partial block.
//!
//! Reference: OpenSSL `crypto/mdc2/mdc2dgst.c`.
//!
//! # WARNING
//!
//! MDC-2 is a legacy construction; do not use it in new designs.

#[cfg(test)]
mod tests;

use bytes::BufMut;
#[cfg(feature = "marshal")]
use crown_derive::Marshal;

use crate::{
    block::{des::Des, BlockCipher},
    core::CoreWrite,
    error::CryptoResult,
    hash::{Hash, HashUser},
};

const CHUNK: usize = 8;
const INIT_H: u8 = 0x52;
const INIT_HH: u8 = 0x25;

/// ISO/IEC 10118-2 padding: zero-fill a trailing partial block only.
pub const PAD_1: u8 = 1;
/// Padding with an always-appended `0x80` block.
pub const PAD_2: u8 = 2;

#[derive(Clone)]
#[cfg_attr(feature = "marshal", derive(Marshal))]
#[cfg_attr(feature = "marshal", marshal(magic = b"mdc2"))]
pub struct Mdc2 {
    h: [u8; CHUNK],
    hh: [u8; CHUNK],
    data: [u8; CHUNK],
    num: usize,
    pad_type: u8,
}

impl Mdc2 {
    /// The blocksize of MDC-2 in bytes.
    const BLOCK_SIZE: usize = CHUNK;
    /// The size of an MDC-2 checksum in bytes.
    const SIZE: usize = 16;

    /// Create a new MDC-2 instance with the given pad type
    /// ([`PAD_1`] or [`PAD_2`]).
    pub fn new_with_pad(pad_type: u8) -> CryptoResult<Self> {
        if pad_type != PAD_1 && pad_type != PAD_2 {
            return Err(crate::error::CryptoError::InvalidLength);
        }
        let mut d = Mdc2 {
            h: [0; CHUNK],
            hh: [0; CHUNK],
            data: [0; CHUNK],
            num: 0,
            pad_type,
        };
        d.reset();
        Ok(d)
    }
}

/// Set the least-significant bit of every byte so the byte carries odd
/// parity (the DES odd-parity adjustment).
fn set_odd_parity(key: &mut [u8; CHUNK]) {
    for b in key.iter_mut() {
        let ones = (*b & 0xfe).count_ones() as u8;
        *b = (*b & 0xfe) | (1 - (ones & 1));
    }
}

impl Mdc2 {
    fn body(&mut self, block: &[u8; CHUNK]) {
        let tin0 = u32::from_le_bytes(block[0..4].try_into().unwrap());
        let tin1 = u32::from_le_bytes(block[4..8].try_into().unwrap());

        // Working copies consumed as DES inputs, like the d/dd pair of the
        // reference implementation.
        let mut d = *block;
        let mut dd = *block;

        // Distinguish the two chains by forcing one key bit each, then fix
        // up odd DES parity (the adjusted bytes persist into later blocks).
        self.h[0] = (self.h[0] & 0x9f) | 0x40;
        self.hh[0] = (self.hh[0] & 0x9f) | 0x20;
        set_odd_parity(&mut self.h);
        set_odd_parity(&mut self.hh);

        Des::new(&self.h).unwrap().encrypt_block(&mut d);
        Des::new(&self.hh).unwrap().encrypt_block(&mut dd);

        let d0 = u32::from_le_bytes(d[0..4].try_into().unwrap());
        let d1 = u32::from_le_bytes(d[4..8].try_into().unwrap());
        let dd0 = u32::from_le_bytes(dd[0..4].try_into().unwrap());
        let dd1 = u32::from_le_bytes(dd[4..8].try_into().unwrap());

        let ttin0 = tin0 ^ dd0;
        let ttin1 = tin1 ^ dd1;
        let tin0 = tin0 ^ d0;
        let tin1 = tin1 ^ d1;

        self.h[0..4].copy_from_slice(&tin0.to_le_bytes());
        self.h[4..8].copy_from_slice(&ttin1.to_le_bytes());
        self.hh[0..4].copy_from_slice(&ttin0.to_le_bytes());
        self.hh[4..8].copy_from_slice(&tin1.to_le_bytes());
    }
}

impl CoreWrite for Mdc2 {
    fn write(&mut self, p: &[u8]) -> CryptoResult<usize> {
        let nn = p.len();
        let mut p = p;

        if self.num > 0 {
            let n = core::cmp::min(p.len(), CHUNK - self.num);
            self.data[self.num..self.num + n].copy_from_slice(&p[..n]);
            self.num += n;
            p = &p[n..];
            if self.num == CHUNK {
                let block = self.data;
                self.body(&block);
                self.num = 0;
            }
        }

        let full = p.len() / CHUNK * CHUNK;
        for chunk in p[..full].as_chunks::<CHUNK>().0 {
            let mut block = [0u8; CHUNK];
            block.copy_from_slice(chunk);
            self.body(&block);
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

impl HashUser for Mdc2 {
    fn reset(&mut self) {
        self.h = [INIT_H; CHUNK];
        self.hh = [INIT_HH; CHUNK];
        self.data = [0; CHUNK];
        self.num = 0;
    }

    fn size(&self) -> usize {
        Self::SIZE
    }

    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }
}

impl Hash<16> for Mdc2 {
    fn sum(&mut self) -> [u8; 16] {
        // Make a copy of self, so that caller can keep writing and summing.
        let mut d = self.clone();

        if d.num > 0 || d.pad_type == PAD_2 {
            if d.pad_type == PAD_2 {
                d.data[d.num] = 0x80;
                d.num += 1;
            }
            d.data[d.num..].fill(0);
            let block = d.data;
            d.body(&block);
        }

        let mut out = [0u8; 16];
        out[..CHUNK].copy_from_slice(&d.h);
        out[CHUNK..].copy_from_slice(&d.hh);
        out
    }
}

/// Create a new [Hash] computing the MDC-2 checksum with the default
/// ISO/IEC 10118-2 padding ([`PAD_1`]).
pub fn new_mdc2() -> Mdc2 {
    Mdc2::new_with_pad(PAD_1).unwrap()
}

/// Compute the MDC-2 checksum of the input (default padding).
pub fn sum_mdc2(input: &[u8]) -> [u8; 16] {
    let mut h = new_mdc2();
    h.write_all(input).unwrap();
    h.sum()
}

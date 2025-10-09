//! Module md2 implements the MD2 hash algorithm as defined in RFC 1319.
//!
//! MD2 is a cryptographic hash algorithm that produces a 128-bit hash value.
//!
//! # WARNING
//!
//! MD2 is cryptographically broken and should **not be used for secure
//! applications**. This implementation is provided for compatibility and
//! legacy purposes only.

use bytes::BufMut;
use crown_derive::Marshal;

use crate::{
    core::CoreWrite,
    error::CryptoResult,
    hash::{Hash, HashUser},
};

#[cfg(test)]
mod tests;

// Magic S table from RFC1319
static S: [u8; 256] = [
    0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
    0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
    0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
    0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
    0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
    0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
    0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
    0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
    0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
    0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
    0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
    0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
    0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
    0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
    0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
    0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14,
];

#[derive(Clone, Marshal)]
pub struct Md2 {
    state: [u8; Self::BLOCK_SIZE],
    cksm: [u8; Self::BLOCK_SIZE],
    data: [u8; Self::BLOCK_SIZE],
    num: usize,
}

impl Md2 {
    pub(crate) const SIZE: usize = 16;
    pub(crate) const BLOCK_SIZE: usize = 16;

    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut md2 = Self {
            state: [0; Self::BLOCK_SIZE],
            cksm: [0; Self::BLOCK_SIZE],
            data: [0; Self::BLOCK_SIZE],
            num: 0,
        };
        md2.reset();
        md2
    }

    // Direct translation of md2_block from C code
    fn md2_block(&mut self, d: &[u8]) {
        let mut state = [0u8; 48];

        // Update checksum and prepare state array
        let mut j = self.cksm[Self::BLOCK_SIZE - 1];
        for i in 0..16 {
            let t = d[i];
            state[i] = self.state[i];
            state[i + 16] = t;
            state[i + 32] = t ^ self.state[i];
            self.cksm[i] ^= S[(t ^ j) as usize];
            j = self.cksm[i];
        }

        // Main transformation - 18 rounds
        let mut t = 0u8;
        for i in 0..18 {
            for j in (0..48).step_by(8) {
                t = state[j] ^ S[t as usize];
                state[j] = t;
                t = state[j + 1] ^ S[t as usize];
                state[j + 1] = t;
                t = state[j + 2] ^ S[t as usize];
                state[j + 2] = t;
                t = state[j + 3] ^ S[t as usize];
                state[j + 3] = t;
                t = state[j + 4] ^ S[t as usize];
                state[j + 4] = t;
                t = state[j + 5] ^ S[t as usize];
                state[j + 5] = t;
                t = state[j + 6] ^ S[t as usize];
                state[j + 6] = t;
                t = state[j + 7] ^ S[t as usize];
                state[j + 7] = t;
            }
            t = t.wrapping_add(i);
        }

        // Copy back first 16 bytes to state
        (0..16).for_each(|i| {
            self.state[i] = state[i];
        });
    }

    fn finalize(&mut self) -> [u8; Self::SIZE] {
        // Padding - fill remaining bytes with padding value
        let v = Self::BLOCK_SIZE - self.num;
        for i in self.num..Self::BLOCK_SIZE {
            self.data[i] = v as u8;
        }

        // Process padded block
        let data_copy = self.data;
        self.md2_block(&data_copy);

        // Process checksum as final block
        let cksm_copy = self.cksm;
        self.md2_block(&cksm_copy);

        // Return final hash
        self.state
    }
}

impl CoreWrite for Md2 {
    fn write(&mut self, mut p: &[u8]) -> CryptoResult<usize> {
        let nn = p.len();

        if nn == 0 {
            return Ok(0);
        }

        // Handle partial block in buffer
        if self.num != 0 {
            if self.num + p.len() >= Self::BLOCK_SIZE {
                // Fill current block and process it
                let copy_len = Self::BLOCK_SIZE - self.num;
                self.data[self.num..Self::BLOCK_SIZE].copy_from_slice(&p[..copy_len]);
                let data_copy = self.data;
                self.md2_block(&data_copy);
                p = &p[copy_len..];
                self.num = 0;
            } else {
                // Just store the data
                self.data[self.num..self.num + p.len()].copy_from_slice(p);
                self.num += p.len();
                return Ok(nn);
            }
        }

        // Process complete blocks
        while p.len() >= Self::BLOCK_SIZE {
            self.md2_block(&p[..Self::BLOCK_SIZE]);
            p = &p[Self::BLOCK_SIZE..];
        }

        // Store remaining bytes
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

impl HashUser for Md2 {
    fn reset(&mut self) {
        self.state.fill(0);
        self.cksm.fill(0);
        self.data.fill(0);
        self.num = 0;
    }

    fn size(&self) -> usize {
        Self::SIZE
    }

    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }
}

impl Hash<16> for Md2 {
    fn sum(&mut self) -> [u8; 16] {
        let mut d0 = self.clone();
        d0.finalize()
    }
}

/// Create a new [Hash] computing the MD2 checksum.
pub fn new_md2() -> Md2 {
    Md2::new()
}

/// Compute the MD2 checksum of the input.
pub fn sum_md2(data: &[u8]) -> [u8; Md2::SIZE] {
    let mut d = new_md2();
    d.write_all(data).unwrap();
    d.sum()
}

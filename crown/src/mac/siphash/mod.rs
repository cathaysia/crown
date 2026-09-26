//! SipHash-2-4 implementation (the reference keyed hash by Aumasson and
//! Bernstein), with the 64-bit and 128-bit output variants.
//!
//! SipHash is a keyed pseudo-random function optimized for short messages;
//! it is used as a MAC and as a hash-table PRF resistant to
//! hash-flooding DoS.
//!
//! Reference: <https://131002.net/siphash/> (C reference implementation,
//! public domain / CC0).

#[cfg(test)]
mod tests;

use crate::{error::CryptoResult, utils::subtle::constant_time_eq};

const BLOCK_SIZE: usize = 8;
const C_ROUNDS: u32 = 2;
const D_ROUNDS: u32 = 4;

/// SipHash-2-4 with an 8-byte output.
pub const TAG_SIZE: usize = 8;
/// SipHash-2-4 with a 16-byte (128-bit) output.
pub const TAG_SIZE_128: usize = 16;

#[inline(always)]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// SipHash-2-4 state.
pub struct SipHash {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    /// Total input length; only the low 8 bits reach the final block,
    /// which places `(len & 0xff) << 56` per the spec.
    total_inlen: usize,
    leavings: [u8; BLOCK_SIZE],
    len: usize,
    hash_size: usize,
    finalized: bool,
}

impl SipHash {
    /// Create a new SipHash-2-4 instance with an 8-byte (`8`) or 16-byte
    /// (`16`) output size.
    pub fn new(key: &[u8; 16], hash_size: usize) -> CryptoResult<Self> {
        if hash_size != TAG_SIZE && hash_size != TAG_SIZE_128 {
            return Err(crate::error::CryptoError::InvalidLength);
        }

        let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());

        let mut v1 = 0x646f72616e646f6d_u64 ^ k1;
        if hash_size == TAG_SIZE_128 {
            v1 ^= 0xee;
        }

        Ok(SipHash {
            v0: 0x736f6d6570736575_u64 ^ k0,
            v1,
            v2: 0x6c7967656e657261_u64 ^ k0,
            v3: 0x7465646279746573_u64 ^ k1,
            total_inlen: 0,
            leavings: [0u8; BLOCK_SIZE],
            len: 0,
            hash_size,
            finalized: false,
        })
    }

    /// Write adds more data to the running MAC.
    pub fn write(&mut self, mut p: &[u8]) {
        if self.finalized {
            panic!("siphash: write to MAC after Sum or Verify");
        }
        self.total_inlen = self.total_inlen.wrapping_add(p.len());

        if self.len > 0 {
            let available = BLOCK_SIZE - self.len;
            if p.len() < available {
                self.leavings[self.len..self.len + p.len()].copy_from_slice(p);
                self.len += p.len();
                return;
            }
            self.leavings[self.len..].copy_from_slice(&p[..available]);
            p = &p[available..];
            self.len = 0;

            let m = u64::from_le_bytes(self.leavings);
            self.v3 ^= m;
            for _ in 0..C_ROUNDS {
                sip_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
            }
            self.v0 ^= m;
        }

        while p.len() >= BLOCK_SIZE {
            let m = u64::from_le_bytes(p[..BLOCK_SIZE].try_into().unwrap());
            self.v3 ^= m;
            for _ in 0..C_ROUNDS {
                sip_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
            }
            self.v0 ^= m;
            p = &p[BLOCK_SIZE..];
        }

        if !p.is_empty() {
            self.leavings[..p.len()].copy_from_slice(p);
            self.len = p.len();
        }
    }

    /// Sum computes the authenticator of all data written. The MAC cannot be
    /// used afterwards. The first 8 bytes are the 64-bit tag; the full 16
    /// bytes are returned when the 128-bit output size was configured.
    pub fn sum(&mut self) -> [u8; TAG_SIZE_128] {
        if self.finalized {
            panic!("siphash: Sum called twice");
        }
        self.finalized = true;

        let mut b = ((self.total_inlen as u64) & 0xff) << 56;
        for i in 0..self.len {
            b |= (self.leavings[i] as u64) << (8 * i);
        }

        self.v3 ^= b;
        for _ in 0..C_ROUNDS {
            sip_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        }
        self.v0 ^= b;

        self.v2 ^= if self.hash_size == TAG_SIZE_128 {
            0xee
        } else {
            0xff
        };
        for _ in 0..D_ROUNDS {
            sip_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        }

        let mut out = [0u8; TAG_SIZE_128];
        out[..8].copy_from_slice(&(self.v0 ^ self.v1 ^ self.v2 ^ self.v3).to_le_bytes());
        if self.hash_size == TAG_SIZE {
            return out;
        }

        self.v1 ^= 0xdd;
        for _ in 0..D_ROUNDS {
            sip_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        }
        out[8..].copy_from_slice(&(self.v0 ^ self.v1 ^ self.v2 ^ self.v3).to_le_bytes());
        out
    }

    /// Verify returns whether the authenticator matches the expected value,
    /// in constant time. `expected` must be 8 or 16 bytes, matching the
    /// configured output size. The MAC cannot be used afterwards.
    pub fn verify(&mut self, expected: &[u8]) -> bool {
        let full = self.sum();
        let tag = &full[..self.hash_size];
        constant_time_eq(tag, expected)
    }
}

/// Compute the SipHash-2-4 tag of `msg` (8-byte output).
pub fn sum(msg: &[u8], key: &[u8; 16]) -> [u8; TAG_SIZE] {
    let mut h = SipHash::new(key, TAG_SIZE).unwrap();
    h.write(msg);
    let full = h.sum();
    full[..TAG_SIZE].try_into().unwrap()
}

/// Compute the SipHash-2-4 tag of `msg` (16-byte output).
pub fn sum128(msg: &[u8], key: &[u8; 16]) -> [u8; TAG_SIZE_128] {
    let mut h = SipHash::new(key, TAG_SIZE_128).unwrap();
    h.write(msg);
    h.sum()
}

#[cfg(test)]
mod tests;

use crate::block::BlockCipher;
use crate::error::{CryptoError, CryptoResult};
use bytes::{Buf, BufMut};

/// MULTI2 block cipher implementation
pub struct Multi2 {
    uk: [u32; 8],
    rounds: usize,
}

impl Multi2 {
    pub const BLOCK_SIZE: usize = 8;
    pub const KEY_SIZE: usize = 40;
    pub const DEFAULT_ROUNDS: usize = 128;

    /// Create a new Multi2 instance with the given 40-byte key and optional rounds
    pub fn new(key: &[u8], rounds: Option<usize>) -> CryptoResult<Self> {
        let rounds = rounds.unwrap_or(Self::DEFAULT_ROUNDS);
        if key.len() != Self::KEY_SIZE {
            return Err(CryptoError::InvalidKeySize {
                expected: "40",
                actual: key.len(),
            });
        }

        if rounds == 0 {
            return Err(CryptoError::InvalidParameterStr(
                "rounds must be greater than zero",
            ));
        }

        let mut sk = [0u32; 8];
        let mut dk = [0u32; 2];
        let mut key_ptr = key;

        for i in 0..8 {
            sk[i] = key_ptr.get_u32();
        }
        for i in 0..2 {
            dk[i] = key_ptr.get_u32();
        }

        let mut uk = [0u32; 8];
        Self::setup(&mut dk, &sk, &mut uk);

        // Security: clear sensitive data
        sk.fill(0);
        dk.fill(0);

        Ok(Self { uk, rounds })
    }

    fn setup(dk: &mut [u32; 2], sk: &[u32; 8], uk: &mut [u32; 8]) {
        Self::pi1(dk);
        Self::pi2(dk, &sk[0..4]);
        uk[0] = dk[0];
        Self::pi3(dk, &sk[0..4]);
        uk[1] = dk[1];
        Self::pi4(dk, &sk[0..4]);
        uk[2] = dk[0];
        Self::pi1(dk);
        uk[3] = dk[1];
        Self::pi2(dk, &sk[4..8]);
        uk[4] = dk[0];
        Self::pi3(dk, &sk[4..8]);
        uk[5] = dk[1];
        Self::pi4(dk, &sk[4..8]);
        uk[6] = dk[0];
        Self::pi1(dk);
        uk[7] = dk[1];
    }

    #[inline(always)]
    fn pi1(p: &mut [u32; 2]) {
        p[1] ^= p[0];
    }

    #[inline(always)]
    fn pi2(p: &mut [u32; 2], k: &[u32]) {
        let mut t = p[1].wrapping_add(k[0]);
        t = t.rotate_left(1).wrapping_add(t).wrapping_sub(1);
        t = t.rotate_left(4) ^ t;
        p[0] ^= t;
    }

    #[inline(always)]
    fn pi3(p: &mut [u32; 2], k: &[u32]) {
        let mut t = p[0].wrapping_add(k[1]);
        t = t.rotate_left(2).wrapping_add(t).wrapping_add(1);
        t = t.rotate_left(8) ^ t;
        t = t.wrapping_add(k[2]);
        t = t.rotate_left(1).wrapping_sub(t);
        t = t.rotate_left(16) ^ (p[0] | t);
        p[1] ^= t;
    }

    #[inline(always)]
    fn pi4(p: &mut [u32; 2], k: &[u32]) {
        let mut t = p[1].wrapping_add(k[3]);
        t = t.rotate_left(2).wrapping_add(t).wrapping_add(1);
        p[0] ^= t;
    }
}

impl BlockCipher for Multi2 {
    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    fn encrypt_block(&self, inout: &mut [u8]) {
        let mut p = [0u32; 2];
        let mut in_ptr = &*inout;
        p[0] = in_ptr.get_u32();
        p[1] = in_ptr.get_u32();

        let mut n = 0;
        let mut t = 0;
        loop {
            Self::pi1(&mut p);
            n += 1;
            if n == self.rounds {
                break;
            }

            Self::pi2(&mut p, &self.uk[t..t + 4]);
            n += 1;
            if n == self.rounds {
                break;
            }

            Self::pi3(&mut p, &self.uk[t..t + 4]);
            n += 1;
            if n == self.rounds {
                break;
            }

            Self::pi4(&mut p, &self.uk[t..t + 4]);
            n += 1;
            if n == self.rounds {
                break;
            }

            t ^= 4;
        }

        let mut out_ptr = inout;
        out_ptr.put_u32(p[0]);
        out_ptr.put_u32(p[1]);
    }

    fn decrypt_block(&self, inout: &mut [u8]) {
        let mut p = [0u32; 2];
        let mut in_ptr = &*inout;
        p[0] = in_ptr.get_u32();
        p[1] = in_ptr.get_u32();

        let mut n = self.rounds;
        let mut t = 4 * (((n - 1) >> 2) & 1);

        while n > 0 {
            let m = if n <= 4 { n } else { ((n - 1) % 4) + 1 };

            if m >= 4 {
                Self::pi4(&mut p, &self.uk[t..t + 4]);
                n -= 1;
            }
            if m >= 3 {
                Self::pi3(&mut p, &self.uk[t..t + 4]);
                n -= 1;
            }
            if m >= 2 {
                Self::pi2(&mut p, &self.uk[t..t + 4]);
                n -= 1;
            }
            if m >= 1 {
                Self::pi1(&mut p);
                n -= 1;
            }

            t ^= 4;
        }

        let mut out_ptr = inout;
        out_ptr.put_u32(p[0]);
        out_ptr.put_u32(p[1]);
    }
}

impl super::BlockCipherMarker for Multi2 {}
use crate::aead::ocb3::Ocb3Marker;
impl Ocb3Marker for Multi2 {}

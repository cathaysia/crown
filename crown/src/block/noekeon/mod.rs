#[cfg(test)]
mod tests;

use crate::aead::ocb3::Ocb3Marker;
use crate::block::BlockCipher;
use crate::error::{CryptoError, CryptoResult};
use bytes::{Buf, BufMut};

/// Noekeon round constants
const RC: [u32; 17] = [
    0x00000080, 0x0000001b, 0x00000036, 0x0000006c, 0x000000d8, 0x000000ab, 0x0000004d, 0x0000009a,
    0x0000002f, 0x0000005e, 0x000000bc, 0x00000063, 0x000000c6, 0x00000097, 0x00000035, 0x0000006a,
    0x000000d4,
];

/// Noekeon block cipher implementation
pub struct Noekeon {
    k: [u32; 4],
    dk: [u32; 4],
}

impl Noekeon {
    pub const BLOCK_SIZE: usize = 16;
    pub const KEY_SIZE: usize = 16;

    /// Create a new Noekeon instance with the given key
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(CryptoError::InvalidKeySize {
                expected: "16",
                actual: key.len(),
            });
        }

        let mut k = [0u32; 4];
        let mut key_ptr = key;
        for i in 0..4 {
            k[i] = key_ptr.get_u32();
        }

        let mut dk = k;
        Self::k_theta(&mut dk);

        Ok(Self { k, dk })
    }

    #[inline(always)]
    fn theta(state: &mut [u32; 4], k: &[u32; 4]) {
        let mut temp = state[0] ^ state[2];
        temp ^= temp.rotate_left(8) ^ temp.rotate_right(8);
        state[1] ^= temp;
        state[3] ^= temp;

        state[0] ^= k[0];
        state[1] ^= k[1];
        state[2] ^= k[2];
        state[3] ^= k[3];

        temp = state[1] ^ state[3];
        temp ^= temp.rotate_left(8) ^ temp.rotate_right(8);
        state[0] ^= temp;
        state[2] ^= temp;
    }

    #[inline(always)]
    fn k_theta(state: &mut [u32; 4]) {
        let mut temp = state[0] ^ state[2];
        temp ^= temp.rotate_left(8) ^ temp.rotate_right(8);
        state[1] ^= temp;
        state[3] ^= temp;

        temp = state[1] ^ state[3];
        temp ^= temp.rotate_left(8) ^ temp.rotate_right(8);
        state[0] ^= temp;
        state[2] ^= temp;
    }

    #[inline(always)]
    fn gamma(state: &mut [u32; 4]) {
        state[1] ^= !(state[3] | state[2]);
        state[0] ^= state[2] & state[1];

        let temp = state[3];
        state[3] = state[0];
        state[0] = temp;

        state[2] ^= state[0] ^ state[1] ^ state[3];
        state[1] ^= !(state[3] | state[2]);
        state[0] ^= state[2] & state[1];
    }

    #[inline(always)]
    fn pi1(state: &mut [u32; 4]) {
        state[1] = state[1].rotate_left(1);
        state[2] = state[2].rotate_left(5);
        state[3] = state[3].rotate_left(2);
    }

    #[inline(always)]
    fn pi2(state: &mut [u32; 4]) {
        state[1] = state[1].rotate_right(1);
        state[2] = state[2].rotate_right(5);
        state[3] = state[3].rotate_right(2);
    }
}

impl BlockCipher for Noekeon {
    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    fn encrypt_block(&self, inout: &mut [u8]) {
        let mut state = [0u32; 4];
        let mut in_ptr = &*inout;
        for i in 0..4 {
            state[i] = in_ptr.get_u32();
        }

        for i in 0..16 {
            state[0] ^= RC[i];
            Self::theta(&mut state, &self.k);
            Self::pi1(&mut state);
            Self::gamma(&mut state);
            Self::pi2(&mut state);
        }
        state[0] ^= RC[16];
        Self::theta(&mut state, &self.k);

        let mut out_ptr = inout;
        for i in 0..4 {
            out_ptr.put_u32(state[i]);
        }
    }

    fn decrypt_block(&self, inout: &mut [u8]) {
        let mut state = [0u32; 4];
        let mut in_ptr = &*inout;
        for i in 0..4 {
            state[i] = in_ptr.get_u32();
        }

        for i in (1..=16).rev() {
            Self::theta(&mut state, &self.dk);
            state[0] ^= RC[i];
            Self::pi1(&mut state);
            Self::gamma(&mut state);
            Self::pi2(&mut state);
        }
        Self::theta(&mut state, &self.dk);
        state[0] ^= RC[0];

        let mut out_ptr = inout;
        for i in 0..4 {
            out_ptr.put_u32(state[i]);
        }
    }
}

impl super::BlockCipherMarker for Noekeon {}
impl Ocb3Marker for Noekeon {}

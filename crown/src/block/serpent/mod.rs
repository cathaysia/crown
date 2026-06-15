#[cfg(test)]
mod tests;

use crate::{
    aead::ocb3::Ocb3Marker,
    block::{BlockCipher, BlockCipherMarker},
    error::{CryptoError, CryptoResult},
};

const PHI: u32 = 0x9e3779b9;
const ROUNDS: usize = 32;

#[derive(Clone)]
pub struct Serpent {
    round_keys: [[u32; 4]; ROUNDS + 1],
}

impl BlockCipherMarker for Serpent {}
impl Ocb3Marker for Serpent {}

impl Serpent {
    pub const BLOCK_SIZE: usize = 16;

    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        let len = key.len();
        if len != 16 && len != 24 && len != 32 {
            return Err(CryptoError::InvalidKeySize {
                expected: "16 | 24 | 32",
                actual: len,
            });
        }

        let mut words = [0u32; 140];
        // 1. Initial key expansion to 256 bits if needed
        let mut k = [0u8; 32];
        k[..len].copy_from_slice(key);
        if len < 32 {
            // Padding with 1 bit followed by zeros
            k[len] |= 1 << 0;
        }

        // Convert key to 8 words w[-8] to w[-1]
        for i in 0..8 {
            words[i] = u32::from_le_bytes(k[i * 4..(i + 1) * 4].try_into().unwrap());
        }

        // 2. Expand to 132 more words w[0] to w[131]
        for i in 0..132 {
            let slot = i + 8;
            words[slot] = (words[slot - 8]
                ^ words[slot - 5]
                ^ words[slot - 3]
                ^ words[slot - 1]
                ^ PHI
                ^ i as u32)
                .rotate_left(11);
        }

        // 3. Generate 33 round keys K0 to K32
        let mut round_keys = [[0u32; 4]; ROUNDS + 1];
        let w_gen = &words[8..];
        for i in 0..=ROUNDS {
            let sbox_index = (32 + 3 - i) % 8;
            let a = w_gen[4 * i];
            let b = w_gen[4 * i + 1];
            let c = w_gen[4 * i + 2];
            let d = w_gen[4 * i + 3];
            round_keys[i] = apply_s(sbox_index, [a, b, c, d]);
        }

        Ok(Serpent { round_keys })
    }
}

impl BlockCipher for Serpent {
    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    fn encrypt_block(&self, inout: &mut [u8]) {
        if inout.len() < Self::BLOCK_SIZE {
            panic!("crypto/serpent: inout not full block");
        }

        let mut words = [
            u32::from_le_bytes(inout[0..4].try_into().unwrap()),
            u32::from_le_bytes(inout[4..8].try_into().unwrap()),
            u32::from_le_bytes(inout[8..12].try_into().unwrap()),
            u32::from_le_bytes(inout[12..16].try_into().unwrap()),
        ];

        for i in 0..ROUNDS {
            // Key mixing
            words[0] ^= self.round_keys[i][0];
            words[1] ^= self.round_keys[i][1];
            words[2] ^= self.round_keys[i][2];
            words[3] ^= self.round_keys[i][3];

            // S-box application
            words = apply_s(i, words);

            // Linear transformation (except last round)
            if i < ROUNDS - 1 {
                words = linear_transform(words);
            } else {
                // Last round key mixing
                words[0] ^= self.round_keys[ROUNDS][0];
                words[1] ^= self.round_keys[ROUNDS][1];
                words[2] ^= self.round_keys[ROUNDS][2];
                words[3] ^= self.round_keys[ROUNDS][3];
            }
        }

        inout[0..4].copy_from_slice(&words[0].to_le_bytes());
        inout[4..8].copy_from_slice(&words[1].to_le_bytes());
        inout[8..12].copy_from_slice(&words[2].to_le_bytes());
        inout[12..16].copy_from_slice(&words[3].to_le_bytes());
    }

    fn decrypt_block(&self, inout: &mut [u8]) {
        if inout.len() < Self::BLOCK_SIZE {
            panic!("crypto/serpent: inout not full block");
        }

        let mut words = [
            u32::from_le_bytes(inout[0..4].try_into().unwrap()),
            u32::from_le_bytes(inout[4..8].try_into().unwrap()),
            u32::from_le_bytes(inout[8..12].try_into().unwrap()),
            u32::from_le_bytes(inout[12..16].try_into().unwrap()),
        ];

        // Inverse of the last step
        words[0] ^= self.round_keys[ROUNDS][0];
        words[1] ^= self.round_keys[ROUNDS][1];
        words[2] ^= self.round_keys[ROUNDS][2];
        words[3] ^= self.round_keys[ROUNDS][3];

        for i in (0..ROUNDS).rev() {
            // Inverse S-box application
            words = apply_s_inv(i, words);

            // Key mixing
            words[0] ^= self.round_keys[i][0];
            words[1] ^= self.round_keys[i][1];
            words[2] ^= self.round_keys[i][2];
            words[3] ^= self.round_keys[i][3];

            // Inverse Linear transformation
            if i > 0 {
                words = linear_transform_inv(words);
            }
        }

        inout[0..4].copy_from_slice(&words[0].to_le_bytes());
        inout[4..8].copy_from_slice(&words[1].to_le_bytes());
        inout[8..12].copy_from_slice(&words[2].to_le_bytes());
        inout[12..16].copy_from_slice(&words[3].to_le_bytes());
    }
}

#[inline]
fn apply_s(index: usize, words: [u32; 4]) -> [u32; 4] {
    match index % 8 {
        0 => sbox_e0(words),
        1 => sbox_e1(words),
        2 => sbox_e2(words),
        3 => sbox_e3(words),
        4 => sbox_e4(words),
        5 => sbox_e5(words),
        6 => sbox_e6(words),
        7 => sbox_e7(words),
        _ => unreachable!(),
    }
}

#[inline]
fn apply_s_inv(index: usize, words: [u32; 4]) -> [u32; 4] {
    match index % 8 {
        0 => sbox_d0(words),
        1 => sbox_d1(words),
        2 => sbox_d2(words),
        3 => sbox_d3(words),
        4 => sbox_d4(words),
        5 => sbox_d5(words),
        6 => sbox_d6(words),
        7 => sbox_d7(words),
        _ => unreachable!(),
    }
}

#[inline]
fn linear_transform(mut words: [u32; 4]) -> [u32; 4] {
    words[0] = words[0].rotate_left(13);
    words[2] = words[2].rotate_left(3);
    words[1] ^= words[0] ^ words[2];
    words[3] = words[3] ^ words[2] ^ (words[0] << 3);
    words[1] = words[1].rotate_left(1);
    words[3] = words[3].rotate_left(7);
    words[0] ^= words[1] ^ words[3];
    words[2] = words[2] ^ words[3] ^ (words[1] << 7);
    words[0] = words[0].rotate_left(5);
    words[2] = words[2].rotate_left(22);
    words
}

#[inline]
fn linear_transform_inv(mut words: [u32; 4]) -> [u32; 4] {
    words[2] = words[2].rotate_right(22);
    words[0] = words[0].rotate_right(5);
    words[2] = words[2] ^ words[3] ^ (words[1] << 7);
    words[0] ^= words[1] ^ words[3];
    words[3] = words[3].rotate_right(7);
    words[1] = words[1].rotate_right(1);
    words[3] = words[3] ^ words[2] ^ (words[0] << 3);
    words[1] ^= words[0] ^ words[2];
    words[2] = words[2].rotate_right(3);
    words[0] = words[0].rotate_right(13);
    words
}

// Bitsliced S-boxes from RustCrypto
#[inline]
const fn sbox_e0([mut w1, mut w2, mut w3, mut w4]: [u32; 4]) -> [u32; 4] {
    w4 ^= w1;
    let mut t0 = w2;
    w2 &= w4;
    t0 ^= w3;
    w2 ^= w1;
    w1 |= w4;
    w1 ^= t0;
    t0 ^= w4;
    w4 ^= w3;
    w3 |= w2;
    w3 ^= t0;
    t0 = !t0;
    t0 |= w2;
    w2 ^= w4;
    w2 ^= t0;
    w4 |= w1;
    w2 ^= w4;
    t0 ^= w4;
    [w2, t0, w3, w1]
}

#[inline]
const fn sbox_e1([mut w1, mut w2, mut w3, mut w4]: [u32; 4]) -> [u32; 4] {
    w1 = !w1;
    w3 = !w3;
    let mut t0 = w1;
    w1 &= w2;
    w3 ^= w1;
    w1 |= w4;
    w4 ^= w3;
    w2 ^= w1;
    w1 ^= t0;
    t0 |= w2;
    w2 ^= w4;
    w3 |= w1;
    w3 &= t0;
    w1 ^= w2;
    w2 &= w3;
    w2 ^= w1;
    w1 &= w3;
    t0 ^= w1;
    [w3, t0, w4, w2]
}

#[inline]
const fn sbox_e2([mut w1, mut w2, mut w3, mut w4]: [u32; 4]) -> [u32; 4] {
    let mut t0 = w1;
    w1 &= w3;
    w1 ^= w4;
    w3 ^= w2;
    w3 ^= w1;
    w4 |= t0;
    w4 ^= w2;
    t0 ^= w3;
    w2 = w4;
    w4 |= t0;
    w4 ^= w1;
    w1 &= w2;
    t0 ^= w1;
    w2 ^= w4;
    w2 ^= t0;
    t0 = !t0;
    [w3, w4, w2, t0]
}

#[inline]
const fn sbox_e3([mut w1, mut w2, mut w3, mut w4]: [u32; 4]) -> [u32; 4] {
    let mut t0 = w1;
    w1 |= w4;
    w4 ^= w2;
    w2 &= t0;
    t0 ^= w3;
    w3 ^= w4;
    w4 &= w1;
    t0 |= w2;
    w4 ^= t0;
    w1 ^= w2;
    t0 &= w1;
    w2 ^= w4;
    t0 ^= w3;
    w2 |= w1;
    w2 ^= w3;
    w1 ^= w4;
    w3 = w2;
    w2 |= w4;
    w1 ^= w2;
    [w1, w3, w4, t0]
}

#[inline]
const fn sbox_e4([mut w1, mut w2, mut w3, mut w4]: [u32; 4]) -> [u32; 4] {
    w2 ^= w4;
    w4 = !w4;
    w3 ^= w4;
    w4 ^= w1;
    let mut t0 = w2;
    w2 &= w4;
    w2 ^= w3;
    t0 ^= w4;
    w1 ^= t0;
    w3 &= t0;
    w3 ^= w1;
    w1 &= w2;
    w4 ^= w1;
    t0 |= w2;
    t0 ^= w1;
    w1 |= w4;
    w1 ^= w3;
    w3 &= w4;
    w1 = !w1;
    t0 ^= w3;
    [w2, t0, w1, w4]
}

#[inline]
const fn sbox_e5([mut w1, mut w2, mut w3, mut w4]: [u32; 4]) -> [u32; 4] {
    w1 ^= w2;
    w2 ^= w4;
    w4 = !w4;
    let mut t0 = w2;
    w2 &= w1;
    w3 ^= w4;
    w2 ^= w3;
    w3 |= t0;
    t0 ^= w4;
    w4 &= w2;
    w4 ^= w1;
    t0 ^= w2;
    t0 ^= w3;
    w3 ^= w1;
    w1 &= w4;
    w3 = !w3;
    w1 ^= t0;
    t0 |= w4;
    t0 ^= w3;
    [w2, w4, w1, t0]
}

#[inline]
const fn sbox_e6([mut w1, mut w2, mut w3, mut w4]: [u32; 4]) -> [u32; 4] {
    w3 = !w3;
    let mut t0 = w4;
    w4 &= w1;
    w1 ^= t0;
    w4 ^= w3;
    w3 |= t0;
    w2 ^= w4;
    w3 ^= w1;
    w1 |= w2;
    w3 ^= w2;
    t0 ^= w1;
    w1 |= w4;
    w1 ^= w3;
    t0 ^= w4;
    t0 ^= w1;
    w4 = !w4;
    w3 &= t0;
    w4 ^= w3;
    [w1, w2, t0, w4]
}

#[inline]
const fn sbox_e7([mut w1, mut w2, mut w3, mut w4]: [u32; 4]) -> [u32; 4] {
    let mut t0 = w2;
    w2 |= w3;
    w2 ^= w4;
    t0 ^= w3;
    w3 ^= w2;
    w4 |= t0;
    w4 &= w1;
    t0 ^= w3;
    w4 ^= w2;
    w2 |= t0;
    w2 ^= w1;
    w1 |= t0;
    w1 ^= w3;
    w2 ^= t0;
    w3 ^= w2;
    w2 &= w1;
    w2 ^= t0;
    w3 = !w3;
    w3 |= w1;
    t0 ^= w3;
    [t0, w4, w2, w1]
}

#[inline]
const fn sbox_d0([mut w1, mut w2, mut w3, mut w4]: [u32; 4]) -> [u32; 4] {
    w3 = !w3;
    let mut t0 = w2;
    w2 |= w1;
    t0 = !t0;
    w2 ^= w3;
    w3 |= t0;
    w2 ^= w4;
    w1 ^= t0;
    w3 ^= w1;
    w1 &= w4;
    t0 ^= w1;
    w1 |= w2;
    w1 ^= w3;
    w4 ^= t0;
    w3 ^= w2;
    w4 ^= w1;
    w4 ^= w2;
    w3 &= w4;
    t0 ^= w3;
    [w1, t0, w2, w4]
}

#[inline]
const fn sbox_d1([mut w1, mut w2, mut w3, mut w4]: [u32; 4]) -> [u32; 4] {
    let mut t0 = w2;
    w2 ^= w4;
    w4 &= w2;
    t0 ^= w3;
    w4 ^= w1;
    w1 |= w2;
    w3 ^= w4;
    w1 ^= t0;
    w1 |= w3;
    w2 ^= w4;
    w1 ^= w2;
    w2 |= w4;
    w2 ^= w1;
    t0 = !t0;
    t0 ^= w2;
    w2 |= w1;
    w2 ^= w1;
    w2 |= t0;
    w4 ^= w2;
    [t0, w1, w4, w3]
}

#[inline]
const fn sbox_d2([mut w1, mut w2, mut w3, mut w4]: [u32; 4]) -> [u32; 4] {
    w3 ^= w4;
    w4 ^= w1;
    let mut t0 = w4;
    w4 &= w3;
    w4 ^= w2;
    w2 |= w3;
    w2 ^= t0;
    t0 &= w4;
    w3 ^= w4;
    t0 &= w1;
    t0 ^= w3;
    w3 &= w2;
    w3 |= w1;
    w4 = !w4;
    w3 ^= w4;
    w1 ^= w4;
    w1 &= w2;
    w4 ^= t0;
    w4 ^= w1;
    [w2, t0, w3, w4]
}

#[inline]
const fn sbox_d3([mut w1, mut w2, mut w3, mut w4]: [u32; 4]) -> [u32; 4] {
    let mut t0 = w3;
    w3 ^= w2;
    w1 ^= w3;
    t0 &= w3;
    t0 ^= w1;
    w1 &= w2;
    w2 ^= w4;
    w4 |= t0;
    w3 ^= w4;
    w1 ^= w4;
    w2 ^= t0;
    w4 &= w3;
    w4 ^= w2;
    w2 ^= w1;
    w2 |= w3;
    w1 ^= w4;
    w2 ^= t0;
    w1 ^= w2;
    [w3, w2, w4, w1]
}

#[inline]
const fn sbox_d4([mut w1, mut w2, mut w3, mut w4]: [u32; 4]) -> [u32; 4] {
    let mut t0 = w3;
    w3 &= w4;
    w3 ^= w2;
    w2 |= w4;
    w2 &= w1;
    t0 ^= w3;
    t0 ^= w2;
    w2 &= w3;
    w1 = !w1;
    w4 ^= t0;
    w2 ^= w4;
    w4 &= w1;
    w4 ^= w3;
    w1 ^= w2;
    w3 &= w1;
    w4 ^= w1;
    w3 ^= t0;
    w3 |= w4;
    w4 ^= w1;
    w3 ^= w2;
    [w1, w4, w3, t0]
}

#[inline]
const fn sbox_d5([w1, mut w2, mut w3, mut w4]: [u32; 4]) -> [u32; 4] {
    w2 = !w2;
    let mut t0 = w4;
    w3 ^= w2;
    w4 |= w1;
    w4 ^= w3;
    w3 |= w2;
    w3 &= w1;
    t0 ^= w4;
    w3 ^= t0;
    t0 |= w1;
    t0 ^= w2;
    w2 &= w3;
    w2 ^= w4;
    t0 ^= w3;
    w4 &= t0;
    t0 ^= w2;
    w4 ^= t0;
    t0 = !t0;
    w4 ^= w1;
    [w2, t0, w4, w3]
}

#[inline]
const fn sbox_d6([mut w1, mut w2, mut w3, mut w4]: [u32; 4]) -> [u32; 4] {
    w1 ^= w3;
    let mut t0 = w3;
    w3 &= w1;
    t0 ^= w4;
    w3 = !w3;
    w4 ^= w2;
    w3 ^= w4;
    t0 |= w1;
    w1 ^= w3;
    w4 ^= t0;
    t0 ^= w2;
    w2 &= w4;
    w2 ^= w1;
    w1 ^= w4;
    w1 |= w3;
    w4 ^= w2;
    t0 ^= w1;
    [w2, w3, t0, w4]
}

#[inline]
const fn sbox_d7([mut w1, mut w2, mut w3, mut w4]: [u32; 4]) -> [u32; 4] {
    let mut t0 = w3;
    w3 ^= w1;
    w1 &= w4;
    t0 |= w4;
    w3 = !w3;
    w4 ^= w2;
    w2 |= w1;
    w1 ^= w3;
    w3 &= t0;
    w4 &= t0;
    w2 ^= w3;
    w3 ^= w1;
    w1 |= w3;
    t0 ^= w2;
    w1 ^= w4;
    w4 ^= t0;
    t0 |= w1;
    w4 ^= w3;
    t0 ^= w3;
    [w4, w1, w2, t0]
}

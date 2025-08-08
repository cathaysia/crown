//!    Implementation adapted from Needham and Wheeler's paper:
//!    http://www.cix.co.uk/~klockstone/xtea.pdf
//!
//!    A precalculated look up table is used during encryption/decryption for values that are based purely on the key.

use super::Cipher;

// XTEA is based on 64 rounds.
pub(crate) const NUM_ROUNDS: usize = 64;

/// Reads an 8 byte slice into two u32s.
/// The block is treated as big endian.
fn block_to_u32(src: &[u8]) -> (u32, u32) {
    let r0 = ((src[0] as u32) << 24) | ((src[1] as u32) << 16) | ((src[2] as u32) << 8) | (src[3] as u32);
    let r1 = ((src[4] as u32) << 24) | ((src[5] as u32) << 16) | ((src[6] as u32) << 8) | (src[7] as u32);
    (r0, r1)
}

/// Writes two u32s into an 8 byte data block.
/// Values are written as big endian.
fn u32_to_block(v0: u32, v1: u32, dst: &mut [u8]) {
    dst[0] = (v0 >> 24) as u8;
    dst[1] = (v0 >> 16) as u8;
    dst[2] = (v0 >> 8) as u8;
    dst[3] = v0 as u8;
    dst[4] = (v1 >> 24) as u8;
    dst[5] = (v1 >> 16) as u8;
    dst[6] = (v1 >> 8) as u8;
    dst[7] = v1 as u8;
}

/// Encrypts a single 8 byte block using XTEA.
pub fn encrypt_block(c: &Cipher, dst: &mut [u8], src: &[u8]) {
    let (mut v0, mut v1) = block_to_u32(src);

    // Two rounds of XTEA applied per loop
    let mut i = 0;
    while i < NUM_ROUNDS {
        v0 = v0.wrapping_add((((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1)) ^ c.table[i]);
        i += 1;
        v1 = v1.wrapping_add((((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0)) ^ c.table[i]);
        i += 1;
    }

    u32_to_block(v0, v1, dst);
}

/// Decrypts a single 8 byte block using XTEA.
pub fn decrypt_block(c: &Cipher, dst: &mut [u8], src: &[u8]) {
    let (mut v0, mut v1) = block_to_u32(src);

    // Two rounds of XTEA applied per loop
    let mut i = NUM_ROUNDS;
    while i > 0 {
        i -= 1;
        v1 = v1.wrapping_sub((((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0)) ^ c.table[i]);
        i -= 1;
        v0 = v0.wrapping_sub((((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1)) ^ c.table[i]);
    }

    u32_to_block(v0, v1, dst);
}

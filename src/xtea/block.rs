//!    Implementation adapted from Needham and Wheeler's paper:
//!    <http://www.cix.co.uk/~klockstone/xtea.pdf>
//!
//!    A precalculated look up table is used during encryption/decryption for values that are based purely on the key.

use bytes::{Buf, BufMut};

use super::Xtea;

/// Encrypts a single 8 byte block using XTEA.
pub fn encrypt_block(c: &Xtea, mut inout: &mut [u8]) {
    let (mut v0, mut v1) = {
        let mut inout = &*inout;
        (inout.get_u32(), inout.get_u32())
    };

    // Two rounds of XTEA applied per loop
    let mut i = 0;
    while i < Xtea::NUM_ROUNDS {
        v0 = v0.wrapping_add((((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1)) ^ c.table[i]);
        i += 1;
        v1 = v1.wrapping_add((((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0)) ^ c.table[i]);
        i += 1;
    }

    inout.put_u32(v0);
    inout.put_u32(v1);
}

/// Decrypts a single 8 byte block using XTEA.
pub fn decrypt_block(c: &Xtea, mut inout: &mut [u8]) {
    let (mut v0, mut v1) = {
        let mut inout = &*inout;
        (inout.get_u32(), inout.get_u32())
    };

    // Two rounds of XTEA applied per loop
    let mut i = Xtea::NUM_ROUNDS;
    while i > 0 {
        i -= 1;
        v1 = v1.wrapping_sub((((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0)) ^ c.table[i]);
        i -= 1;
        v0 = v0.wrapping_sub((((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1)) ^ c.table[i]);
    }

    inout.put_u32(v0);
    inout.put_u32(v1);
}

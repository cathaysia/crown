#![allow(dead_code)]

use super::BlockExpanded;
use crate::simd::u32x4::u32x4;

pub fn encrypt_block_generic(c: &BlockExpanded, inout: &mut [u8]) {
    assert!(inout.len() >= 16);
    let xk = &c.enc;

    let mut keys: [u32x4; 15] = unsafe { core::mem::zeroed() };
    (0..15).for_each(|i| {
        let v = u32x4::from_slice(&xk[i * 4..]);
        keys[i] = v.swap_bytes();
    });

    let mut round = u32x4::from_bytes(inout);
    round = round ^ keys[0];

    (1..=c.rounds).for_each(|i| unsafe {
        if i == c.rounds {
            round = round.aes_enc_last(keys[i]);
        } else {
            round = round.aes_enc(keys[i]);
        }
    });

    let v = round.as_bytes();

    inout.copy_from_slice(v.as_slice());
}

pub fn decrypt_block_generic(c: &BlockExpanded, inout: &mut [u8]) {
    assert!(inout.len() >= 16);
    let xk = &c.dec;

    let mut keys: [u32x4; 15] = unsafe { core::mem::zeroed() };
    (0..15).for_each(|i| {
        let v = u32x4::from_slice(&xk[i * 4..]);
        keys[i] = v.swap_bytes();
    });

    let mut round = u32x4::from_bytes(inout);
    round = round ^ keys[0];

    (1..=c.rounds).for_each(|i| unsafe {
        if i == c.rounds {
            round = round.aes_dec_last(keys[i]);
        } else {
            round = round.aes_dec(keys[i]);
        }
    });

    let v = round.as_bytes();

    inout.copy_from_slice(v.as_slice());
}

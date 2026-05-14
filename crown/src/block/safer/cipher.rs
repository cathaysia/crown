use super::consts::{SAFER_EBOX, SAFER_LBOX};
use crate::{
    aead::ocb3::Ocb3Marker,
    block::{BlockCipher, BlockCipherMarker},
    error::{CryptoError, CryptoResult},
};
use alloc::vec::Vec;

#[derive(Clone)]
pub struct Safer {
    pub(crate) rounds: u8,
    pub(crate) expanded_key: Vec<u8>,
}

impl BlockCipherMarker for Safer {}
impl Ocb3Marker for Safer {}

impl BlockCipher for Safer {
    fn block_size(&self) -> usize {
        8
    }

    fn encrypt_block(&self, inout: &mut [u8]) {
        if inout.len() < 8 {
            panic!("crypto/safer: inout not full block");
        }

        let mut a = inout[0];
        let mut b = inout[1];
        let mut c = inout[2];
        let mut d = inout[3];
        let mut e = inout[4];
        let mut f = inout[5];
        let mut g = inout[6];
        let mut h = inout[7];

        let mut key_idx = 1;
        let mut r = self.rounds;

        while r > 0 {
            a ^= self.expanded_key[key_idx];
            key_idx += 1;
            b = b.wrapping_add(self.expanded_key[key_idx]);
            key_idx += 1;
            c = c.wrapping_add(self.expanded_key[key_idx]);
            key_idx += 1;
            d ^= self.expanded_key[key_idx];
            key_idx += 1;
            e ^= self.expanded_key[key_idx];
            key_idx += 1;
            f = f.wrapping_add(self.expanded_key[key_idx]);
            key_idx += 1;
            g = g.wrapping_add(self.expanded_key[key_idx]);
            key_idx += 1;
            h ^= self.expanded_key[key_idx];
            key_idx += 1;

            a = SAFER_EBOX[a as usize].wrapping_add(self.expanded_key[key_idx]);
            key_idx += 1;
            b = SAFER_LBOX[b as usize] ^ self.expanded_key[key_idx];
            key_idx += 1;
            c = SAFER_LBOX[c as usize] ^ self.expanded_key[key_idx];
            key_idx += 1;
            d = SAFER_EBOX[d as usize].wrapping_add(self.expanded_key[key_idx]);
            key_idx += 1;
            e = SAFER_EBOX[e as usize].wrapping_add(self.expanded_key[key_idx]);
            key_idx += 1;
            f = SAFER_LBOX[f as usize] ^ self.expanded_key[key_idx];
            key_idx += 1;
            g = SAFER_LBOX[g as usize] ^ self.expanded_key[key_idx];
            key_idx += 1;
            h = SAFER_EBOX[h as usize].wrapping_add(self.expanded_key[key_idx]);
            key_idx += 1;

            // PHT
            b = b.wrapping_add(a);
            a = a.wrapping_add(b);
            d = d.wrapping_add(c);
            c = c.wrapping_add(d);
            f = f.wrapping_add(e);
            e = e.wrapping_add(f);
            h = h.wrapping_add(g);
            g = g.wrapping_add(h);

            c = c.wrapping_add(a);
            a = a.wrapping_add(c);
            g = g.wrapping_add(e);
            e = e.wrapping_add(g);
            d = d.wrapping_add(b);
            b = b.wrapping_add(d);
            h = h.wrapping_add(f);
            f = f.wrapping_add(h);

            e = e.wrapping_add(a);
            a = a.wrapping_add(e);
            f = f.wrapping_add(b);
            b = b.wrapping_add(f);
            g = g.wrapping_add(c);
            c = c.wrapping_add(g);
            h = h.wrapping_add(d);
            d = d.wrapping_add(h);

            // Permutation
            let t = b;
            b = e;
            e = c;
            c = t;
            let t = d;
            d = f;
            f = g;
            g = t;

            r -= 1;
        }

        a ^= self.expanded_key[key_idx];
        key_idx += 1;
        b = b.wrapping_add(self.expanded_key[key_idx]);
        key_idx += 1;
        c = c.wrapping_add(self.expanded_key[key_idx]);
        key_idx += 1;
        d ^= self.expanded_key[key_idx];
        key_idx += 1;
        e ^= self.expanded_key[key_idx];
        key_idx += 1;
        f = f.wrapping_add(self.expanded_key[key_idx]);
        key_idx += 1;
        g = g.wrapping_add(self.expanded_key[key_idx]);
        key_idx += 1;
        h ^= self.expanded_key[key_idx];

        inout[0] = a;
        inout[1] = b;
        inout[2] = c;
        inout[3] = d;
        inout[4] = e;
        inout[5] = f;
        inout[6] = g;
        inout[7] = h;
    }

    fn decrypt_block(&self, inout: &mut [u8]) {
        if inout.len() < 8 {
            panic!("crypto/safer: inout not full block");
        }

        let mut a = inout[0];
        let mut b = inout[1];
        let mut c = inout[2];
        let mut d = inout[3];
        let mut e = inout[4];
        let mut f = inout[5];
        let mut g = inout[6];
        let mut h = inout[7];

        let mut r = self.rounds;
        let mut key_idx = 1 + 8 * (1 + 2 * r as usize);

        key_idx -= 1;
        h ^= self.expanded_key[key_idx];
        key_idx -= 1;
        g = g.wrapping_sub(self.expanded_key[key_idx]);
        key_idx -= 1;
        f = f.wrapping_sub(self.expanded_key[key_idx]);
        key_idx -= 1;
        e ^= self.expanded_key[key_idx];
        key_idx -= 1;
        d ^= self.expanded_key[key_idx];
        key_idx -= 1;
        c = c.wrapping_sub(self.expanded_key[key_idx]);
        key_idx -= 1;
        b = b.wrapping_sub(self.expanded_key[key_idx]);
        key_idx -= 1;
        a ^= self.expanded_key[key_idx];

        while r > 0 {
            // Inverse Permutation
            let t = e;
            e = b;
            b = c;
            c = t;
            let t = f;
            f = d;
            d = g;
            g = t;

            // IPHT
            a = a.wrapping_sub(e);
            e = e.wrapping_sub(a);
            b = b.wrapping_sub(f);
            f = f.wrapping_sub(b);
            c = c.wrapping_sub(g);
            g = g.wrapping_sub(c);
            d = d.wrapping_sub(h);
            h = h.wrapping_sub(d);

            a = a.wrapping_sub(c);
            c = c.wrapping_sub(a);
            e = e.wrapping_sub(g);
            g = g.wrapping_sub(e);
            b = b.wrapping_sub(d);
            d = d.wrapping_sub(b);
            f = f.wrapping_sub(h);
            h = h.wrapping_sub(f);

            a = a.wrapping_sub(b);
            b = b.wrapping_sub(a);
            c = c.wrapping_sub(d);
            d = d.wrapping_sub(c);
            e = e.wrapping_sub(f);
            f = f.wrapping_sub(e);
            g = g.wrapping_sub(h);
            h = h.wrapping_sub(g);

            key_idx -= 1;
            h = h.wrapping_sub(self.expanded_key[key_idx]);
            key_idx -= 1;
            g ^= self.expanded_key[key_idx];
            key_idx -= 1;
            f ^= self.expanded_key[key_idx];
            key_idx -= 1;
            e = e.wrapping_sub(self.expanded_key[key_idx]);
            key_idx -= 1;
            d = d.wrapping_sub(self.expanded_key[key_idx]);
            key_idx -= 1;
            c ^= self.expanded_key[key_idx];
            key_idx -= 1;
            b ^= self.expanded_key[key_idx];
            key_idx -= 1;
            a = a.wrapping_sub(self.expanded_key[key_idx]);

            key_idx -= 1;
            h = SAFER_LBOX[h as usize] ^ self.expanded_key[key_idx];
            key_idx -= 1;
            g = SAFER_EBOX[g as usize].wrapping_sub(self.expanded_key[key_idx]);
            key_idx -= 1;
            f = SAFER_EBOX[f as usize].wrapping_sub(self.expanded_key[key_idx]);
            key_idx -= 1;
            e = SAFER_LBOX[e as usize] ^ self.expanded_key[key_idx];
            key_idx -= 1;
            d = SAFER_LBOX[d as usize] ^ self.expanded_key[key_idx];
            key_idx -= 1;
            c = SAFER_EBOX[c as usize].wrapping_sub(self.expanded_key[key_idx]);
            key_idx -= 1;
            b = SAFER_EBOX[b as usize].wrapping_sub(self.expanded_key[key_idx]);
            key_idx -= 1;
            a = SAFER_LBOX[a as usize] ^ self.expanded_key[key_idx];

            r -= 1;
        }

        inout[0] = a;
        inout[1] = b;
        inout[2] = c;
        inout[3] = d;
        inout[4] = e;
        inout[5] = f;
        inout[6] = g;
        inout[7] = h;
    }
}

impl Safer {
    pub const BLOCK_SIZE: usize = 8;
    pub const MAX_NOF_ROUNDS: u8 = 13;

    pub fn new_k64(key: &[u8], rounds: u8) -> CryptoResult<Self> {
        if key.len() != 8 {
            return Err(CryptoError::InvalidKeySize {
                expected: "8",
                actual: key.len(),
            });
        }
        if rounds != 0 && (rounds < 6 || rounds > Self::MAX_NOF_ROUNDS) {
            return Err(CryptoError::InvalidRound(rounds as usize));
        }
        let rounds = if rounds == 0 { 6 } else { rounds };
        let expanded_key = safer_expand_userkey(key, key, rounds as u32, false);
        Ok(Self {
            rounds,
            expanded_key,
        })
    }

    pub fn new_sk64(key: &[u8], rounds: u8) -> CryptoResult<Self> {
        if key.len() != 8 {
            return Err(CryptoError::InvalidKeySize {
                expected: "8",
                actual: key.len(),
            });
        }
        if rounds != 0 && (rounds < 6 || rounds > Self::MAX_NOF_ROUNDS) {
            return Err(CryptoError::InvalidRound(rounds as usize));
        }
        let rounds = if rounds == 0 { 6 } else { rounds };
        let expanded_key = safer_expand_userkey(key, key, rounds as u32, true);
        Ok(Self {
            rounds,
            expanded_key,
        })
    }

    pub fn new_k128(key: &[u8], rounds: u8) -> CryptoResult<Self> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeySize {
                expected: "16",
                actual: key.len(),
            });
        }
        if rounds != 0 && (rounds < 6 || rounds > Self::MAX_NOF_ROUNDS) {
            return Err(CryptoError::InvalidRound(rounds as usize));
        }
        let rounds = if rounds == 0 { 10 } else { rounds };
        let expanded_key = safer_expand_userkey(&key[..8], &key[8..16], rounds as u32, false);
        Ok(Self {
            rounds,
            expanded_key,
        })
    }

    pub fn new_sk128(key: &[u8], rounds: u8) -> CryptoResult<Self> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeySize {
                expected: "16",
                actual: key.len(),
            });
        }
        if rounds != 0 && (rounds < 6 || rounds > Self::MAX_NOF_ROUNDS) {
            return Err(CryptoError::InvalidRound(rounds as usize));
        }
        let rounds = if rounds == 0 { 10 } else { rounds };
        let expanded_key = safer_expand_userkey(&key[..8], &key[8..16], rounds as u32, true);
        Ok(Self {
            rounds,
            expanded_key,
        })
    }
}

fn safer_expand_userkey(
    userkey_1: &[u8],
    userkey_2: &[u8],
    nof_rounds: u32,
    strengthened: bool,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 2 * nof_rounds as usize * 8 + 8);
    let mut ka = [0u8; 9];
    let mut kb = [0u8; 9];

    let nof_rounds = nof_rounds.min(13);

    key.push(nof_rounds as u8);

    ka[8] = 0;
    kb[8] = 0;

    for j in 0..8 {
        ka[j] = userkey_1[j].rotate_left(5);
        ka[8] ^= ka[j];
        kb[j] = userkey_2[j];
        key.push(kb[j]);
        kb[8] ^= kb[j];
    }

    let mut k = 0;
    for i in 1..=nof_rounds {
        for j in 0..9 {
            ka[j] = ka[j].rotate_left(6);
            kb[j] = kb[j].rotate_left(6);
        }

        if strengthened {
            k = (2 * i - 1) as usize;
            while k >= 9 {
                k -= 9;
            }
        }

        for j in 0..8usize {
            let bias_idx = (18 * i + j as u32 + 1) & 0xFF;
            let bias = SAFER_EBOX[SAFER_EBOX[bias_idx as usize] as usize];
            if strengthened {
                key.push(ka[k].wrapping_add(bias));
                k += 1;
                if k == 9 {
                    k = 0;
                }
            } else {
                key.push(ka[j].wrapping_add(bias));
            }
        }

        if strengthened {
            k = (2 * i) as usize;
            while k >= 9 {
                k -= 9;
            }
        }

        for j in 0..8usize {
            let bias_idx = (18 * i + j as u32 + 10) & 0xFF;
            let bias = SAFER_EBOX[SAFER_EBOX[bias_idx as usize] as usize];
            if strengthened {
                key.push(kb[k].wrapping_add(bias));
                k += 1;
                if k == 9 {
                    k = 0;
                }
            } else {
                key.push(kb[j].wrapping_add(bias));
            }
        }
    }
    key
}

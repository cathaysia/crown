//! Module cast5 implements CAST5, as defined in RFC 2144.
//!
//! # WARNING
//!
//! CAST5 is a legacy cipher and its short block size makes it vulnerable to
//! birthday bound attacks (see <https://sweet32.info>). It should only be used
//! where compatibility with legacy systems, not security, is the goal.
//!
//! Deprecated: any new system should use [AES](crate::block::aes::Aes) (if necessary in
//! an AEAD mode like Aes-Gcm or
//! [ChaCha20-Poly1305](crate::aead::chacha20poly1305::ChaCha20Poly1305).

mod data;

#[cfg(test)]
mod tests;

use crate::{
    aead::{ocb::OcbGeneric, ocb3::Ocb3Generic},
    block::{BlockCipher, BlockCipherMarker},
    error::{CryptoError, CryptoResult},
};
use data::SCHEDULE;
use data::S_BOX;

pub struct Cast5 {
    masking: [u32; 16],
    rotate: [u8; 16],
}
impl BlockCipherMarker for Cast5 {}
impl OcbGeneric for Cast5 {}
impl Ocb3Generic for Cast5 {}

impl Cast5 {
    pub const KEY_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 8;
    /// Create a new instance of Cast5.
    ///
    /// **key**: The key size should be 16 bytes.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(CryptoError::InvalidKeySize {
                expected: "16",
                actual: key.len(),
            });
        }

        let mut cipher = Cast5 {
            masking: [0; 16],
            rotate: [0; 16],
        };

        cipher.key_schedule(key);
        Ok(cipher)
    }

    fn key_schedule(&mut self, key: &[u8]) {
        let mut t = [0u32; 8];
        let mut k = [0u32; 32];

        (0..4).for_each(|i| {
            let j = i * 4;
            t[i] = u32::from_be_bytes([key[j], key[j + 1], key[j + 2], key[j + 3]]);
        });

        let x = [6, 7, 4, 5];
        let mut ki = 0;

        for _half in 0..2 {
            for round in &SCHEDULE {
                for j in 0..4 {
                    let a = round.a[j];
                    let mut w = t[a[1] as usize];
                    w ^= S_BOX[4][(t[a[2] as usize >> 2] >> (24 - 8 * (a[2] & 3))) as usize & 0xff];
                    w ^= S_BOX[5][(t[a[3] as usize >> 2] >> (24 - 8 * (a[3] & 3))) as usize & 0xff];
                    w ^= S_BOX[6][(t[a[4] as usize >> 2] >> (24 - 8 * (a[4] & 3))) as usize & 0xff];
                    w ^= S_BOX[7][(t[a[5] as usize >> 2] >> (24 - 8 * (a[5] & 3))) as usize & 0xff];
                    w ^= S_BOX[x[j]]
                        [(t[a[6] as usize >> 2] >> (24 - 8 * (a[6] & 3))) as usize & 0xff];
                    t[a[0] as usize] = w;
                }

                for j in 0..4 {
                    let b = round.b[j];
                    let mut w =
                        S_BOX[4][(t[b[0] as usize >> 2] >> (24 - 8 * (b[0] & 3))) as usize & 0xff];
                    w ^= S_BOX[5][(t[b[1] as usize >> 2] >> (24 - 8 * (b[1] & 3))) as usize & 0xff];
                    w ^= S_BOX[6][(t[b[2] as usize >> 2] >> (24 - 8 * (b[2] & 3))) as usize & 0xff];
                    w ^= S_BOX[7][(t[b[3] as usize >> 2] >> (24 - 8 * (b[3] & 3))) as usize & 0xff];
                    w ^= S_BOX[4 + j]
                        [(t[b[4] as usize >> 2] >> (24 - 8 * (b[4] & 3))) as usize & 0xff];
                    k[ki] = w;
                    ki += 1;
                }
            }
        }

        for i in 0..16 {
            self.masking[i] = k[i];
            self.rotate[i] = (k[16 + i] & 0x1f) as u8;
        }
    }
}
impl BlockCipher for Cast5 {
    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    fn encrypt(&self, inout: &mut [u8]) {
        let mut l = u32::from_be_bytes([inout[0], inout[1], inout[2], inout[3]]);
        let mut r = u32::from_be_bytes([inout[4], inout[5], inout[6], inout[7]]);

        (l, r) = (r, l ^ f1(r, self.masking[0], self.rotate[0]));
        (l, r) = (r, l ^ f2(r, self.masking[1], self.rotate[1]));
        (l, r) = (r, l ^ f3(r, self.masking[2], self.rotate[2]));
        (l, r) = (r, l ^ f1(r, self.masking[3], self.rotate[3]));

        (l, r) = (r, l ^ f2(r, self.masking[4], self.rotate[4]));
        (l, r) = (r, l ^ f3(r, self.masking[5], self.rotate[5]));
        (l, r) = (r, l ^ f1(r, self.masking[6], self.rotate[6]));
        (l, r) = (r, l ^ f2(r, self.masking[7], self.rotate[7]));

        (l, r) = (r, l ^ f3(r, self.masking[8], self.rotate[8]));
        (l, r) = (r, l ^ f1(r, self.masking[9], self.rotate[9]));
        (l, r) = (r, l ^ f2(r, self.masking[10], self.rotate[10]));
        (l, r) = (r, l ^ f3(r, self.masking[11], self.rotate[11]));

        (l, r) = (r, l ^ f1(r, self.masking[12], self.rotate[12]));
        (l, r) = (r, l ^ f2(r, self.masking[13], self.rotate[13]));
        (l, r) = (r, l ^ f3(r, self.masking[14], self.rotate[14]));
        (l, r) = (r, l ^ f1(r, self.masking[15], self.rotate[15]));

        inout[0] = (r >> 24) as u8;
        inout[1] = (r >> 16) as u8;
        inout[2] = (r >> 8) as u8;
        inout[3] = r as u8;
        inout[4] = (l >> 24) as u8;
        inout[5] = (l >> 16) as u8;
        inout[6] = (l >> 8) as u8;
        inout[7] = l as u8;
    }

    fn decrypt(&self, inout: &mut [u8]) {
        let mut l = u32::from_be_bytes([inout[0], inout[1], inout[2], inout[3]]);
        let mut r = u32::from_be_bytes([inout[4], inout[5], inout[6], inout[7]]);

        (l, r) = (r, l ^ f1(r, self.masking[15], self.rotate[15]));
        (l, r) = (r, l ^ f3(r, self.masking[14], self.rotate[14]));
        (l, r) = (r, l ^ f2(r, self.masking[13], self.rotate[13]));
        (l, r) = (r, l ^ f1(r, self.masking[12], self.rotate[12]));

        (l, r) = (r, l ^ f3(r, self.masking[11], self.rotate[11]));
        (l, r) = (r, l ^ f2(r, self.masking[10], self.rotate[10]));
        (l, r) = (r, l ^ f1(r, self.masking[9], self.rotate[9]));
        (l, r) = (r, l ^ f3(r, self.masking[8], self.rotate[8]));

        (l, r) = (r, l ^ f2(r, self.masking[7], self.rotate[7]));
        (l, r) = (r, l ^ f1(r, self.masking[6], self.rotate[6]));
        (l, r) = (r, l ^ f3(r, self.masking[5], self.rotate[5]));
        (l, r) = (r, l ^ f2(r, self.masking[4], self.rotate[4]));

        (l, r) = (r, l ^ f1(r, self.masking[3], self.rotate[3]));
        (l, r) = (r, l ^ f3(r, self.masking[2], self.rotate[2]));
        (l, r) = (r, l ^ f2(r, self.masking[1], self.rotate[1]));
        (l, r) = (r, l ^ f1(r, self.masking[0], self.rotate[0]));

        inout[0] = (r >> 24) as u8;
        inout[1] = (r >> 16) as u8;
        inout[2] = (r >> 8) as u8;
        inout[3] = r as u8;
        inout[4] = (l >> 24) as u8;
        inout[5] = (l >> 16) as u8;
        inout[6] = (l >> 8) as u8;
        inout[7] = l as u8;
    }
}

// These are the three 'f' functions. See RFC 2144, section 2.2.
fn f1(d: u32, m: u32, r: u8) -> u32 {
    let t = m.wrapping_add(d);
    let i = t.rotate_left(r as u32);
    ((S_BOX[0][(i >> 24) as usize] ^ S_BOX[1][((i >> 16) & 0xff) as usize])
        .wrapping_sub(S_BOX[2][((i >> 8) & 0xff) as usize]))
    .wrapping_add(S_BOX[3][(i & 0xff) as usize])
}

fn f2(d: u32, m: u32, r: u8) -> u32 {
    let t = m ^ d;
    let i = t.rotate_left(r as u32);
    ((S_BOX[0][(i >> 24) as usize].wrapping_sub(S_BOX[1][((i >> 16) & 0xff) as usize]))
        .wrapping_add(S_BOX[2][((i >> 8) & 0xff) as usize]))
        ^ S_BOX[3][(i & 0xff) as usize]
}

fn f3(d: u32, m: u32, r: u8) -> u32 {
    let t = m.wrapping_sub(d);
    let i = t.rotate_left(r as u32);
    ((S_BOX[0][(i >> 24) as usize].wrapping_add(S_BOX[1][((i >> 16) & 0xff) as usize]))
        ^ S_BOX[2][((i >> 8) & 0xff) as usize])
        .wrapping_sub(S_BOX[3][(i & 0xff) as usize])
}

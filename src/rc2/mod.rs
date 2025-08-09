//! Package rc2 implements the RC2 cipher
//! https://www.ietf.org/rfc/rfc2268.txt
//! http://people.csail.mit.edu/rivest/pubs/KRRR98.pdf
//!
//! This code is licensed under the MIT license.

#[cfg(test)]
mod tests;

use std::convert::TryInto;

use crate::cipher::{marker::BlockCipherMarker, BlockCipher};

const BLOCK_SIZE: usize = 8;

const PI_TABLE: [u8; 256] = [
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
    0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
    0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
    0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
    0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
    0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
    0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
    0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
    0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
    0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
    0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
];

pub struct Rc2Cipher {
    k: [u16; 64],
}

impl BlockCipherMarker for Rc2Cipher {}

impl Rc2Cipher {
    pub fn new(key: &[u8], t1: usize) -> Result<Self, &'static str> {
        Ok(Self {
            k: expand_key(key, t1),
        })
    }
}

impl BlockCipher for Rc2Cipher {
    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
        if src.len() < BLOCK_SIZE || dst.len() < BLOCK_SIZE {
            panic!("src and dst must be at least {} bytes", BLOCK_SIZE);
        }

        let mut r0 = u16::from_le_bytes(src[0..2].try_into().unwrap());
        let mut r1 = u16::from_le_bytes(src[2..4].try_into().unwrap());
        let mut r2 = u16::from_le_bytes(src[4..6].try_into().unwrap());
        let mut r3 = u16::from_le_bytes(src[6..8].try_into().unwrap());

        let mut j = 0;

        while j <= 16 {
            // mix r0
            r0 = r0
                .wrapping_add(self.k[j])
                .wrapping_add(r3 & r2)
                .wrapping_add((!r3) & r1);
            r0 = r0.rotate_left(1);
            j += 1;

            // mix r1
            r1 = r1
                .wrapping_add(self.k[j])
                .wrapping_add(r0 & r3)
                .wrapping_add((!r0) & r2);
            r1 = r1.rotate_left(2);
            j += 1;

            // mix r2
            r2 = r2
                .wrapping_add(self.k[j])
                .wrapping_add(r1 & r0)
                .wrapping_add((!r1) & r3);
            r2 = r2.rotate_left(3);
            j += 1;

            // mix r3
            r3 = r3
                .wrapping_add(self.k[j])
                .wrapping_add(r2 & r1)
                .wrapping_add((!r2) & r0);
            r3 = r3.rotate_left(5);
            j += 1;
        }

        r0 = r0.wrapping_add(self.k[(r3 & 63) as usize]);
        r1 = r1.wrapping_add(self.k[(r0 & 63) as usize]);
        r2 = r2.wrapping_add(self.k[(r1 & 63) as usize]);
        r3 = r3.wrapping_add(self.k[(r2 & 63) as usize]);

        while j <= 40 {
            // mix r0
            r0 = r0
                .wrapping_add(self.k[j])
                .wrapping_add(r3 & r2)
                .wrapping_add((!r3) & r1);
            r0 = r0.rotate_left(1);
            j += 1;

            // mix r1
            r1 = r1
                .wrapping_add(self.k[j])
                .wrapping_add(r0 & r3)
                .wrapping_add((!r0) & r2);
            r1 = r1.rotate_left(2);
            j += 1;

            // mix r2
            r2 = r2
                .wrapping_add(self.k[j])
                .wrapping_add(r1 & r0)
                .wrapping_add((!r1) & r3);
            r2 = r2.rotate_left(3);
            j += 1;

            // mix r3
            r3 = r3
                .wrapping_add(self.k[j])
                .wrapping_add(r2 & r1)
                .wrapping_add((!r2) & r0);
            r3 = r3.rotate_left(5);
            j += 1;
        }

        r0 = r0.wrapping_add(self.k[(r3 & 63) as usize]);
        r1 = r1.wrapping_add(self.k[(r0 & 63) as usize]);
        r2 = r2.wrapping_add(self.k[(r1 & 63) as usize]);
        r3 = r3.wrapping_add(self.k[(r2 & 63) as usize]);

        while j <= 60 {
            // mix r0
            r0 = r0
                .wrapping_add(self.k[j])
                .wrapping_add(r3 & r2)
                .wrapping_add((!r3) & r1);
            r0 = r0.rotate_left(1);
            j += 1;

            // mix r1
            r1 = r1
                .wrapping_add(self.k[j])
                .wrapping_add(r0 & r3)
                .wrapping_add((!r0) & r2);
            r1 = r1.rotate_left(2);
            j += 1;

            // mix r2
            r2 = r2
                .wrapping_add(self.k[j])
                .wrapping_add(r1 & r0)
                .wrapping_add((!r1) & r3);
            r2 = r2.rotate_left(3);
            j += 1;

            // mix r3
            r3 = r3
                .wrapping_add(self.k[j])
                .wrapping_add(r2 & r1)
                .wrapping_add((!r2) & r0);
            r3 = r3.rotate_left(5);
            j += 1;
        }

        dst[0..2].copy_from_slice(&r0.to_le_bytes());
        dst[2..4].copy_from_slice(&r1.to_le_bytes());
        dst[4..6].copy_from_slice(&r2.to_le_bytes());
        dst[6..8].copy_from_slice(&r3.to_le_bytes());
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
        if src.len() < BLOCK_SIZE || dst.len() < BLOCK_SIZE {
            panic!("src and dst must be at least {} bytes", BLOCK_SIZE);
        }

        let mut r0 = u16::from_le_bytes(src[0..2].try_into().unwrap());
        let mut r1 = u16::from_le_bytes(src[2..4].try_into().unwrap());
        let mut r2 = u16::from_le_bytes(src[4..6].try_into().unwrap());
        let mut r3 = u16::from_le_bytes(src[6..8].try_into().unwrap());

        let mut j = 63;

        while j >= 44 {
            // unmix r3
            r3 = r3.rotate_left(16 - 5);
            r3 = r3
                .wrapping_sub(self.k[j])
                .wrapping_sub(r2 & r1)
                .wrapping_sub((!r2) & r0);
            j -= 1;

            // unmix r2
            r2 = r2.rotate_left(16 - 3);
            r2 = r2
                .wrapping_sub(self.k[j])
                .wrapping_sub(r1 & r0)
                .wrapping_sub((!r1) & r3);
            j -= 1;

            // unmix r1
            r1 = r1.rotate_left(16 - 2);
            r1 = r1
                .wrapping_sub(self.k[j])
                .wrapping_sub(r0 & r3)
                .wrapping_sub((!r0) & r2);
            j -= 1;

            // unmix r0
            r0 = r0.rotate_left(16 - 1);
            r0 = r0
                .wrapping_sub(self.k[j])
                .wrapping_sub(r3 & r2)
                .wrapping_sub((!r3) & r1);
            j -= 1;
        }

        r3 = r3.wrapping_sub(self.k[(r2 & 63) as usize]);
        r2 = r2.wrapping_sub(self.k[(r1 & 63) as usize]);
        r1 = r1.wrapping_sub(self.k[(r0 & 63) as usize]);
        r0 = r0.wrapping_sub(self.k[(r3 & 63) as usize]);

        while j >= 20 {
            // unmix r3
            r3 = r3.rotate_left(16 - 5);
            r3 = r3
                .wrapping_sub(self.k[j])
                .wrapping_sub(r2 & r1)
                .wrapping_sub((!r2) & r0);
            j -= 1;

            // unmix r2
            r2 = r2.rotate_left(16 - 3);
            r2 = r2
                .wrapping_sub(self.k[j])
                .wrapping_sub(r1 & r0)
                .wrapping_sub((!r1) & r3);
            j -= 1;

            // unmix r1
            r1 = r1.rotate_left(16 - 2);
            r1 = r1
                .wrapping_sub(self.k[j])
                .wrapping_sub(r0 & r3)
                .wrapping_sub((!r0) & r2);
            j -= 1;

            // unmix r0
            r0 = r0.rotate_left(16 - 1);
            r0 = r0
                .wrapping_sub(self.k[j])
                .wrapping_sub(r3 & r2)
                .wrapping_sub((!r3) & r1);
            j -= 1;
        }

        r3 = r3.wrapping_sub(self.k[(r2 & 63) as usize]);
        r2 = r2.wrapping_sub(self.k[(r1 & 63) as usize]);
        r1 = r1.wrapping_sub(self.k[(r0 & 63) as usize]);
        r0 = r0.wrapping_sub(self.k[(r3 & 63) as usize]);

        loop {
            // unmix r3
            r3 = r3.rotate_left(16 - 5);
            r3 = r3
                .wrapping_sub(self.k[j])
                .wrapping_sub(r2 & r1)
                .wrapping_sub((!r2) & r0);
            if j == 0 {
                break;
            }
            j -= 1;

            // unmix r2
            r2 = r2.rotate_left(16 - 3);
            r2 = r2
                .wrapping_sub(self.k[j])
                .wrapping_sub(r1 & r0)
                .wrapping_sub((!r1) & r3);
            if j == 0 {
                break;
            }
            j -= 1;

            // unmix r1
            r1 = r1.rotate_left(16 - 2);
            r1 = r1
                .wrapping_sub(self.k[j])
                .wrapping_sub(r0 & r3)
                .wrapping_sub((!r0) & r2);
            if j == 0 {
                break;
            }
            j -= 1;

            // unmix r0
            r0 = r0.rotate_left(16 - 1);
            r0 = r0
                .wrapping_sub(self.k[j])
                .wrapping_sub(r3 & r2)
                .wrapping_sub((!r3) & r1);
            if j == 0 {
                break;
            }
            j -= 1;
        }

        dst[0..2].copy_from_slice(&r0.to_le_bytes());
        dst[2..4].copy_from_slice(&r1.to_le_bytes());
        dst[4..6].copy_from_slice(&r2.to_le_bytes());
        dst[6..8].copy_from_slice(&r3.to_le_bytes());
    }
}

fn expand_key(key: &[u8], t1: usize) -> [u16; 64] {
    let mut l = [0u8; 128];
    l[..key.len()].copy_from_slice(key);

    let t = key.len();
    let t8 = (t1 + 7) / 8;
    let tm = (255 % (1u32 << (8 + t1 - 8 * t8))) as u8;

    for i in key.len()..128 {
        l[i] = PI_TABLE[(l[i - 1].wrapping_add(l[i - t])) as usize];
    }

    l[128 - t8] = PI_TABLE[(l[128 - t8] & tm) as usize];

    for i in (0..=(127 - t8)).rev() {
        l[i] = PI_TABLE[(l[i + 1] ^ l[i + t8]) as usize];
    }

    let mut k = [0u16; 64];
    for i in 0..64 {
        k[i] = u16::from_le_bytes([l[2 * i], l[2 * i + 1]]);
    }

    k
}

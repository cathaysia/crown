#[cfg(test)]
mod tests;

use bytes::BufMut;

use crate::aead::ocb3::Ocb3Marker;
use crate::error::CryptoError;
use crate::error::CryptoResult;

use super::BlockCipher;
use super::BlockCipherMarker;

use bytes::Buf;

pub struct Sm4 {
    pub ek: [u32; 32],
    pub dk: [u32; 32],
}

impl BlockCipherMarker for Sm4 {}
impl Ocb3Marker for Sm4 {}

impl Sm4 {
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeySize {
                expected: "16",
                actual: key.len(),
            });
        }
        let mut ret = Self {
            ek: [0; 32],
            dk: [0; 32],
        };
        ret.s_sm4_setkey(key);
        Ok(ret)
    }

    #[inline]
    fn s_sm4_setkey(&mut self, key: &[u8]) {
        s_sm4_mk2rk(&mut self.ek, key);
        for i in 0..32 {
            self.dk[i] = self.ek[32 - 1 - i];
        }
    }
}

impl BlockCipher for Sm4 {
    fn block_size(&self) -> usize {
        128 / 8
    }

    fn encrypt(&self, inout: &mut [u8]) {
        s_sm4_do(inout, &(self.ek));
    }

    fn decrypt(&self, inout: &mut [u8]) {
        s_sm4_do(inout, &(self.dk));
    }
}
static SM4_SBOX_TABLE: [[u8; 16]; 16] = [
    [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c,
        0x5,
    ],
    [
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x4, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x6,
        0x99,
    ],
    [
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0xb, 0x43, 0xed, 0xcf, 0xac,
        0x62,
    ],
    [
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x8, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f,
        0xa6,
    ],
    [
        0x47, 0x7, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f,
        0xa8,
    ],
    [
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0xf, 0x4b, 0x70, 0x56, 0x9d,
        0x35,
    ],
    [
        0x1e, 0x24, 0xe, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x1, 0x21, 0x78,
        0x87,
    ],
    [
        0xd4, 0, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x2, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    ],
    [
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15,
        0xa1,
    ],
    [
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1,
        0xe3,
    ],
    [
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0xd, 0x53, 0x4e,
        0x6f,
    ],
    [
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x3, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b,
        0x51,
    ],
    [
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a,
        0xd8,
    ],
    [
        0xa, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4,
        0xb0,
    ],
    [
        0x89, 0x69, 0x97, 0x4a, 0xc, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x9, 0xc5, 0x6e, 0xc6,
        0x84,
    ],
    [
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39,
        0x48,
    ],
];

macro_rules! ROLc {
    ($x:expr, $n:expr) => {
        $x.rotate_left($n)
    };
}

#[inline]
fn s_sm4_sbox(a: u8) -> u8 {
    let a = a as i32;
    SM4_SBOX_TABLE[((a >> 4) & 0xf) as usize][(a & 0xf as libc::c_int) as usize]
}
#[inline]
fn s_sm4_t(a: u32) -> u32 {
    let a = a.to_be_bytes();
    let mut b: [u8; 4] = [0; 4];
    b[0] = s_sm4_sbox(a[0]);
    b[1] = s_sm4_sbox(a[1]);
    b[2] = s_sm4_sbox(a[2]);
    b[3] = s_sm4_sbox(a[3]);
    u32::from_be_bytes(b)
}
#[inline]
fn s_sm4_l62(b: u32) -> u32 {
    b ^ ROLc!(b, 2) ^ ROLc!(b, 10) ^ ROLc!(b, 18) ^ ROLc!(b, 24)
}
#[inline]
fn s_sm4_t62(z: u32) -> u32 {
    s_sm4_l62(s_sm4_t(z))
}
static SM4_FK: [u32; 4] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
static SM4_CK: [u32; 32] = [
    0x70e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];
#[inline]
fn s_sm4_l73(b: u32) -> u32 {
    b ^ ROLc!(b, 13) ^ ROLc!(b, 23)
}
#[inline]
fn s_sm4_t73(z: u32) -> u32 {
    s_sm4_l73(s_sm4_t(z))
}
#[inline]
fn s_sm4_mk2rk(rk: &mut [u32], mk: &[u8]) {
    let mut mkb: [u32; 4] = [0, 0, 0, 0];
    let mut k: [u32; 36] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ];
    {
        let mut mk = mk;
        mkb[0] = mk.get_u32();
        mkb[1] = mk.get_u32();
        mkb[2] = mk.get_u32();
        mkb[3] = mk.get_u32();
    }
    for i in 0..4 {
        k[i] = mkb[i] ^ SM4_FK[i];
    }
    for i in 0..32 {
        k[i + 4] = k[i] ^ s_sm4_t73(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]);
    }
    (0..32).for_each(|i| {
        rk[i] = k[i + 4];
    });
}
#[inline]
fn s_sm4_f(x: &[u32], rk: u32) -> u32 {
    x[0] ^ s_sm4_t62(x[1] ^ x[2] ^ x[3] ^ rk)
}
#[inline]
fn s_sm4_r(y: &mut [u32], x: &[u32]) {
    y[0] = x[35];
    y[1] = x[34];
    y[2] = x[33];
    y[3] = x[32];
}

#[inline]
fn s_sm4_crypt(y: &mut [u32], x: &mut [u32], rk: &[u32]) {
    for i in 0..32 {
        x[i + 4] = s_sm4_f(&x[i..], rk[i]);
    }

    s_sm4_r(y, x);
}

#[inline]
fn s_sm4_do(inout: &mut [u8], rk: &[u32]) {
    let mut y: [u32; 4] = [0; 4];
    let mut x: [u32; 36] = [0; 36];
    {
        let mut input = &*inout;
        x[0] = input.get_u32();
        x[1] = input.get_u32();
        x[2] = input.get_u32();
        x[3] = input.get_u32();
    }
    s_sm4_crypt(&mut y, &mut x, rk);

    {
        let mut output = inout;
        output.put_u32(y[0]);
        output.put_u32(y[1]);
        output.put_u32(y[2]);
        output.put_u32(y[3]);
    }
}

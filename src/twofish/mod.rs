//! Package twofish implements Bruce Schneier's Twofish encryption algorithm.
//!
//! Deprecated: Twofish is a legacy cipher and should not be used for new
//! applications. Also, this package does not and will not provide an optimized
//! implementation. Instead, use AES (from crypto/aes, if necessary in an AEAD
//! mode like crypto/cipher.NewGCM) or XChaCha20-Poly1305 (from
//! golang.org/x/crypto/chacha20poly1305).

// Twofish is defined in https://www.schneier.com/paper-twofish-paper.pdf [TWOFISH]

// This code is a port of the LibTom C implementation.
// See http://libtom.org/?page=features&newsitems=5&whatfile=crypt.
// LibTomCrypt is free for all purposes under the public domain.
// It was heavily inspired by the go blowfish package.

#[cfg(test)]
mod tests;

use crate::{cipher::BlockCipher, error::CryptoError};

// BlockSize is the constant block size of Twofish.
pub const BLOCK_SIZE: usize = 16;

const MDS_POLYNOMIAL: u32 = 0x169; // x^8 + x^6 + x^5 + x^3 + 1, see [TWOFISH] 4.2
const RS_POLYNOMIAL: u32 = 0x14d; // x^8 + x^6 + x^3 + x^2 + 1, see [TWOFISH] 4.3

// A Cipher is an instance of Twofish encryption using a particular key.
pub struct Cipher {
    s: [[u32; 256]; 4],
    k: [u32; 40],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySizeError(pub usize);

impl std::fmt::Display for KeySizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "crypto/twofish: invalid key size {}", self.0)
    }
}

impl std::error::Error for KeySizeError {}

impl From<KeySizeError> for CryptoError {
    fn from(err: KeySizeError) -> Self {
        CryptoError::InvalidKeySize(err.0)
    }
}

// NewCipher creates and returns a Cipher.
// The key argument should be the Twofish key, 16, 24 or 32 bytes.
pub fn new_cipher(key: &[u8]) -> Result<Cipher, KeySizeError> {
    let keylen = key.len();

    if keylen != 16 && keylen != 24 && keylen != 32 {
        return Err(KeySizeError(keylen));
    }

    // k is the number of 64 bit words in key
    let k = keylen / 8;

    // Create the S[..] words
    let mut s = [0u8; 4 * 4];
    for i in 0..k {
        // Computes [y0 y1 y2 y3] = rs . [x0 x1 x2 x3 x4 x5 x6 x7]
        for (j, rs_row) in RS.iter().enumerate() {
            for (k_idx, &rs_val) in rs_row.iter().enumerate() {
                s[4 * i + j] ^= gf_mult(key[8 * i + k_idx], rs_val, RS_POLYNOMIAL);
            }
        }
    }

    // Calculate subkeys
    let mut c = Cipher {
        s: [[0; 256]; 4],
        k: [0; 40],
    };

    let mut tmp = [0u8; 4];
    for i in 0u8..20 {
        // A = h(p * 2x, Me)
        (0..tmp.len()).for_each(|j| {
            tmp[j] = 2 * i;
        });
        let a = h(&tmp, key, 0);

        // B = rolc(h(p * (2x + 1), Mo), 8)
        (0..tmp.len()).for_each(|j| {
            tmp[j] = 2 * i + 1;
        });
        let b = h(&tmp, key, 1);
        let b = b.rotate_left(8);

        c.k[2 * i as usize] = a.wrapping_add(b);

        // K[2i+1] = (A + 2B) <<< 9
        c.k[2 * i as usize + 1] = (2u32.wrapping_mul(b).wrapping_add(a)).rotate_left(9);
    }

    // Calculate sboxes
    match k {
        2 => {
            for i in 0..256 {
                c.s[0][i] = mds_column_mult(
                    SBOX[1][(SBOX[0][(SBOX[0][i] ^ s[0]) as usize] ^ s[4]) as usize],
                    0,
                );
                c.s[1][i] = mds_column_mult(
                    SBOX[0][(SBOX[0][(SBOX[1][i] ^ s[1]) as usize] ^ s[5]) as usize],
                    1,
                );
                c.s[2][i] = mds_column_mult(
                    SBOX[1][(SBOX[1][(SBOX[0][i] ^ s[2]) as usize] ^ s[6]) as usize],
                    2,
                );
                c.s[3][i] = mds_column_mult(
                    SBOX[0][(SBOX[1][(SBOX[1][i] ^ s[3]) as usize] ^ s[7]) as usize],
                    3,
                );
            }
        }
        3 => {
            for i in 0..256 {
                c.s[0][i] = mds_column_mult(
                    SBOX[1][(SBOX[0][(SBOX[0][(SBOX[1][i] ^ s[0]) as usize] ^ s[4]) as usize]
                        ^ s[8]) as usize],
                    0,
                );
                c.s[1][i] = mds_column_mult(
                    SBOX[0][(SBOX[0][(SBOX[1][(SBOX[1][i] ^ s[1]) as usize] ^ s[5]) as usize]
                        ^ s[9]) as usize],
                    1,
                );
                c.s[2][i] = mds_column_mult(
                    SBOX[1][(SBOX[1][(SBOX[0][(SBOX[0][i] ^ s[2]) as usize] ^ s[6]) as usize]
                        ^ s[10]) as usize],
                    2,
                );
                c.s[3][i] = mds_column_mult(
                    SBOX[0][(SBOX[1][(SBOX[1][(SBOX[0][i] ^ s[3]) as usize] ^ s[7]) as usize]
                        ^ s[11]) as usize],
                    3,
                );
            }
        }
        _ => {
            for i in 0..256 {
                c.s[0][i] = mds_column_mult(
                    SBOX[1][(SBOX[0][(SBOX[0]
                        [(SBOX[1][(SBOX[1][i] ^ s[0]) as usize] ^ s[4]) as usize]
                        ^ s[8]) as usize]
                        ^ s[12]) as usize],
                    0,
                );
                c.s[1][i] = mds_column_mult(
                    SBOX[0][(SBOX[0][(SBOX[1]
                        [(SBOX[1][(SBOX[0][i] ^ s[1]) as usize] ^ s[5]) as usize]
                        ^ s[9]) as usize]
                        ^ s[13]) as usize],
                    1,
                );
                c.s[2][i] = mds_column_mult(
                    SBOX[1][(SBOX[1][(SBOX[0]
                        [(SBOX[0][(SBOX[0][i] ^ s[2]) as usize] ^ s[6]) as usize]
                        ^ s[10]) as usize]
                        ^ s[14]) as usize],
                    2,
                );
                c.s[3][i] = mds_column_mult(
                    SBOX[0][(SBOX[1][(SBOX[1]
                        [(SBOX[0][(SBOX[1][i] ^ s[3]) as usize] ^ s[7]) as usize]
                        ^ s[11]) as usize]
                        ^ s[15]) as usize],
                    3,
                );
            }
        }
    }

    Ok(c)
}

impl BlockCipher for Cipher {
    // BlockSize returns the Twofish block size, 16 bytes.
    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    // Encrypt encrypts a 16-byte block from src to dst, which may overlap.
    // Note that for amounts of data larger than a block,
    // it is not safe to just call Encrypt on successive blocks;
    // instead, use an encryption mode like CBC (see crypto/cipher/cbc.go).
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
        let s1 = &self.s[0];
        let s2 = &self.s[1];
        let s3 = &self.s[2];
        let s4 = &self.s[3];

        // Load input
        let mut ia = load32l(&src[0..4]);
        let mut ib = load32l(&src[4..8]);
        let mut ic = load32l(&src[8..12]);
        let mut id = load32l(&src[12..16]);

        // Pre-whitening
        ia ^= self.k[0];
        ib ^= self.k[1];
        ic ^= self.k[2];
        id ^= self.k[3];

        for i in 0..8 {
            let k = &self.k[8 + i * 4..12 + i * 4];
            let t2 = s2[ib as u8 as usize]
                ^ s3[(ib >> 8) as u8 as usize]
                ^ s4[(ib >> 16) as u8 as usize]
                ^ s1[(ib >> 24) as u8 as usize];
            let t1 = s1[ia as u8 as usize]
                ^ s2[(ia >> 8) as u8 as usize]
                ^ s3[(ia >> 16) as u8 as usize]
                ^ s4[(ia >> 24) as u8 as usize];
            let t1 = t1.wrapping_add(t2);
            ic = (ic ^ (t1.wrapping_add(k[0]))).rotate_right(1);
            id = id.rotate_left(1) ^ (t2.wrapping_add(t1).wrapping_add(k[1]));

            let t2 = s2[id as u8 as usize]
                ^ s3[(id >> 8) as u8 as usize]
                ^ s4[(id >> 16) as u8 as usize]
                ^ s1[(id >> 24) as u8 as usize];
            let t1 = s1[ic as u8 as usize]
                ^ s2[(ic >> 8) as u8 as usize]
                ^ s3[(ic >> 16) as u8 as usize]
                ^ s4[(ic >> 24) as u8 as usize];
            let t1 = t1.wrapping_add(t2);
            ia = (ia ^ (t1.wrapping_add(k[2]))).rotate_right(1);
            ib = ib.rotate_left(1) ^ (t2.wrapping_add(t1).wrapping_add(k[3]));
        }

        // Output with "undo last swap"
        let ta = ic ^ self.k[4];
        let tb = id ^ self.k[5];
        let tc = ia ^ self.k[6];
        let td = ib ^ self.k[7];

        store32l(&mut dst[0..4], ta);
        store32l(&mut dst[4..8], tb);
        store32l(&mut dst[8..12], tc);
        store32l(&mut dst[12..16], td);
    }

    // Decrypt decrypts a 16-byte block from src to dst, which may overlap.
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
        let s1 = &self.s[0];
        let s2 = &self.s[1];
        let s3 = &self.s[2];
        let s4 = &self.s[3];

        // Load input
        let ta = load32l(&src[0..4]);
        let tb = load32l(&src[4..8]);
        let tc = load32l(&src[8..12]);
        let td = load32l(&src[12..16]);

        // Undo undo final swap
        let mut ia = tc ^ self.k[6];
        let mut ib = td ^ self.k[7];
        let mut ic = ta ^ self.k[4];
        let mut id = tb ^ self.k[5];

        for i in (1..=8).rev() {
            let k = &self.k[4 + i * 4..8 + i * 4];
            let t2 = s2[id as u8 as usize]
                ^ s3[(id >> 8) as u8 as usize]
                ^ s4[(id >> 16) as u8 as usize]
                ^ s1[(id >> 24) as u8 as usize];
            let t1 = s1[ic as u8 as usize]
                ^ s2[(ic >> 8) as u8 as usize]
                ^ s3[(ic >> 16) as u8 as usize]
                ^ s4[(ic >> 24) as u8 as usize];
            let t1 = t1.wrapping_add(t2);
            ia = ia.rotate_left(1) ^ (t1.wrapping_add(k[2]));
            ib = (ib ^ (t2.wrapping_add(t1).wrapping_add(k[3]))).rotate_right(1);

            let t2 = s2[ib as u8 as usize]
                ^ s3[(ib >> 8) as u8 as usize]
                ^ s4[(ib >> 16) as u8 as usize]
                ^ s1[(ib >> 24) as u8 as usize];
            let t1 = s1[ia as u8 as usize]
                ^ s2[(ia >> 8) as u8 as usize]
                ^ s3[(ia >> 16) as u8 as usize]
                ^ s4[(ia >> 24) as u8 as usize];
            let t1 = t1.wrapping_add(t2);
            ic = ic.rotate_left(1) ^ (t1.wrapping_add(k[0]));
            id = (id ^ (t2.wrapping_add(t1).wrapping_add(k[1]))).rotate_right(1);
        }

        // Undo pre-whitening
        ia ^= self.k[0];
        ib ^= self.k[1];
        ic ^= self.k[2];
        id ^= self.k[3];

        store32l(&mut dst[0..4], ia);
        store32l(&mut dst[4..8], ib);
        store32l(&mut dst[8..12], ic);
        store32l(&mut dst[12..16], id);
    }
}

// store32l stores src in dst in little-endian form.
fn store32l(dst: &mut [u8], src: u32) {
    dst[0] = src as u8;
    dst[1] = (src >> 8) as u8;
    dst[2] = (src >> 16) as u8;
    dst[3] = (src >> 24) as u8;
}

// load32l reads a little-endian uint32 from src.
fn load32l(src: &[u8]) -> u32 {
    u32::from(src[0])
        | (u32::from(src[1]) << 8)
        | (u32::from(src[2]) << 16)
        | (u32::from(src[3]) << 24)
}

// The RS matrix. See [TWOFISH] 4.3
const RS: [[u8; 8]; 4] = [
    [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
    [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
    [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
    [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03],
];

// sbox tables
const SBOX: [[u8; 256]; 2] = [
    [
        0xa9, 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76, 0x9a, 0x92, 0x80, 0x78, 0xe4, 0xdd, 0xd1,
        0x38, 0x0d, 0xc6, 0x35, 0x98, 0x18, 0xf7, 0xec, 0x6c, 0x43, 0x75, 0x37, 0x26, 0xfa, 0x13,
        0x94, 0x48, 0xf2, 0xd0, 0x8b, 0x30, 0x84, 0x54, 0xdf, 0x23, 0x19, 0x5b, 0x3d, 0x59, 0xf3,
        0xae, 0xa2, 0x82, 0x63, 0x01, 0x83, 0x2e, 0xd9, 0x51, 0x9b, 0x7c, 0xa6, 0xeb, 0xa5, 0xbe,
        0x16, 0x0c, 0xe3, 0x61, 0xc0, 0x8c, 0x3a, 0xf5, 0x73, 0x2c, 0x25, 0x0b, 0xbb, 0x4e, 0x89,
        0x6b, 0x53, 0x6a, 0xb4, 0xf1, 0xe1, 0xe6, 0xbd, 0x45, 0xe2, 0xf4, 0xb6, 0x66, 0xcc, 0x95,
        0x03, 0x56, 0xd4, 0x1c, 0x1e, 0xd7, 0xfb, 0xc3, 0x8e, 0xb5, 0xe9, 0xcf, 0xbf, 0xba, 0xea,
        0x77, 0x39, 0xaf, 0x33, 0xc9, 0x62, 0x71, 0x81, 0x79, 0x09, 0xad, 0x24, 0xcd, 0xf9, 0xd8,
        0xe5, 0xc5, 0xb9, 0x4d, 0x44, 0x08, 0x86, 0xe7, 0xa1, 0x1d, 0xaa, 0xed, 0x06, 0x70, 0xb2,
        0xd2, 0x41, 0x7b, 0xa0, 0x11, 0x31, 0xc2, 0x27, 0x90, 0x20, 0xf6, 0x60, 0xff, 0x96, 0x5c,
        0xb1, 0xab, 0x9e, 0x9c, 0x52, 0x1b, 0x5f, 0x93, 0x0a, 0xef, 0x91, 0x85, 0x49, 0xee, 0x2d,
        0x4f, 0x8f, 0x3b, 0x47, 0x87, 0x6d, 0x46, 0xd6, 0x3e, 0x69, 0x64, 0x2a, 0xce, 0xcb, 0x2f,
        0xfc, 0x97, 0x05, 0x7a, 0xac, 0x7f, 0xd5, 0x1a, 0x4b, 0x0e, 0xa7, 0x5a, 0x28, 0x14, 0x3f,
        0x29, 0x88, 0x3c, 0x4c, 0x02, 0xb8, 0xda, 0xb0, 0x17, 0x55, 0x1f, 0x8a, 0x7d, 0x57, 0xc7,
        0x8d, 0x74, 0xb7, 0xc4, 0x9f, 0x72, 0x7e, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34, 0x6e,
        0x50, 0xde, 0x68, 0x65, 0xbc, 0xdb, 0xf8, 0xc8, 0xa8, 0x2b, 0x40, 0xdc, 0xfe, 0x32, 0xa4,
        0xca, 0x10, 0x21, 0xf0, 0xd3, 0x5d, 0x0f, 0x00, 0x6f, 0x9d, 0x36, 0x42, 0x4a, 0x5e, 0xc1,
        0xe0,
    ],
    [
        0x75, 0xf3, 0xc6, 0xf4, 0xdb, 0x7b, 0xfb, 0xc8, 0x4a, 0xd3, 0xe6, 0x6b, 0x45, 0x7d, 0xe8,
        0x4b, 0xd6, 0x32, 0xd8, 0xfd, 0x37, 0x71, 0xf1, 0xe1, 0x30, 0x0f, 0xf8, 0x1b, 0x87, 0xfa,
        0x06, 0x3f, 0x5e, 0xba, 0xae, 0x5b, 0x8a, 0x00, 0xbc, 0x9d, 0x6d, 0xc1, 0xb1, 0x0e, 0x80,
        0x5d, 0xd2, 0xd5, 0xa0, 0x84, 0x07, 0x14, 0xb5, 0x90, 0x2c, 0xa3, 0xb2, 0x73, 0x4c, 0x54,
        0x92, 0x74, 0x36, 0x51, 0x38, 0xb0, 0xbd, 0x5a, 0xfc, 0x60, 0x62, 0x96, 0x6c, 0x42, 0xf7,
        0x10, 0x7c, 0x28, 0x27, 0x8c, 0x13, 0x95, 0x9c, 0xc7, 0x24, 0x46, 0x3b, 0x70, 0xca, 0xe3,
        0x85, 0xcb, 0x11, 0xd0, 0x93, 0xb8, 0xa6, 0x83, 0x20, 0xff, 0x9f, 0x77, 0xc3, 0xcc, 0x03,
        0x6f, 0x08, 0xbf, 0x40, 0xe7, 0x2b, 0xe2, 0x79, 0x0c, 0xaa, 0x82, 0x41, 0x3a, 0xea, 0xb9,
        0xe4, 0x9a, 0xa4, 0x97, 0x7e, 0xda, 0x7a, 0x17, 0x66, 0x94, 0xa1, 0x1d, 0x3d, 0xf0, 0xde,
        0xb3, 0x0b, 0x72, 0xa7, 0x1c, 0xef, 0xd1, 0x53, 0x3e, 0x8f, 0x33, 0x26, 0x5f, 0xec, 0x76,
        0x2a, 0x49, 0x81, 0x88, 0xee, 0x21, 0xc4, 0x1a, 0xeb, 0xd9, 0xc5, 0x39, 0x99, 0xcd, 0xad,
        0x31, 0x8b, 0x01, 0x18, 0x23, 0xdd, 0x1f, 0x4e, 0x2d, 0xf9, 0x48, 0x4f, 0xf2, 0x65, 0x8e,
        0x78, 0x5c, 0x58, 0x19, 0x8d, 0xe5, 0x98, 0x57, 0x67, 0x7f, 0x05, 0x64, 0xaf, 0x63, 0xb6,
        0xfe, 0xf5, 0xb7, 0x3c, 0xa5, 0xce, 0xe9, 0x68, 0x44, 0xe0, 0x4d, 0x43, 0x69, 0x29, 0x2e,
        0xac, 0x15, 0x59, 0xa8, 0x0a, 0x9e, 0x6e, 0x47, 0xdf, 0x34, 0x35, 0x6a, 0xcf, 0xdc, 0x22,
        0xc9, 0xc0, 0x9b, 0x89, 0xd4, 0xed, 0xab, 0x12, 0xa2, 0x0d, 0x52, 0xbb, 0x02, 0x2f, 0xa9,
        0xd7, 0x61, 0x1e, 0xb4, 0x50, 0x04, 0xf6, 0xc2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xbe,
        0x91,
    ],
];

// gfMult returns a·b in GF(2^8)/p
fn gf_mult(a: u8, b: u8, p: u32) -> u8 {
    let mut b_table = [0, u32::from(b)];
    let p_table = [0, p];
    let mut result = 0u32;
    let mut a = a;

    // branchless GF multiplier
    for _ in 0..7 {
        result ^= b_table[(a & 1) as usize];
        a >>= 1;
        b_table[1] = p_table[(b_table[1] >> 7) as usize] ^ (b_table[1] << 1);
    }
    result ^= b_table[(a & 1) as usize];
    result as u8
}

// More accurate implementation of gf_mult
fn gf_mult_accurate(mut a: u8, b: u8, p: u32) -> u8 {
    let mut b_val = u32::from(b);
    let mut result = 0u32;

    for _ in 0..7 {
        if a & 1 != 0 {
            result ^= b_val;
        }
        a >>= 1;
        if b_val & 0x80 != 0 {
            b_val = (b_val << 1) ^ p;
        } else {
            b_val <<= 1;
        }
    }

    if a & 1 != 0 {
        result ^= b_val;
    }

    result as u8
}

// mdsColumnMult calculates y{col} where [y0 y1 y2 y3] = MDS · [x0]
fn mds_column_mult(input: u8, col: usize) -> u32 {
    let mul01 = u32::from(input);
    let mul5b = u32::from(gf_mult_accurate(input, 0x5B, MDS_POLYNOMIAL));
    let mulef = u32::from(gf_mult_accurate(input, 0xEF, MDS_POLYNOMIAL));

    match col {
        0 => mul01 | (mul5b << 8) | (mulef << 16) | (mulef << 24),
        1 => mulef | (mulef << 8) | (mul5b << 16) | (mul01 << 24),
        2 => mul5b | (mulef << 8) | (mul01 << 16) | (mulef << 24),
        3 => mul5b | (mul01 << 8) | (mulef << 16) | (mul5b << 24),
        _ => panic!("unreachable"),
    }
}

// h implements the S-box generation function. See [TWOFISH] 4.3.5
fn h(input: &[u8], key: &[u8], offset: usize) -> u32 {
    let mut y = [0u8; 4];
    for (i, &val) in input.iter().enumerate().take(4) {
        y[i] = val;
    }

    match key.len() / 8 {
        4 => {
            y[0] = SBOX[1][y[0] as usize] ^ key[4 * (6 + offset)];
            y[1] = SBOX[0][y[1] as usize] ^ key[4 * (6 + offset) + 1];
            y[2] = SBOX[0][y[2] as usize] ^ key[4 * (6 + offset) + 2];
            y[3] = SBOX[1][y[3] as usize] ^ key[4 * (6 + offset) + 3];
            // fallthrough
            y[0] = SBOX[1][y[0] as usize] ^ key[4 * (4 + offset)];
            y[1] = SBOX[1][y[1] as usize] ^ key[4 * (4 + offset) + 1];
            y[2] = SBOX[0][y[2] as usize] ^ key[4 * (4 + offset) + 2];
            y[3] = SBOX[0][y[3] as usize] ^ key[4 * (4 + offset) + 3];
            // fallthrough
            y[0] = SBOX[1][(SBOX[0][(SBOX[0][y[0] as usize] ^ key[4 * (2 + offset)]) as usize]
                ^ key[4 * offset]) as usize];
            y[1] = SBOX[0][(SBOX[0][(SBOX[1][y[1] as usize] ^ key[4 * (2 + offset) + 1]) as usize]
                ^ key[4 * offset + 1]) as usize];
            y[2] = SBOX[1][(SBOX[1][(SBOX[0][y[2] as usize] ^ key[4 * (2 + offset) + 2]) as usize]
                ^ key[4 * offset + 2]) as usize];
            y[3] = SBOX[0][(SBOX[1][(SBOX[1][y[3] as usize] ^ key[4 * (2 + offset) + 3]) as usize]
                ^ key[4 * offset + 3]) as usize];
        }
        3 => {
            y[0] = SBOX[1][y[0] as usize] ^ key[4 * (4 + offset)];
            y[1] = SBOX[1][y[1] as usize] ^ key[4 * (4 + offset) + 1];
            y[2] = SBOX[0][y[2] as usize] ^ key[4 * (4 + offset) + 2];
            y[3] = SBOX[0][y[3] as usize] ^ key[4 * (4 + offset) + 3];
            // fallthrough
            y[0] = SBOX[1][(SBOX[0][(SBOX[0][y[0] as usize] ^ key[4 * (2 + offset)]) as usize]
                ^ key[4 * offset]) as usize];
            y[1] = SBOX[0][(SBOX[0][(SBOX[1][y[1] as usize] ^ key[4 * (2 + offset) + 1]) as usize]
                ^ key[4 * offset + 1]) as usize];
            y[2] = SBOX[1][(SBOX[1][(SBOX[0][y[2] as usize] ^ key[4 * (2 + offset) + 2]) as usize]
                ^ key[4 * offset + 2]) as usize];
            y[3] = SBOX[0][(SBOX[1][(SBOX[1][y[3] as usize] ^ key[4 * (2 + offset) + 3]) as usize]
                ^ key[4 * offset + 3]) as usize];
        }
        2 => {
            y[0] = SBOX[1][(SBOX[0][(SBOX[0][y[0] as usize] ^ key[4 * (2 + offset)]) as usize]
                ^ key[4 * offset]) as usize];
            y[1] = SBOX[0][(SBOX[0][(SBOX[1][y[1] as usize] ^ key[4 * (2 + offset) + 1]) as usize]
                ^ key[4 * offset + 1]) as usize];
            y[2] = SBOX[1][(SBOX[1][(SBOX[0][y[2] as usize] ^ key[4 * (2 + offset) + 2]) as usize]
                ^ key[4 * offset + 2]) as usize];
            y[3] = SBOX[0][(SBOX[1][(SBOX[1][y[3] as usize] ^ key[4 * (2 + offset) + 3]) as usize]
                ^ key[4 * offset + 3]) as usize];
        }
        _ => {}
    }

    // [y0 y1 y2 y3] = MDS . [x0 x1 x2 x3]
    let mut mds_mult = 0u32;
    for (i, &y_val) in y.iter().enumerate() {
        mds_mult ^= mds_column_mult(y_val, i);
    }
    mds_mult
}

// SHA512 block step.
// In its own file so that a faster assembly or C version
// can be substituted easily.

use super::*;
use crate::error::CryptoResult;

/// SHA512 round constants
const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// SHA512 block size in bytes
const CHUNK: usize = 128;

/// Generic SHA512 block processing function
pub fn block_generic<const N: usize>(dig: &mut Sha512<N>, mut p: &[u8]) -> CryptoResult<()> {
    let mut w = [0u64; 80];
    let mut h0 = dig.h[0];
    let mut h1 = dig.h[1];
    let mut h2 = dig.h[2];
    let mut h3 = dig.h[3];
    let mut h4 = dig.h[4];
    let mut h5 = dig.h[5];
    let mut h6 = dig.h[6];
    let mut h7 = dig.h[7];

    while p.len() >= CHUNK {
        // Parse the first 16 words from the input
        (0..16).for_each(|i| {
            let j = i * 8;
            w[i] = ((p[j] as u64) << 56)
                | ((p[j + 1] as u64) << 48)
                | ((p[j + 2] as u64) << 40)
                | ((p[j + 3] as u64) << 32)
                | ((p[j + 4] as u64) << 24)
                | ((p[j + 5] as u64) << 16)
                | ((p[j + 6] as u64) << 8)
                | (p[j + 7] as u64);
        });

        // Extend the first 16 words into the remaining 64 words
        for i in 16..80 {
            let v1 = w[i - 2];
            let t1 = v1.rotate_right(19) ^ v1.rotate_right(61) ^ (v1 >> 6);
            let v2 = w[i - 15];
            let t2 = v2.rotate_right(1) ^ v2.rotate_right(8) ^ (v2 >> 7);

            w[i] = t1
                .wrapping_add(w[i - 7])
                .wrapping_add(t2)
                .wrapping_add(w[i - 16]);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;

        // Main compression loop
        for i in 0..80 {
            let t1 = h
                .wrapping_add(e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41))
                .wrapping_add((e & f) ^ (!e & g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);

            let t2 = (a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39))
                .wrapping_add((a & b) ^ (a & c) ^ (b & c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);

        p = &p[CHUNK..];
    }

    dig.h[0] = h0;
    dig.h[1] = h1;
    dig.h[2] = h2;
    dig.h[3] = h3;
    dig.h[4] = h4;
    dig.h[5] = h5;
    dig.h[6] = h6;
    dig.h[7] = h7;

    Ok(())
}

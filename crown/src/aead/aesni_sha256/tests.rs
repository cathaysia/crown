//! Tests for aesni_cbc_sha256_enc vs software AES-CBC + SHA-256.
#![cfg(all(feature = "asm", target_arch = "x86_64"))]

use super::*;
use crate::block::aes::aesni;

/// Portable SHA-256 compression (FIPS 180-4) used as the test oracle.
fn sha256_compress(h: &mut [u32; 8], block: &[u8]) {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
        (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// SHA-256 of `data` using the portable compression as oracle.
fn sha256_portable(data: &[u8]) -> [u32; 8] {
    let mut h = SHA256_IV;
    for chunk in data.chunks(64) {
        if chunk.len() == 64 {
            sha256_compress(&mut h, chunk);
        } else {
            let mut last = [0u8; 128];
            last[..chunk.len()].copy_from_slice(chunk);
            last[chunk.len()] = 0x80;
            let bitlen = (data.len() as u64) * 8;
            let n = if chunk.len() < 56 { 64 } else { 128 };
            last[n - 8..].copy_from_slice(&bitlen.to_be_bytes());
            sha256_compress(&mut h, &last[..64]);
            if n == 128 {
                sha256_compress(&mut h, &last[64..]);
            }
        }
    }
    h
}

fn prf(seed: &mut u64) -> u8 {
    *seed = seed
        .wrapping_mul(0x9e3779b97f4a7c15)
        .wrapping_add(0x165667b19e3779f9);
    (*seed >> 24) as u8
}

#[test]
fn cbc_sha256_enc_matches_software() {
    if !aesni::supported() {
        return;
    }
    let mut seed = 0xae51u64 ^ 0x256;
    for &nblocks in &[1usize, 2, 3, 5, 8] {
        let len = nblocks * 64;
        let key_bytes: [u8; 16] = core::array::from_fn(|_| prf(&mut seed));
        let mut iv0 = [0u8; 16];
        for b in iv0.iter_mut() {
            *b = prf(&mut seed);
        }
        let inp: alloc::vec::Vec<u8> = (0..len).map(|_| prf(&mut seed)).collect();

        let key = aesni::set_encrypt_key(&key_bytes);

        // stitched path
        let mut out = alloc::vec![0u8; len];
        let mut iv = iv0;
        let mut ctx = SHA256_IV;
        cbc_sha256_enc(&inp, &mut out, &key, &mut iv, &mut ctx);

        // software AES-CBC oracle (same key schedule)
        let mut expect_ct = inp.clone();
        let mut iv2 = iv0;
        aesni::cbc_encrypt(&mut expect_ct, &key, &mut iv2, true);
        assert_eq!(out, expect_ct, "CBC mismatch for {nblocks} blocks");
        assert_eq!(iv, iv2, "IV mismatch for {nblocks} blocks");

        // portable SHA-256 compression oracle (length counters excluded)
        let mut expect_h = SHA256_IV;
        for chunk in inp.chunks(64) {
            sha256_compress(&mut expect_h, chunk);
        }
        assert_eq!(ctx, expect_h, "SHA-256 state mismatch for {nblocks} blocks");
    }
}

#[test]
fn cbc_sha256_enc_matches_full_sha256_digest() {
    if !aesni::supported() {
        return;
    }
    // 3 blocks of message; verify the stitched state equals the state
    // implied by the full SHA-256 digest path.
    let mut seed = 0x5eedu64;
    let len = 3 * 64;
    let key_bytes: [u8; 16] = core::array::from_fn(|_| prf(&mut seed));
    let mut iv = [0u8; 16];
    for b in iv.iter_mut() {
        *b = prf(&mut seed);
    }
    let inp: alloc::vec::Vec<u8> = (0..len).map(|_| prf(&mut seed)).collect();
    let key = aesni::set_encrypt_key(&key_bytes);
    let mut out = alloc::vec![0u8; len];
    let mut ctx = SHA256_IV;
    cbc_sha256_enc(&inp, &mut out, &key, &mut iv, &mut ctx);
    assert_eq!(ctx, sha256_portable(&inp));
}

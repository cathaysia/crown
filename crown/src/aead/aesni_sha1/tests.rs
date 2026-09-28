//! Tests for aesni_cbc_sha1_enc vs software AES-CBC + SHA-1.
#![cfg(all(feature = "asm", target_arch = "x86_64"))]

use super::*;
use crate::block::aes::aesni;

/// Portable SHA-1 compression (FIPS 180-4) used as the test oracle.
fn sha1_compress(h: &mut [u32; 5], block: &[u8]) {
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
    for i in 0..80 {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5a827999),
            20..=39 => (b ^ c ^ d, 0x6ed9eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
            _ => (b ^ c ^ d, 0xca62c1d6),
        };
        let t = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
}

/// SHA-1 of `data` using the portable compression as oracle.
fn sha1_portable(data: &[u8]) -> [u32; 5] {
    let mut h = SHA1_IV;
    for chunk in data.chunks(64) {
        if chunk.len() == 64 {
            sha1_compress(&mut h, chunk);
        } else {
            let mut last = [0u8; 128];
            last[..chunk.len()].copy_from_slice(chunk);
            last[chunk.len()] = 0x80;
            let bitlen = (data.len() as u64) * 8;
            let n = if chunk.len() < 56 { 64 } else { 128 };
            last[n - 8..].copy_from_slice(&bitlen.to_be_bytes());
            sha1_compress(&mut h, &last[..64]);
            if n == 128 {
                sha1_compress(&mut h, &last[64..]);
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
fn cbc_sha1_enc_matches_software() {
    if !aesni::supported() {
        return;
    }
    let mut seed = 0xae51u64 ^ 0x1234;
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
        let mut ctx = SHA1_IV;
        cbc_sha1_enc(&inp, &mut out, &key, &mut iv, &mut ctx);

        // software AES-CBC oracle (same key schedule)
        let mut expect_ct = inp.clone();
        let mut iv2 = iv0;
        aesni::cbc_encrypt(&mut expect_ct, &key, &mut iv2, true);
        assert_eq!(out, expect_ct, "CBC mismatch for {nblocks} blocks");
        assert_eq!(iv, iv2, "IV mismatch for {nblocks} blocks");

        // portable SHA-1 compression oracle (length counters excluded)
        let mut expect_h = SHA1_IV;
        for chunk in inp.chunks(64) {
            sha1_compress(&mut expect_h, chunk);
        }
        assert_eq!(ctx, expect_h, "SHA-1 state mismatch for {nblocks} blocks");
    }
}

#[test]
fn cbc_sha1_enc_matches_full_sha1_digest() {
    if !aesni::supported() {
        return;
    }
    // 3 blocks of message; verify the stitched state equals the state
    // implied by the full SHA-1 digest path.
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
    let mut ctx = SHA1_IV;
    cbc_sha1_enc(&inp, &mut out, &key, &mut iv, &mut ctx);
    assert_eq!(ctx, sha1_portable(&inp));
}

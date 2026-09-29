//! Stitched AES-NI CBC + SHA-256 (`aesni-sha256-x86_64.pl`) for x86_64.
//!
//! OpenSSL's `crypto/aes/asm/aesni-sha256-x86_64.pl` provides
//! `aesni_cbc_sha256_enc`, which interleaves AES-CBC encryption with SHA-256
//! message expansion — the kernel of the TLS `AES-CBC-HMAC-SHA256` stitched
//! AEAD.
//!
//! C ABI:
//!
//! ```text
//! void aesni_cbc_sha256_enc(const void *inp, void *out, size_t blocks,
//!                           AES_KEY *key, unsigned char iv[16],
//!                           SHA256_CTX *ctx, const void *in0);
//! ```
//!
//! `blocks` counts **64-byte** chunks. Only `ctx->h[0..7]` is updated
//! (the caller owns the length counters and final padding).
//!
//! The AVX stitched body is wired via `global_asm!` when the `asm`
//! feature is enabled. shaext/xop/avx2 tiers are not ported yet (see
//! `NOTES.md`); the dispatcher routes to the AVX body.

#![allow(dead_code, unused_imports)]
use crate::block::aes::aesni::AesKey;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/aead/aesni_sha256/x86_64.ts"),
    options(att_syntax)
);

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
extern "C" {
    fn aesni_cbc_sha256_enc(
        inp: *const u8,
        out: *mut u8,
        blocks: usize,
        key: *const u8,
        iv: *mut u8,
        ctx: *mut u32,
        in0: *const u8,
    );
}

/// SHA-256 chaining value length (the only part of `SHA256_CTX` the asm touches).
pub const SHA256_STATE_WORDS: usize = 8;

/// SHA-256 initialization vector (FIPS 180-4).
pub const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_compress(h: &mut [u32; 8], block: &[u8]) {
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
        let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
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

/// AES-CBC encrypt `inp` into `out` while folding each 64-byte chunk of the
/// **plaintext** into the SHA-256 state `ctx` (8 words).
///
/// `inp.len()` must be a non-zero multiple of 64 and `out.len() >= inp.len()`.
/// `iv` is updated in place to the final CBC IV. `ctx` is updated with the
/// SHA-256 compression of `inp` (length counters are **not** touched — the
/// caller adds `8 * inp.len()` bits). This matches `aesni_cbc_sha256_enc`.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn cbc_sha256_enc(
    inp: &[u8],
    out: &mut [u8],
    key: &AesKey,
    iv: &mut [u8; 16],
    ctx: &mut [u32; SHA256_STATE_WORDS],
) {
    let blocks = inp.len() / 64;
    assert!(blocks > 0 && inp.len().is_multiple_of(64), "len must be a positive multiple of 64");
    assert!(out.len() >= inp.len());
    unsafe {
        aesni_cbc_sha256_enc(
            inp.as_ptr(),
            out.as_mut_ptr(),
            blocks,
            key as *const AesKey as *const u8,
            iv.as_mut_ptr(),
            ctx.as_mut_ptr(),
            inp.as_ptr(),
        );
    }
}

#[cfg(not(all(feature = "asm", target_arch = "x86_64")))]
pub fn cbc_sha256_enc(
    inp: &[u8],
    out: &mut [u8],
    key: &AesKey,
    iv: &mut [u8; 16],
    ctx: &mut [u32; SHA256_STATE_WORDS],
) {
    let blocks = inp.len() / 64;
    assert!(blocks > 0 && inp.len().is_multiple_of(64), "len must be a positive multiple of 64");
    assert!(out.len() >= inp.len());
    out[..inp.len()].copy_from_slice(inp);
    crate::block::aes::aesni::cbc_encrypt(&mut out[..inp.len()], key, iv, true);
    for chunk in inp.chunks(64) {
        sha256_compress(ctx, chunk);
    }
}

#[cfg(test)]
mod tests;

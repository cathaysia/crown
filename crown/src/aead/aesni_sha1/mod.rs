//! Stitched AES-NI CBC + SHA-1 (`aesni-sha1-x86_64.pl`) for x86_64.
//!
//! OpenSSL's `crypto/aes/asm/aesni-sha1-x86_64.pl` provides
//! `aesni_cbc_sha1_enc`, which interleaves AES-CBC encryption with SHA-1
//! message expansion across the execution pipeline — the kernel of the TLS
//! `AES-CBC-HMAC-SHA1` stitched AEAD (`e_aes_cbc_hmac_sha1.c`).
//!
//! C ABI (`$win64=0`, unix SysV; 7th argument on the stack):
//!
//! ```text
//! void aesni_cbc_sha1_enc(const void *inp, void *out, size_t blocks,
//!                         const AES_KEY *key, unsigned char iv[16],
//!                         SHA_CTX *ctx, const void *in0);
//! ```
//!
//! - `blocks` counts **64-byte** chunks. Each chunk is AES-CBC-encrypted
//!   (4 AES blocks) and folded into `ctx->h[0..4]` as SHA-1 input.
//! - `in0` is the base pointer used for relative output addressing
//!   (`out` may alias `inp`; pass `in0 == inp` for the common case).
//! - Only `ctx->h[0..4]` is updated. The caller is responsible for the
//!   SHA-1 length counters (`Nl`/`Nh`) and the final padding — matching
//!   the OpenSSL TLS caller.
//!
//! Dispatch (inside the asm): SHA-NI if `OPENSSL_ia32cap_P` bit 61, else
//! AVX if the AVX+Intel bits match, else SSSE3. All three paths are
//! semantically identical.
//!
//! See `NOTES.md` for config pins and re-verification.

use crate::block::aes::aesni::AesKey;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/aead/aesni_sha1/x86_64.ts"),
    options(att_syntax)
);

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
extern "C" {
    fn aesni_cbc_sha1_enc(
        inp: *const u8,
        out: *mut u8,
        blocks: usize,
        key: *const AesKey,
        iv: *mut u8,
        ctx: *mut u32,
        in0: *const u8,
    );
}

/// SHA-1 chaining value length (the only part of `SHA_CTX` the asm touches).
pub const SHA1_STATE_WORDS: usize = 5;

/// SHA-1 initialization vector (FIPS 180-4).
pub const SHA1_IV: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// AES-CBC encrypt `inp` into `out` while folding each 64-byte chunk of
/// `hash_inp` into the SHA-1 state `ctx` (5 words).
///
/// `inp.len()` must be a non-zero multiple of 64 and `out.len() >= inp.len()`;
/// `hash_inp.len()` must equal `inp.len()` and may differ from `inp` — the
/// OpenSSL TLS caller hashes `in + iv + sha_off` while CBC-encrypting the
/// record from its start. `iv` is updated in place to the final CBC IV.
/// `ctx` is updated with the SHA-1 compression of `hash_inp` (length
/// counters are **not** touched — the caller adds `8 * inp.len()` bits).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn cbc_sha1_enc(
    inp: &[u8],
    hash_inp: &[u8],
    out: &mut [u8],
    key: &AesKey,
    iv: &mut [u8; 16],
    ctx: &mut [u32; SHA1_STATE_WORDS],
) {
    let blocks = inp.len() / 64;
    assert!(
        blocks > 0 && inp.len().is_multiple_of(64),
        "len must be a positive multiple of 64"
    );
    assert!(out.len() >= inp.len());
    assert_eq!(hash_inp.len(), inp.len());
    unsafe {
        aesni_cbc_sha1_enc(
            inp.as_ptr(),
            out.as_mut_ptr(),
            blocks,
            key,
            iv.as_mut_ptr(),
            ctx.as_mut_ptr(),
            hash_inp.as_ptr(),
        );
    }
}

#[cfg(test)]
mod tests;

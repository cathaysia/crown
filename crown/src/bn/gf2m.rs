//! GF(2^m) polynomial multiplication helpers (`x86_64-gf2m.pl`) for x86_64.
//!
//! OpenSSL's `crypto/bn/asm/x86_64-gf2m.pl` provides `bn_GF2m_mul_2x2`, the
//! carry-less product of two degree-1 polynomials over GF(2)[x] used by
//! `crypto/bn/bn_gf2m.c` in the binary-curve (sect* / FRP / custom
//! `BN_GF2m_*`) paths. The routine has two implementations picked at
//! runtime from `OPENSSL_ia32cap_P` bit 33 (PCLMULQDQ): a Westmere+
//! carry-less path and a portable integer table path.
//!
//! C ABI (`$win64=0`, unix SysV):
//!
//! ```text
//! void bn_GF2m_mul_2x2(BN_ULONG r[4], BN_ULONG a1, BN_ULONG a0,
//!                      BN_ULONG b1, BN_ULONG b0);
//! ```
//!
//! Computes `(a1·x^64 + a0)·(b1·x^64 + b0)` over GF(2)[x] and stores the
//! 256-bit polynomial in `r[0..4]` (little-endian 64-bit limbs:
//! `r[0] + r[1]·x^64 + r[2]·x^128 + r[3]·x^192`).
//!
//! There is no crown-side consumer yet (crown's EC is prime-field only);
//! the primitive is exported and unit-tested against a portable
//! shift-and-xor reference. See `gf2m/NOTES.md` for config pins and
//! re-verification.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/bn/gf2m_x86_64.ts"),
    options(att_syntax)
);

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
extern "C" {
    fn bn_GF2m_mul_2x2(r: *mut u64, a1: u64, a0: u64, b1: u64, b0: u64);
}

/// `r = (a1·x^64 + a0)·(b1·x^64 + b0)` over GF(2)[x].
///
/// `r` must have room for 4 limbs. The PCLMULQDQ path is chosen at
/// runtime from `OPENSSL_ia32cap_P` bit 33; both paths are semantically
/// identical.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn mul_2x2(r: &mut [u64; 4], a1: u64, a0: u64, b1: u64, b0: u64) {
    unsafe {
        bn_GF2m_mul_2x2(r.as_mut_ptr(), a1, a0, b1, b0);
    }
}

/// Portable reference: carry-less 64x64 -> 128 product over GF(2)[x].
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
#[cfg(test)]
pub(crate) fn poly_mul64(a: u64, b: u64) -> [u64; 2] {
    let mut r0 = 0u64;
    let mut r1 = 0u64;
    for i in 0..64 {
        if (b >> i) & 1 == 1 {
            if i == 0 {
                r0 ^= a;
            } else {
                r0 ^= a << i;
                r1 ^= a >> (64 - i);
            }
        }
    }
    [r0, r1]
}

/// Portable reference for [`mul_2x2`].
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
#[cfg(test)]
pub(crate) fn poly_mul2x2(a1: u64, a0: u64, b1: u64, b0: u64) -> [u64; 4] {
    let p00 = poly_mul64(a0, b0);
    let p11 = poly_mul64(a1, b1);
    let p01 = poly_mul64(a0, b1);
    let p10 = poly_mul64(a1, b0);
    [
        p00[0],
        p00[1] ^ p01[0] ^ p10[0],
        p11[0] ^ p01[1] ^ p10[1],
        p11[1],
    ]
}

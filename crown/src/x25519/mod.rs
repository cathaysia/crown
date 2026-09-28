//! X25519 Diffie-Hellman (RFC 7748), ported from OpenSSL's
//! `crypto/ec/curve25519.c` (`x25519_scalar_mult` / `X25519_public_from_private`).
//!
//! Montgomery ladder over radix-2^64 field arithmetic ([`fe64`]). With the
//! `asm` feature the hot operations dispatch to the x25519-x86_64.pl helpers
//! (`x25519_fe64_*`); the ladder itself is the constant-time bit loop from
//! the reference implementation.

mod fe64;

use fe64::{add, cswap, from_bytes, invert, mul, mul121666, sq, sub, to_bytes, Fe64};

pub const PUBLIC_KEY_SIZE: usize = 32;
pub const PRIVATE_KEY_SIZE: usize = 32;
pub const SHARED_SECRET_SIZE: usize = 32;

/// Curve25519 base point `u = 9`.
const BASE_POINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// Clamp a private scalar as specified by RFC 7748 / OpenSSL
/// (`e[0] &= 248; e[31] &= 127; e[31] |= 64`).
fn clamp(scalar: &mut [u8; 32]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

/// Montgomery ladder: `out = scalar * u` on Curve25519.
///
/// This is the Coq-verified ladder from
/// `x25519_scalar_mult_generic_nohw` (AWS-LC / OpenSSL).
fn scalar_mult(out: &mut [u8; 32], scalar: &[u8; 32], u: &[u8; 32]) {
    let mut e = *scalar;
    clamp(&mut e);

    let x1 = from_bytes(u);
    let mut x2: Fe64 = [1, 0, 0, 0];
    let mut z2 = [0u64; 4];
    let mut x3 = x1;
    let mut z3: Fe64 = [1, 0, 0, 0];

    let mut swap = 0u64;
    for pos in (0..=254).rev() {
        let b = ((e[pos / 8] >> (pos & 7)) & 1) as u64;
        swap ^= b;
        cswap(&mut x2, &mut x3, swap);
        cswap(&mut z2, &mut z3, swap);
        swap = b;

        // ladderstep
        let tmp0 = sub(&x3, &z3);
        let tmp1 = sub(&x2, &z2);
        let x2l = add(&x2, &z2);
        let z2l = add(&x3, &z3);
        let mut z3n = mul(&tmp0, &x2l);
        let mut z2n = mul(&z2l, &tmp1);
        let tmp0 = sq(&tmp1);
        let tmp1 = sq(&x2l);
        let x3l = add(&z3n, &z2n);
        z2n = sub(&z3n, &z2n);
        x2 = mul(&tmp1, &tmp0);
        let tmp1l = sub(&tmp1, &tmp0);
        z2 = sq(&z2n);
        z3n = mul121666(&tmp1l);
        x3 = sq(&x3l);
        let tmp0l = add(&tmp0, &z3n);
        z3 = mul(&x1, &z2);
        z2 = mul(&tmp1l, &tmp0l);
    }
    cswap(&mut x2, &mut x3, swap);
    cswap(&mut z2, &mut z3, swap);

    let z2inv = invert(&z2);
    let out_fe = mul(&x2, &z2inv);
    *out = to_bytes(&out_fe);

    // scrub the clamped scalar
    for b in e.iter_mut() {
        *b = 0;
    }
}

/// Derive the X25519 public value from a 32-byte private scalar:
/// `X25519(private, 9)`.
pub fn public_from_private(private: &[u8; PRIVATE_KEY_SIZE]) -> [u8; PUBLIC_KEY_SIZE] {
    let mut out = [0u8; 32];
    scalar_mult(&mut out, private, &BASE_POINT);
    out
}

/// X25519 key agreement. Returns `None` when the shared secret is all
/// zeros (low-order peer point), matching OpenSSL's `X25519()`.
pub fn x25519(
    private: &[u8; PRIVATE_KEY_SIZE],
    peer_public: &[u8; PUBLIC_KEY_SIZE],
) -> Option<[u8; SHARED_SECRET_SIZE]> {
    let mut out = [0u8; SHARED_SECRET_SIZE];
    scalar_mult(&mut out, private, peer_public);
    if out.iter().all(|&b| b == 0) {
        return None;
    }
    Some(out)
}

/// Generate a random private/public pair. The caller supplies the RNG
/// (crown has no ambient `RAND`); the 32-byte seed is clamped before use
/// as usual.
pub fn keypair(
    rng: &mut impl crate::rsa::Rng,
) -> ([u8; PRIVATE_KEY_SIZE], [u8; PUBLIC_KEY_SIZE]) {
    let mut private = [0u8; PRIVATE_KEY_SIZE];
    rng.fill_bytes(&mut private);
    let public = public_from_private(&private);
    (private, public)
}

#[cfg(test)]
mod tests;

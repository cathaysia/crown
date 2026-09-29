//! X448 Diffie-Hellman (RFC 7748 §5), software only.
//!
//! Montgomery ladder over the shared radix-2^56 field ([`crate::curve448::fe`]),
//! shaped after [`crate::x25519`]. Scalars are clamped with
//! `k[0] &= 252; k[55] |= 128` and the ladder runs 448 bit steps.

#![allow(dead_code)]
use crate::curve448::fe;

pub const PUBLIC_KEY_SIZE: usize = 56;
pub const PRIVATE_KEY_SIZE: usize = 56;
pub const SHARED_SECRET_SIZE: usize = 56;

/// Curve448 base point `u = 5`.
const BASE_POINT: [u8; 56] = {
    let mut b = [0u8; 56];
    b[0] = 5;
    b
};

/// a24 = (A - 2) / 4 = 39081 for the Montgomery curve `y^2 = x^3 + A x^2 + x`
/// with A = 156326 (RFC 7748 §4.2).
const A24: u32 = 39081;

/// Clamp a private scalar as specified by RFC 7748 §5
/// (`e[0] &= 252; e[55] |= 128`).
fn clamp(scalar: &mut [u8; 56]) {
    scalar[0] &= 252;
    scalar[55] |= 128;
}

/// Montgomery ladder: `out = scalar * u` on Curve448.
///
/// Mirrors the RFC 7748 §5 pseudocode: a bit loop over `t = 447..=0`
/// with conditional swaps and the classic differential ladder step.
fn scalar_mult(out: &mut [u8; 56], scalar: &[u8; 56], u: &[u8; 56]) {
    let mut e = *scalar;
    clamp(&mut e);

    let x1 = fe::from_bytes(u);
    let mut x2 = fe::ONE;
    let mut z2 = fe::ZERO;
    let mut x3 = x1;
    let mut z3 = fe::ONE;

    let mut swap = 0u64;
    for pos in (0..=447).rev() {
        let b = ((e[pos / 8] >> (pos & 7)) & 1) as u64;
        swap ^= b;
        fe::cswap(&mut x2, &mut x3, swap);
        fe::cswap(&mut z2, &mut z3, swap);
        swap = b;

        // RFC 7748 §5 ladder step.
        let a = fe::add(&x2, &z2);
        let aa = fe::sq(&a);
        let bv = fe::sub(&x2, &z2);
        let bb = fe::sq(&bv);
        let e_ = fe::sub(&aa, &bb);
        let c = fe::add(&x3, &z3);
        let d = fe::sub(&x3, &z3);
        let da = fe::mul(&d, &a);
        let cb = fe::mul(&c, &bv);
        let x3n = fe::sq(&fe::add(&da, &cb));
        let z3n = fe::mul(&x1, &fe::sq(&fe::sub(&da, &cb)));
        let x2n = fe::mul(&aa, &bb);
        // z2' = E * (AA + a24 * E)
        let z2n = fe::mul(&e_, &fe::add(&aa, &fe::mul_small(&e_, A24)));

        x2 = x2n;
        z2 = z2n;
        x3 = x3n;
        z3 = z3n;
    }
    fe::cswap(&mut x2, &mut x3, swap);
    fe::cswap(&mut z2, &mut z3, swap);

    let z2inv = fe::invert(&z2);
    *out = fe::to_bytes(&fe::mul(&x2, &z2inv));

    // scrub the clamped scalar
    for b in e.iter_mut() {
        *b = 0;
    }
}

/// Derive the X448 public value from a 56-byte private scalar:
/// `X448(private, 5)`.
pub fn public_from_private(private: &[u8; PRIVATE_KEY_SIZE]) -> [u8; PUBLIC_KEY_SIZE] {
    let mut out = [0u8; 56];
    scalar_mult(&mut out, private, &BASE_POINT);
    out
}

/// X448 key agreement. Returns `None` when the shared secret is all
/// zeros (low-order peer point), matching OpenSSL's `X448()`.
pub fn x448(
    private: &[u8; PRIVATE_KEY_SIZE],
    peer_public: &[u8; PUBLIC_KEY_SIZE],
) -> Option<[u8; SHARED_SECRET_SIZE]> {
    let mut out = [0u8; 56];
    scalar_mult(&mut out, private, peer_public);
    if out.iter().all(|&b| b == 0) {
        return None;
    }
    Some(out)
}

/// Generate a random private/public pair. The caller supplies the RNG
/// (crown has no ambient `RAND`).
pub fn keypair(
    rng: &mut impl crate::rng::Rng,
) -> ([u8; PRIVATE_KEY_SIZE], [u8; PUBLIC_KEY_SIZE]) {
    let mut private = [0u8; PRIVATE_KEY_SIZE];
    rng.fill_bytes(&mut private);
    let public = public_from_private(&private);
    (private, public)
}

#[cfg(test)]
mod tests;

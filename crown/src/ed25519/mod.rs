//! Ed25519 digital signatures (RFC 8032), ported from OpenSSL's
//! ed25519 operations in `crypto/ec/curve25519.c`
//! (`ossl_ed25519_sign`/`ossl_ed25519_verify`).
//!
//! Pure Ed25519 only: the DOM2/PH/context variants (ed25519ph, context
//! strings) are not exposed, matching the `dom2flag = 0` default.
//!
//! Keys are 32-byte little-endian scalars/encodings and signatures are the
//! concatenated encoding of `R` and `S` (64 bytes). Verification rejects
//! non-canonical `S >= L` and undecodable public keys, like OpenSSL.

#[cfg(test)]
mod tests;

mod fe;
mod ge;
mod sc;

use crate::core::CoreWrite;
use crate::hash::sha512::new512;
use crate::hash::Hash;

pub const SIGNATURE_SIZE: usize = 64;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SECRET_KEY_SIZE: usize = 32;

fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = new512();
    for part in parts {
        h.write_all(part).expect("hash write cannot fail");
    }
    h.sum()
}

/// Clamp the first half of the SHA-512 of the secret key into the scalar.
fn clamp_az(az: &mut [u8; 32]) {
    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;
}

/// Derive the public key from the 32-byte secret seed:
/// `A = [clamp(SHA512(seed)[0..32])]B`.
pub fn public_from_secret(secret: &[u8; SECRET_KEY_SIZE]) -> [u8; PUBLIC_KEY_SIZE] {
    let hash = sha512(&[secret]);
    let mut a = [0u8; 32];
    a.copy_from_slice(&hash[..32]);
    clamp_az(&mut a);
    ge::to_bytes(&ge::scalarmult_base(&a))
}

/// Sign `msg` with the 32-byte secret seed. Returns the 64-byte
/// `R || S` signature.
pub fn sign(secret: &[u8; SECRET_KEY_SIZE], msg: &[u8]) -> [u8; SIGNATURE_SIZE] {
    let hash = sha512(&[secret]);
    let mut az = [0u8; 32];
    az.copy_from_slice(&hash[..32]);
    clamp_az(&mut az);

    let public = ge::to_bytes(&ge::scalarmult_base(&az));

    // r = H(az[32..] || msg) mod L
    let nonce = sha512(&[&hash[32..64], msg]);
    let r = sc::reduce_wide(&nonce);
    let r_bytes = ge::to_bytes(&ge::scalarmult_base(&r));

    // S = (r + H(R || A || msg) * a) mod L
    let hram = sha512(&[&r_bytes, &public, msg]);
    let k = sc::reduce_wide(&hram);
    let s = sc::muladd(&k, &az, &r);

    let mut sig = [0u8; SIGNATURE_SIZE];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(&s);
    sig
}

/// Verify `sig` over `msg` with the 32-byte compressed public key.
pub fn verify(public: &[u8; PUBLIC_KEY_SIZE], sig: &[u8; SIGNATURE_SIZE], msg: &[u8]) -> bool {
    if !sc::is_canonical(sig[32..].try_into().unwrap()) {
        return false;
    }
    let a_point = match ge::from_bytes(public) {
        Some(a) => a,
        None => return false,
    };
    // Negate A so the sum [S]B + [-k]A can reuse the ladder.
    let neg_a = ge::P3 {
        x: fe::neg(&a_point.x),
        y: a_point.y,
        z: a_point.z,
        t: fe::neg(&a_point.t),
    };

    // k = H(R || A || msg) mod L
    let h = sha512(&[&sig[..32], public, msg]);
    let k = sc::reduce_wide(&h);

    let s = sig[32..].try_into().unwrap();
    let r_check = ge::add(&ge::scalarmult_base(s), &ge::scalarmult(&neg_a, &k));
    let r_bytes = ge::to_bytes(&r_check);

    // Constant-time compare of R and sig[..32].
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= r_bytes[i] ^ sig[i];
    }
    diff == 0
}

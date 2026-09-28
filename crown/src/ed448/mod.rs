//! Ed448 digital signatures (RFC 8032 §5.2), software only.
//!
//! Pure Ed448 (phflag = 0) with a required context string (possibly
//! empty), the `dom4` domain prefix, SHAKE256 hashing, and the
//! edwards448 group from [`ge`]. Signatures are 114 bytes (`R || S`
//! with 57 bytes each); public keys and secret seeds are 57 bytes.

#[cfg(test)]
mod tests;

mod ge;
mod sc;

use crate::core::{CoreRead, CoreWrite};
use crate::hash::sha3::new_shake256;

pub const SIGNATURE_SIZE: usize = 114;
pub const PUBLIC_KEY_SIZE: usize = 57;
pub const SECRET_KEY_SIZE: usize = 57;

/// Maximum context length accepted by RFC 8032 §5.2.
pub const MAX_CONTEXT_SIZE: usize = 255;

/// SHAKE256 over the concatenation of `parts`, squeezed to 114 bytes.
fn shake256(parts: &[&[u8]]) -> [u8; 114] {
    let mut h = new_shake256();
    for part in parts {
        h.write_all(part).expect("hash write cannot fail");
    }
    let mut out = [0u8; 114];
    h.read_exact(&mut out).expect("shake read cannot fail");
    out
}

/// The middle two bytes of `dom4(0, context)`: the phflag octet `0`
/// and the one-octet context length (RFC 8032 §5.2).
fn dom4_len_byte(context: &[u8]) -> [u8; 2] {
    [0, context.len() as u8]
}

/// Clamp the first 57 bytes of the SHAKE256 of the secret seed into the
/// scalar (RFC 8032 §5.2.5 step 2): clear the two least significant
/// bits of the first octet, clear all eight bits of the last octet, set
/// the highest bit of the second-to-last octet.
fn clamp_s(s: &mut [u8; 57]) {
    s[0] &= 0xfc;
    s[55] |= 0x80;
    s[56] = 0;
}

/// Expand the 57-byte secret seed into the clamped scalar `s` and the
/// 57-byte `prefix` (the second half of SHAKE256(seed, 114)).
fn expand_seed(secret: &[u8; SECRET_KEY_SIZE]) -> ([u8; 57], [u8; 57]) {
    let hash = shake256(&[secret]);
    let mut s = [0u8; 57];
    s.copy_from_slice(&hash[..57]);
    clamp_s(&mut s);
    let mut prefix = [0u8; 57];
    prefix.copy_from_slice(&hash[57..114]);
    (s, prefix)
}

/// Derive the public key from the 57-byte secret seed:
/// `A = [clamp(SHAKE256(seed, 114)[0..57])]B`.
pub fn public_from_secret(secret: &[u8; SECRET_KEY_SIZE]) -> [u8; PUBLIC_KEY_SIZE] {
    let (s, _) = expand_seed(secret);
    ge::to_bytes(&ge::scalarmult_base(&s))
}

/// Sign `msg` with the 57-byte secret seed under `context` (at most
/// 255 octets, may be empty). Returns the 114-byte `R || S` signature.
pub fn sign(
    secret: &[u8; SECRET_KEY_SIZE],
    msg: &[u8],
    context: &[u8],
) -> [u8; SIGNATURE_SIZE] {
    assert!(
        context.len() <= MAX_CONTEXT_SIZE,
        "Ed448 context must be at most 255 octets"
    );

    let (s, prefix) = expand_seed(secret);
    let public = ge::to_bytes(&ge::scalarmult_base(&s));
    let dom_len = dom4_len_byte(context);

    // r = SHAKE256(dom4 || prefix || M) as a little-endian integer.
    let hash = shake256(&[b"SigEd448", &dom_len, context, &prefix, msg]);
    let r = sc::reduce_wide(&hash);
    let r_bytes = ge::to_bytes(&ge::scalarmult_base(&r));

    // k = SHAKE256(dom4 || R || A || M)
    let hash = shake256(&[b"SigEd448", &dom_len, context, &r_bytes, &public, msg]);
    let k = sc::reduce_wide(&hash);

    // S = (r + k * s) mod L
    let s_val = sc::muladd(&k, &s, &r);

    let mut sig = [0u8; SIGNATURE_SIZE];
    sig[..57].copy_from_slice(&r_bytes);
    sig[57..].copy_from_slice(&s_val);
    sig
}

/// Verify `sig` over `msg` under `context` with the 57-byte compressed
/// public key.
pub fn verify(
    public: &[u8; PUBLIC_KEY_SIZE],
    sig: &[u8; SIGNATURE_SIZE],
    msg: &[u8],
    context: &[u8],
) -> bool {
    if context.len() > MAX_CONTEXT_SIZE {
        return false;
    }
    let s: [u8; 57] = sig[57..].try_into().unwrap();
    if !sc::is_canonical(&s) {
        return false;
    }
    let a_point = match ge::from_bytes(public) {
        Some(a) => a,
        None => return false,
    };
    let mut r_bytes = [0u8; 57];
    r_bytes.copy_from_slice(&sig[..57]);
    let r_point = match ge::from_bytes(&r_bytes) {
        Some(r) => r,
        None => return false,
    };

    // k = SHAKE256(dom4 || R || A || M)
    let dom_len = dom4_len_byte(context);
    let hash = shake256(&[b"SigEd448", &dom_len, context, &r_bytes, public, msg]);
    let k = sc::reduce_wide(&hash);

    // Check [S]B = R + [k]A (cofactorless, sufficient per RFC 8032 §5.2.7).
    let lhs = ge::to_bytes(&ge::scalarmult_base(&s));
    let rhs = ge::to_bytes(&ge::add(&r_point, &ge::scalarmult(&a_point, &k)));

    // Constant-time compare of the two 57-byte point encodings.
    let mut diff = 0u8;
    for i in 0..PUBLIC_KEY_SIZE {
        diff |= lhs[i] ^ rhs[i];
    }
    diff == 0
}

//! Package hkdf implements the HMAC-based Extract-and-Expand Key Derivation
//! Function (HKDF) as defined in RFC 5869.
//!
//! HKDF is a cryptographic key derivation function (KDF) with the goal of
//! expanding limited input keying material into one or more cryptographically
//! strong secret keys.

use crate::{
    hash::{Hash, HashUser},
    hmac::{self, Marshalable},
};
use std::io::Write;

/// Extract a pseudorandom key from input keying material.
///
/// This is the "extract" step of HKDF as defined in RFC 5869.
/// It takes optional salt and input keying material (IKM) and produces
/// a pseudorandom key (PRK) of fixed length.
pub fn extract<const N: usize, H, F>(hash_fn: F, secret: &[u8], salt: Option<&[u8]>) -> [u8; N]
where
    H: Hash<N> + Marshalable,
    F: Fn() -> H,
{
    let salt = match salt {
        Some(s) => s.to_vec(),
        None => vec![0u8; hash_fn().size()],
    };

    let mut extractor = hmac::new(hash_fn, &salt);
    extractor.mark_as_used_in_kdf();
    extractor
        .write_all(secret)
        .expect("HMAC write should not fail");

    extractor.sum()
}

/// Expand a pseudorandom key to the desired length.
///
/// This is the "expand" step of HKDF as defined in RFC 5869.
/// It takes a pseudorandom key (PRK), optional context info, and desired
/// output length, and produces the output keying material (OKM).
pub fn expand<const N: usize, H, F>(
    hash_fn: F,
    pseudorandom_key: &[u8],
    info: &str,
    key_len: usize,
) -> [u8; N]
where
    H: Hash<N> + Marshalable,
    F: Fn() -> H,
{
    let mut out = Vec::with_capacity(key_len);
    let mut expander = hmac::new(&hash_fn, pseudorandom_key);
    expander.mark_as_used_in_kdf();
    let mut counter: u8 = 0;
    let mut buf = Vec::new();

    while out.len() < key_len {
        counter = counter.checked_add(1).expect("hkdf: counter overflow");

        if counter > 1 {
            expander.reset();
        }

        expander
            .write_all(&buf)
            .expect("HMAC write should not fail");
        expander
            .write_all(info.as_bytes())
            .expect("HMAC write should not fail");
        expander
            .write_all(&[counter])
            .expect("HMAC write should not fail");

        buf = expander.sum().to_vec();

        let remain = std::cmp::min(key_len - out.len(), buf.len());
        out.extend_from_slice(&buf[..remain]);
    }

    out.try_into().unwrap()
}

/// Derive key material using HKDF.
///
/// This is a convenience function that combines the extract and expand steps.
/// It's equivalent to calling extract() followed by expand().
pub fn key<const N: usize, H, F>(
    hash_fn: F,
    secret: &[u8],
    salt: Option<&[u8]>,
    info: &str,
    key_len: usize,
) -> [u8; N]
where
    H: Hash<N> + Marshalable,
    F: Fn() -> H + Clone,
{
    let prk = extract(hash_fn.clone(), secret, salt);
    expand(hash_fn, &prk, info, key_len)
}

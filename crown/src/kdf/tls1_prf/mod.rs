//! TLS PRF from RFC 2246 (TLS 1.0) section 5 and RFC 5246 (TLS 1.2)
//! section 5, ported from OpenSSL
//! `providers/implementations/kdfs/tls1_prf.c`.
//!
//! * TLS 1.0/1.1 (`derive_md5_sha1`, OpenSSL digest `MD5-SHA1`):
//!   `PRF(secret, seed) = P_MD5(S1, seed) XOR P_SHA-1(S2, seed)` with
//!   `S1`/`S2` the two (possibly overlapping) halves of the secret.
//! * TLS 1.2 (`derive`): `PRF(secret, seed) = P_<hash>(secret, seed)` with
//!   any single HMAC digest.
//!
//! `P_<hash>(secret, seed)` is the usual HMAC chain:
//! `A(0) = seed`, `A(i) = HMAC(secret, A(i-1))`,
//! output = `HMAC(secret, A(1) || seed) || HMAC(secret, A(2) || seed) || ...`.

#[cfg(test)]
mod tests;

use crate::core::CoreWrite;
use crate::envelope::EvpHash;
use crate::error::{CryptoError, CryptoResult};
use crate::kdf::HmacFactory;
use alloc::vec::Vec;

/// TLS 1.2+ PRF with a single digest. `hmac` is an HMAC factory such as
/// `EvpHash::new_sha256_hmac`; its output size selects the block length.
pub fn derive(
    hmac: HmacFactory,
    secret: &[u8],
    seed: &[u8],
    key_len: usize,
) -> CryptoResult<Vec<u8>> {
    if key_len == 0 {
        return Err(CryptoError::InvalidLength);
    }
    p_hash(hmac, secret, seed, key_len)
}

/// TLS 1.0/1.1 PRF with the MD5/SHA-1 combination (OpenSSL digest
/// `MD5-SHA1`): `P_MD5(S1) XOR P_SHA-1(S2)` over split secret halves.
pub fn derive_md5_sha1(secret: &[u8], seed: &[u8], key_len: usize) -> CryptoResult<Vec<u8>> {
    if key_len == 0 {
        return Err(CryptoError::InvalidLength);
    }

    let l_s = secret.len().div_ceil(2);
    let md5 = p_hash(EvpHash::new_md5_hmac, &secret[..l_s], seed, key_len)?;
    let sha1 = p_hash(
        EvpHash::new_sha1_hmac,
        &secret[secret.len() - l_s..],
        seed,
        key_len,
    )?;

    Ok(md5.iter().zip(sha1.iter()).map(|(a, b)| a ^ b).collect())
}

/// P_<hash>(secret, seed) expansion into exactly `key_len` bytes.
fn p_hash(hmac: HmacFactory, secret: &[u8], seed: &[u8], key_len: usize) -> CryptoResult<Vec<u8>> {
    let mut out = Vec::with_capacity(key_len);

    // A(1) = HMAC(secret, A(0) = seed)
    let mut h = hmac(secret)?;
    h.write(seed)?;
    let mut a = h.sum();

    while out.len() < key_len {
        let mut h = hmac(secret)?;
        h.write(&a)?;
        h.write(seed)?;
        let block = h.sum();

        let remaining = key_len - out.len();
        out.extend_from_slice(&block[..core::cmp::min(remaining, block.len())]);

        if out.len() < key_len {
            let mut h = hmac(secret)?;
            h.write(&a)?;
            a = h.sum();
        }
    }

    Ok(out)
}

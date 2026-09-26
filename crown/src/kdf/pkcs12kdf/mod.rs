//! PKCS #12 key derivation (RFC 7292 appendix B), ported from OpenSSL
//! `providers/implementations/kdfs/pkcs12kdf.c`.
//!
//! The KDF mixes the password and salt into blocks of the digest's block
//! size, then iterates a hash chain seeded with `id` bytes:
//!
//! * `id = 1` derives MAC/integrity keys,
//! * `id = 2` derives encryption (key) material,
//! * `id = 3` derives IV bytes.
//!
//! The caller is responsible for encoding the password the way the PBE
//! packet expects it (RFC 7292 uses UTF-16-BE with two trailing zero bytes).

#[cfg(test)]
mod tests;

use crate::core::CoreWrite;
use crate::error::{CryptoError, CryptoResult};
use crate::hash::HashUser;
use crate::kdf::HashFactory;
use alloc::vec::Vec;

/// Derive `key_len` bytes with PKCS #12's KDF for the given purpose `id`
/// (1, 2 or 3), iteration count and digest.
pub fn derive(
    hash: HashFactory,
    pass: &[u8],
    salt: &[u8],
    id: u8,
    iter: u64,
    key_len: usize,
) -> CryptoResult<Vec<u8>> {
    if !(1..=3).contains(&id) {
        return Err(CryptoError::StrError("pkcs12kdf: id must be 1, 2 or 3"));
    }
    if iter == 0 {
        return Err(CryptoError::StrError(
            "pkcs12kdf: iteration count must be at least 1",
        ));
    }
    if key_len == 0 {
        return Err(CryptoError::InvalidLength);
    }

    let mut h = hash()?;
    let u = h.size();
    let v = h.block_size();

    // I = S || P where S (P) repeats the salt (password) to a multiple of v.
    let slen = if salt.is_empty() {
        0
    } else {
        v * salt.len().div_ceil(v)
    };
    let plen = if pass.is_empty() {
        0
    } else {
        v * pass.len().div_ceil(v)
    };
    let mut i = Vec::with_capacity(slen + plen);
    for k in 0..slen {
        i.push(salt[k % salt.len()]);
    }
    for k in 0..plen {
        i.push(pass[k % pass.len()]);
    }

    let mut out = Vec::with_capacity(key_len);
    let mut n = key_len;

    loop {
        // A = Hash(D || I) where D is v copies of id, hashed iter times.
        h.reset();
        for _ in 0..v {
            h.write(&[id])?;
        }
        h.write(&i)?;
        let mut a = h.sum();
        for _ in 1..iter {
            let mut h = hash()?;
            h.write(&a)?;
            a = h.sum();
        }

        let take = core::cmp::min(u, n);
        out.extend_from_slice(&a[..take]);
        if u >= n {
            break;
        }
        n -= u;

        // B = A repeated to v bytes; I_j = I_j + B + 1 per v-byte chunk.
        let b: Vec<u8> = (0..v).map(|k| a[k % u]).collect();
        for chunk_start in (0..i.len()).step_by(v) {
            let mut carry = 1u16;
            for k in (0..v).rev() {
                carry += i[chunk_start + k] as u16 + b[k] as u16;
                i[chunk_start + k] = carry as u8;
                carry >>= 8;
            }
        }
    }

    Ok(out)
}

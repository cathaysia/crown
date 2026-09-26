//! Single Step KDF (NIST SP 800-56C rev 1 section 4) and the ANSI X9.63
//! KDF, ported from OpenSSL `providers/implementations/kdfs/sskdf.c`.
//!
//! The auxiliary function H(x) is either a plain hash, HMAC or KMAC:
//!
//! * hash:  `Result(i) = Result(i-1) || H(counter || Z || FixedInfo)`
//! * HMAC:  `Result(i) = Result(i-1) || HMAC(salt, counter || Z || FixedInfo)`
//! * KMAC:  a single KMAC call over `counter || Z || FixedInfo` with
//!   customisation string "KDF"
//!
//! X9.63 only supports the hash variant and appends the counter after the
//! secret: `Result(i) = Result(i-1) || H(Z || counter || FixedInfo)`.

#[cfg(test)]
mod tests;

use crate::core::CoreWrite;
use crate::error::{CryptoError, CryptoResult};
use crate::hash::HashUser;
use crate::kdf::{HashFactory, HmacFactory};
use crate::mac::kmac::{Kmac128, Kmac256};
use alloc::vec::Vec;

const MAX_IN_LEN: usize = 1 << 30;
const KMAC_CUSTOM: &[u8] = b"KDF";
/// Default salt (KMAC key) lengths: 168 - 4 and 136 - 4 bytes.
const KMAC128_DEFAULT_SALT: usize = 164;
const KMAC256_DEFAULT_SALT: usize = 132;

fn check_lengths(secret_len: usize, info_len: usize, key_len: usize) -> CryptoResult<()> {
    if secret_len > MAX_IN_LEN || info_len > MAX_IN_LEN || key_len > MAX_IN_LEN || key_len == 0 {
        return Err(CryptoError::InvalidLength);
    }
    Ok(())
}

fn be32(counter: usize) -> [u8; 4] {
    (counter as u32).to_be_bytes()
}

/// SP 800-56C One-Step KDF with H(x) = hash(x).
pub fn derive_hash(
    hash: HashFactory,
    secret: &[u8],
    info: &[u8],
    key_len: usize,
) -> CryptoResult<Vec<u8>> {
    check_lengths(secret.len(), info.len(), key_len)?;

    let mut out = Vec::with_capacity(key_len);
    let mut counter = 1usize;
    while out.len() < key_len {
        let mut h = hash()?;
        h.write(&be32(counter))?;
        h.write(secret)?;
        h.write(info)?;
        let block = h.sum();
        let remaining = key_len - out.len();
        out.extend_from_slice(&block[..core::cmp::min(remaining, block.len())]);
        counter += 1;
    }
    Ok(out)
}

/// SP 800-56C One-Step KDF with H(x) = HMAC(salt, x). An empty salt becomes
/// a zero string of the digest output size.
pub fn derive_hmac(
    hmac: HmacFactory,
    salt: &[u8],
    secret: &[u8],
    info: &[u8],
    key_len: usize,
) -> CryptoResult<Vec<u8>> {
    check_lengths(secret.len(), info.len(), key_len)?;

    let salt: alloc::vec::Vec<u8> = if salt.is_empty() {
        alloc::vec![0u8; hmac(&[])?.size()]
    } else {
        salt.to_vec()
    };

    let mut out = Vec::with_capacity(key_len);
    let mut counter = 1usize;
    while out.len() < key_len {
        let mut h = hmac(&salt)?;
        h.write(&be32(counter))?;
        h.write(secret)?;
        h.write(info)?;
        let block = h.sum();
        let remaining = key_len - out.len();
        out.extend_from_slice(&block[..core::cmp::min(remaining, block.len())]);
        counter += 1;
    }
    Ok(out)
}

/// SP 800-56C One-Step KDF with H(x) = KMAC128(salt, x, "KDF").
pub fn derive_kmac128(
    salt: &[u8],
    secret: &[u8],
    info: &[u8],
    key_len: usize,
) -> CryptoResult<Vec<u8>> {
    derive_kmac(
        salt,
        secret,
        info,
        key_len,
        KMAC128_DEFAULT_SALT,
        KmacVariant::Kmac128,
    )
}

/// SP 800-56C One-Step KDF with H(x) = KMAC256(salt, x, "KDF").
pub fn derive_kmac256(
    salt: &[u8],
    secret: &[u8],
    info: &[u8],
    key_len: usize,
) -> CryptoResult<Vec<u8>> {
    derive_kmac(
        salt,
        secret,
        info,
        key_len,
        KMAC256_DEFAULT_SALT,
        KmacVariant::Kmac256,
    )
}

#[derive(Clone, Copy)]
enum KmacVariant {
    Kmac128,
    Kmac256,
}

fn derive_kmac(
    salt: &[u8],
    secret: &[u8],
    info: &[u8],
    key_len: usize,
    default_salt: usize,
    variant: KmacVariant,
) -> CryptoResult<Vec<u8>> {
    check_lengths(secret.len(), info.len(), key_len)?;

    let salt: alloc::vec::Vec<u8> = if salt.is_empty() {
        alloc::vec![0u8; default_salt]
    } else {
        salt.to_vec()
    };

    // Single KMAC call: the output size equals the derived key length, so
    // the counter loop of SSKDF_mac_kdm performs exactly one iteration.
    let mut out = alloc::vec![0u8; key_len];
    match variant {
        KmacVariant::Kmac128 => {
            let mut kmac = Kmac128::new(&salt, KMAC_CUSTOM)?;
            kmac.write(&be32(1));
            kmac.write(secret);
            kmac.write(info);
            kmac.sum(&mut out);
        }
        KmacVariant::Kmac256 => {
            let mut kmac = Kmac256::new(&salt, KMAC_CUSTOM)?;
            kmac.write(&be32(1));
            kmac.write(secret);
            kmac.write(info);
            kmac.sum(&mut out);
        }
    }
    Ok(out)
}

/// ANSI X9.63 KDF: hash-based with the counter appended after the secret.
pub fn x963_derive_hash(
    hash: HashFactory,
    secret: &[u8],
    info: &[u8],
    key_len: usize,
) -> CryptoResult<Vec<u8>> {
    check_lengths(secret.len(), info.len(), key_len)?;

    let mut out = Vec::with_capacity(key_len);
    let mut counter = 1usize;
    while out.len() < key_len {
        let mut h = hash()?;
        h.write(secret)?;
        h.write(&be32(counter))?;
        h.write(info)?;
        let block = h.sum();
        let remaining = key_len - out.len();
        out.extend_from_slice(&block[..core::cmp::min(remaining, block.len())]);
        counter += 1;
    }
    Ok(out)
}

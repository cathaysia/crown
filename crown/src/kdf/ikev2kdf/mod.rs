//! IKEv2 key derivation (RFC 7296 section 2.14, NIST SP 800-135), ported
//! from OpenSSL `providers/implementations/kdfs/ikev2kdf.c`.
//!
//! * `seedkey_gen`:   SKEYSEED = HMAC(Ni || Nr, g^ir)
//! * `seedkey_rekey`: SKEYSEED' = HMAC(SK_d, g^ir_new || Ni || Nr)
//! * `dkm`: keyed HMAC chain producing the child keying material:
//!   `HMAC(K, [K(i-1)] || [g^ir_new] || Ni || Nr || [SPIi || SPIr] || counter)`
//!
//! The shared secret must be 28..=1024 bytes; when it does not already have
//! one of the well-known DH group lengths it is zero-padded on the left to
//! the next larger length (mirrors `ikev2_check_secret_and_pad`).

#[cfg(test)]
mod tests;

use crate::core::CoreWrite;
use crate::error::{CryptoError, CryptoResult};
use crate::hash::HashUser;
use crate::kdf::HmacFactory;
use alloc::vec::Vec;

const MIN_SECRET_LEN: usize = 28;
const MAX_SECRET_LEN: usize = 1024;
const MIN_NONCE_LEN: usize = 8;
const MAX_NONCE_LEN: usize = 256;
const MAX_DKM_LEN: usize = 2048;

/// Well-known shared secret lengths (ECDH P-256/P-384/P-521, DH groups).
const SECRET_PAD_LENGTHS: [usize; 9] = [32, 48, 66, 128, 256, 384, 512, 768, 1024];

fn check_nonce(nonce: &[u8]) -> CryptoResult<()> {
    if nonce.len() < MIN_NONCE_LEN || nonce.len() > MAX_NONCE_LEN {
        return Err(CryptoError::StrError("ikev2kdf: invalid nonce length"));
    }
    Ok(())
}

/// Zero-pad the shared secret on the left to the next well-known length.
fn pad_secret(secret: &[u8]) -> CryptoResult<Vec<u8>> {
    if secret.is_empty() {
        return Ok(Vec::new());
    }
    if secret.len() < MIN_SECRET_LEN || secret.len() > MAX_SECRET_LEN {
        return Err(CryptoError::StrError("ikev2kdf: invalid secret length"));
    }
    if SECRET_PAD_LENGTHS.contains(&secret.len()) {
        return Ok(secret.to_vec());
    }
    let pad_len = SECRET_PAD_LENGTHS
        .iter()
        .find(|l| **l > secret.len())
        .map(|l| l - secret.len())
        .unwrap_or(0);
    let mut padded = alloc::vec![0u8; pad_len];
    padded.extend_from_slice(secret);
    Ok(padded)
}

/// Generate the initial SKEYSEED: `HMAC(Ni || Nr, secret)`. The output
/// length equals the digest size.
pub fn seedkey_gen(
    hmac: HmacFactory,
    secret: &[u8],
    ni: &[u8],
    nr: &[u8],
) -> CryptoResult<Vec<u8>> {
    check_nonce(ni)?;
    check_nonce(nr)?;
    let secret = pad_secret(secret)?;
    if secret.is_empty() {
        return Err(CryptoError::StrError("ikev2kdf: missing secret"));
    }

    let mut nonce = Vec::with_capacity(ni.len() + nr.len());
    nonce.extend_from_slice(ni);
    nonce.extend_from_slice(nr);

    let mut h = hmac(&nonce)?;
    h.write(&secret)?;
    Ok(h.sum().to_vec())
}

/// Regenerate the SKEYSEED for rekeying: `HMAC(SK_d, secret || Ni || Nr)`.
/// `SK_d` must be one digest long.
pub fn seedkey_rekey(
    hmac: HmacFactory,
    sk_d: &[u8],
    secret: &[u8],
    ni: &[u8],
    nr: &[u8],
) -> CryptoResult<Vec<u8>> {
    check_nonce(ni)?;
    check_nonce(nr)?;
    let secret = pad_secret(secret)?;
    if secret.is_empty() {
        return Err(CryptoError::StrError("ikev2kdf: missing secret"));
    }
    let md_size = hmac(&[])?.size();
    if sk_d.len() != md_size {
        return Err(CryptoError::StrError(
            "ikev2kdf: SK_d length must match the digest",
        ));
    }

    let mut h = hmac(sk_d)?;
    h.write(&secret)?;
    h.write(ni)?;
    h.write(nr)?;
    Ok(h.sum().to_vec())
}

/// Derive keying material for child SAs. Exactly one of the two call
/// shapes is valid:
///
/// * `spii`/`spir` set and `shared_secret` absent: `key` is the SKEYSEED
///   (one digest long); produces the DKM.
/// * `spii`/`spir` absent: `key` is SK_d and `shared_secret` may hold the
///   new DH secret (Child DH) or be empty (Child SA); produces `out_len`
///   bytes, where `out_len` is between the digest size and 2048.
#[allow(clippy::too_many_arguments)]
pub fn dkm(
    hmac: HmacFactory,
    key: &[u8],
    ni: &[u8],
    nr: &[u8],
    spii: Option<&[u8]>,
    spir: Option<&[u8]>,
    shared_secret: Option<&[u8]>,
    out_len: usize,
) -> CryptoResult<Vec<u8>> {
    check_nonce(ni)?;
    check_nonce(nr)?;
    let md_size = hmac(&[])?.size();

    match (spii, spir, shared_secret) {
        (Some(spi_i), Some(spi_r), None) => {
            // DKM from the seed key.
            if key.len() != md_size {
                return Err(CryptoError::StrError(
                    "ikev2kdf: seedkey length must match the digest",
                ));
            }
            if spi_i.is_empty() || spi_r.is_empty() {
                return Err(CryptoError::StrError("ikev2kdf: empty SPI"));
            }
            if out_len < md_size || out_len > MAX_DKM_LEN {
                return Err(CryptoError::InvalidLength);
            }
            dkm_chain(
                hmac,
                key,
                &[],
                ni,
                nr,
                Some((spi_i, spi_r)),
                out_len,
                md_size,
            )
        }
        (None, None, shared_secret) => {
            // DKM(Child SA) or DKM(Child_DH) from SK_d; no length check on
            // SK_d in this branch (matching OpenSSL).
            if out_len < md_size || out_len > MAX_DKM_LEN {
                return Err(CryptoError::InvalidLength);
            }
            let secret = pad_secret(shared_secret.unwrap_or(&[]))?;
            if shared_secret.is_some() && secret.is_empty() {
                return Err(CryptoError::StrError("ikev2kdf: empty shared secret"));
            }
            dkm_chain(hmac, key, secret.as_slice(), ni, nr, None, out_len, md_size)
        }
        _ => Err(CryptoError::StrError(
            "ikev2kdf: invalid parameters for DKM",
        )),
    }
}

/// The `IKEV2_DKM` HMAC chain.
#[allow(clippy::too_many_arguments)]
fn dkm_chain(
    hmac: HmacFactory,
    key: &[u8],
    secret: &[u8],
    ni: &[u8],
    nr: &[u8],
    spis: Option<(&[u8], &[u8])>,
    out_len: usize,
    md_size: usize,
) -> CryptoResult<Vec<u8>> {
    let mut out = alloc::vec![0u8; out_len];
    let mut counter = 1u8;
    let mut prev_block: Vec<u8> = Vec::new();
    for chunk in out.chunks_mut(md_size) {
        let mut h = hmac(key)?;
        if !prev_block.is_empty() {
            // K(i-1): the previous full HMAC block.
            h.write(&prev_block)?;
        }
        h.write(secret)?;
        h.write(ni)?;
        h.write(nr)?;
        if let Some((spi_i, spi_r)) = spis {
            h.write(spi_i)?;
            h.write(spi_r)?;
        }
        h.write(&[counter])?;
        let block = h.sum();
        let take = core::cmp::min(chunk.len(), block.len());
        chunk[..take].copy_from_slice(&block[..take]);
        prev_block.clear();
        prev_block.extend_from_slice(&block);
        counter = counter.wrapping_add(1);
    }
    Ok(out)
}

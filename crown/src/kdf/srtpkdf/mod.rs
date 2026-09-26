//! SRTP key derivation (RFC 3711 appendix B, AES-CM), ported from OpenSSL
//! `providers/implementations/kdfs/srtpkdf.c`.
//!
//! For a label in 0..=7 the master salt is XORed with the key derivation
//! rate-reduced packet index and the label, and the result (padded to a
//! 16-byte AES-CTR IV) keystream-encrypts a zero buffer:
//!
//! * labels 0, 3, 6 produce `key.len()` bytes (the cipher key length),
//! * labels 1, 4 produce the 20-byte auth keys,
//! * labels 2, 5, 7 produce the 14-byte salt keys.

#[cfg(test)]
mod tests;

use crate::block::aes::Aes;
use crate::error::{CryptoError, CryptoResult};
use crate::modes::ctr::Ctr;
use crate::stream::StreamCipher;
use alloc::vec::Vec;

const SALT_LEN: usize = 14;
const SRTP_IDX_LEN: usize = 6;
const SRTCP_IDX_LEN: usize = 4;
const AUTH_KEY_LEN: usize = 20;

/// Derive the key material for `label` (0..=7) from the master key and the
/// 14-byte master salt. `kdr` is the key derivation rate: 0 disables index
/// processing, otherwise it must be a power of two and `index` must hold at
/// least 6 bytes (labels 0-2) or 4 bytes (labels 3-7) big-endian.
pub fn derive_aes_cm(
    key: &[u8],
    master_salt: &[u8],
    index: &[u8],
    kdr: u32,
    label: u8,
) -> CryptoResult<Vec<u8>> {
    if label > 7 {
        return Err(CryptoError::StrError("srtpkdf: label must be 0..=7"));
    }
    if master_salt.len() != SALT_LEN {
        return Err(CryptoError::InvalidKeySize {
            expected: "14",
            actual: master_salt.len(),
        });
    }

    let o_len = match label {
        0 | 3 | 6 => key.len(),
        1 | 4 => AUTH_KEY_LEN,
        _ => SALT_LEN,
    };

    let cipher = Aes::new(key)?;
    let idx_len = if label <= 2 {
        SRTP_IDX_LEN
    } else {
        SRTCP_IDX_LEN
    };

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(master_salt);

    if kdr > 0 {
        if !kdr.is_power_of_two() {
            return Err(CryptoError::StrError("srtpkdf: kdr must be a power of two"));
        }
        if index.len() < idx_len {
            return Err(CryptoError::StrError("srtpkdf: index too short"));
        }

        // iv = index >> log2(kdr), big-endian, right-aligned in the salt.
        let mut value = [0u8; SRTP_IDX_LEN];
        value[..idx_len].copy_from_slice(&index[..idx_len]);
        shift_right(&mut value, kdr.trailing_zeros());
        for i in 0..idx_len {
            salt[SALT_LEN - idx_len + i] ^= value[i];
        }
    }

    // key_id = label || r occupies the salt tail; the label sits right
    // before the index bytes.
    salt[SALT_LEN - 1 - idx_len] ^= label;

    // AES-CM keystream over a zero buffer with IV = salt || 0^2.
    let mut iv = [0u8; 16];
    iv[..SALT_LEN].copy_from_slice(&salt);

    let mut out = alloc::vec![0u8; o_len];
    cipher.to_ctr(&iv)?.xor_key_stream(&mut out)?;
    Ok(out)
}

/// Big-endian right shift of a fixed-width big-endian integer by `bits`.
fn shift_right(value: &mut [u8], bits: u32) {
    if bits == 0 {
        return;
    }
    let byte_shift = (bits / 8) as usize;
    let bit_shift = (bits % 8) as u8;
    if byte_shift > 0 {
        for i in (0..value.len()).rev() {
            value[i] = if i >= byte_shift {
                value[i - byte_shift]
            } else {
                0
            };
        }
    }
    if bit_shift == 0 {
        return;
    }
    let mut carry = 0u8;
    for b in value.iter_mut() {
        let low = *b & ((1u16 << bit_shift) - 1) as u8;
        *b = (*b >> bit_shift) | (carry << (8 - bit_shift));
        carry = low;
    }
}

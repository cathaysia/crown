//! Key-Based KDFs from NIST SP 800-108 (counter mode and feedback mode)
//! with HMAC, CMAC or KMAC, ported from OpenSSL
//! `providers/implementations/kdfs/kbkdf.c`.
//!
//! The fixed input data per iteration is the (big-endian) counter of `r`
//! bits, the label, an optional 0x00 separator, the context and the
//! (big-endian) 32-bit output length in bits:
//!
//! * counter mode:  `K_i = PRF(KI, [i] || Label || 0x00 || Context || [L])`
//! * feedback mode: `K_i = PRF(KI, K(i-1) || [i] || Label || 0x00 || Context || [L])`
//!
//! The KMAC variants perform a single KMAC call over the context with the
//! given customisation string, deriving the whole output in one invocation
//! (OpenSSL's `kmac_derive`).

#[cfg(test)]
mod tests;

use crate::block::BlockCipher;
use crate::core::CoreWrite;
use crate::error::{CryptoError, CryptoResult};
use crate::hash::HashUser;
use crate::kdf::HmacFactory;
use crate::mac::cmac::Cmac;
use crate::mac::kmac::{Kmac128, Kmac256};
use alloc::vec::Vec;

/// SP 800-108 operation mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Counter,
    Feedback,
}

/// Configuration of the fixed input data. OpenSSL's defaults are empty
/// label/context/IV, `use_l = true`, `use_separator = true`, `r = 32`.
#[derive(Clone, Copy)]
pub struct FixedInput<'a> {
    /// Label; may be empty.
    pub label: &'a [u8],
    /// Context; may be empty.
    pub context: &'a [u8],
    /// IV/seed for feedback mode; must be empty or one MAC output long.
    pub iv: &'a [u8],
    /// Whether the 32-bit output length L is part of the fixed input.
    pub use_l: bool,
    /// Whether the 0x00 separator between label and context is included.
    pub use_separator: bool,
    /// Counter width in bits (8, 16 or 32).
    pub r: u32,
}

/// Write the `r`-bit big-endian counter: the low `r / 8` bytes of the
/// 32-bit value.
fn counter_slice(counter: u32, r: u32) -> ([u8; 4], usize) {
    (counter.to_be_bytes(), (r / 8) as usize)
}

fn validate(mode: Mode, fi: &FixedInput<'_>, h: usize, out_len: usize) -> CryptoResult<()> {
    if out_len == 0 {
        return Err(CryptoError::InvalidLength);
    }
    if !matches!(fi.r, 8 | 16 | 32) {
        return Err(CryptoError::StrError("kbkdf: r must be 8, 16 or 32"));
    }
    if !fi.iv.is_empty() && fi.iv.len() != h {
        return Err(CryptoError::StrError("kbkdf: invalid seed length"));
    }
    // Fail if the output is too long for the counter width.
    if mode == Mode::Counter && out_len / h >= (1usize << fi.r) {
        return Err(CryptoError::StrError("kbkdf: output too long for r"));
    }
    Ok(())
}

/// SP 800-108 counter/feedback mode with HMAC(KI, x) under the given digest.
pub fn derive_hmac(
    hmac: HmacFactory,
    mode: Mode,
    ki: &[u8],
    fi: &FixedInput<'_>,
    out_len: usize,
) -> CryptoResult<Vec<u8>> {
    let h = hmac(ki)?.size();
    validate(mode, fi, h, out_len)?;

    let mut out = Vec::with_capacity(out_len);
    // K(0) for feedback mode; empty in counter mode.
    let mut k_i: Vec<u8> = fi.iv.to_vec();
    let mut counter = 1u32;
    while out.len() < out_len {
        let mut mac = hmac(ki)?;
        if mode == Mode::Feedback {
            mac.write(&k_i)?;
        }
        let (be, n) = counter_slice(counter, fi.r);
        mac.write(&be[4 - n..])?;
        mac.write(fi.label)?;
        if fi.use_separator {
            mac.write(&[0u8])?;
        }
        mac.write(fi.context)?;
        if fi.use_l {
            mac.write(&(8 * out_len as u32).to_be_bytes())?;
        }
        k_i = mac.sum();

        let remaining = out_len - out.len();
        out.extend_from_slice(&k_i[..core::cmp::min(remaining, k_i.len())]);
        counter = counter.wrapping_add(1);
    }
    Ok(out)
}

/// SP 800-108 counter/feedback mode with CMAC under a cipher keyed with KI.
pub fn derive_cmac<C: BlockCipher, const BLOCK_SIZE: usize>(
    cipher: C,
    mode: Mode,
    fi: &FixedInput<'_>,
    out_len: usize,
) -> CryptoResult<Vec<u8>> {
    validate(mode, fi, BLOCK_SIZE, out_len)?;

    let mut mac = Cmac::<C, BLOCK_SIZE>::new(cipher)?;
    let mut out = Vec::with_capacity(out_len);
    let mut k_i = [0u8; BLOCK_SIZE];
    k_i[..fi.iv.len()].copy_from_slice(fi.iv);

    let mut counter = 1u32;
    while out.len() < out_len {
        mac.reset();
        if mode == Mode::Feedback {
            mac.write(&k_i);
        }
        let (be, n) = counter_slice(counter, fi.r);
        mac.write(&be[4 - n..]);
        mac.write(fi.label);
        if fi.use_separator {
            mac.write(&[0u8]);
        }
        mac.write(fi.context);
        if fi.use_l {
            mac.write(&(8 * out_len as u32).to_be_bytes());
        }
        k_i = mac.sum();

        let remaining = out_len - out.len();
        out.extend_from_slice(&k_i[..core::cmp::min(remaining, BLOCK_SIZE)]);
        counter = counter.wrapping_add(1);
    }
    Ok(out)
}

/// SP 800-108 with KMAC128: a single KMAC call over the context.
pub fn derive_kmac128(
    key: &[u8],
    custom: &[u8],
    context: &[u8],
    out_len: usize,
) -> CryptoResult<Vec<u8>> {
    if out_len == 0 {
        return Err(CryptoError::InvalidLength);
    }
    let mut out = alloc::vec![0u8; out_len];
    let mut mac = Kmac128::new(key, custom)?;
    mac.write(context);
    mac.sum(&mut out);
    Ok(out)
}

/// SP 800-108 with KMAC256: a single KMAC call over the context.
pub fn derive_kmac256(
    key: &[u8],
    custom: &[u8],
    context: &[u8],
    out_len: usize,
) -> CryptoResult<Vec<u8>> {
    if out_len == 0 {
        return Err(CryptoError::InvalidLength);
    }
    let mut out = alloc::vec![0u8; out_len];
    let mut mac = Kmac256::new(key, custom)?;
    mac.write(context);
    mac.sum(&mut out);
    Ok(out)
}

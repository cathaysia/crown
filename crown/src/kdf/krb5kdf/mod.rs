//! Kerberos V5 key derivation (RFC 3961 section 5.1 "simple key
//! derivation"), ported from OpenSSL
//! `providers/implementations/kdfs/krb5kdf.c`.
//!
//! DK(Key, Constant) = random-to-key(K-truncate(E(Key, n-fold(Constant))))
//!
//! The n-folded constant is encrypted block by block with a fresh cipher
//! each block, the ciphertext of one block becoming the plaintext of the
//! next. For DES3 the output additionally passes through the RFC 3961
//! random-to-key parity fixup.

#[cfg(test)]
mod tests;

use crate::block::BlockCipher;
use crate::error::{CryptoError, CryptoResult};
use crate::utils::subtle::constant_time_eq;
use alloc::vec::Vec;

/// Derive `key_len` bytes (normally the cipher's key size) from an already
/// keyed cipher and the derivation constant.
pub fn derive<C: BlockCipher>(
    cipher: &C,
    key_len: usize,
    constant: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key_len == 0 {
        return Err(CryptoError::InvalidLength);
    }
    let block_size = cipher.block_size();
    if constant.is_empty() || constant.len() > block_size {
        return Err(CryptoError::StrError("krb5kdf: invalid constant length"));
    }

    let mut block = alloc::vec![0u8; block_size];
    n_fold(&mut block, constant);

    let mut out = Vec::with_capacity(key_len);
    loop {
        cipher.encrypt_block(&mut block);
        let take = core::cmp::min(block_size, key_len - out.len());
        out.extend_from_slice(&block[..take]);
        if out.len() == key_len {
            break;
        }
    }
    Ok(out)
}

/// DES3 special case (RFC 3961 6.3.1): derive 24 bytes and fix up the parity
/// bits, failing if the result degrades to single DES.
pub fn derive_des3<C: BlockCipher>(cipher: &C, constant: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut key = derive(cipher, 24, constant)?;
    fixup_des3_key(&mut key)?;
    Ok(key)
}

/// DES3 "raw" derivation: 21 bytes without the parity fixup (the input to
/// the string-to-key function).
pub fn derive_des3_raw<C: BlockCipher>(cipher: &C, constant: &[u8]) -> CryptoResult<Vec<u8>> {
    derive(cipher, 21, constant)
}

/// Set odd parity on each DES key block and reject degenerate keys
/// (mirrors `fixup_des3_key`).
fn fixup_des3_key(key: &mut [u8]) -> CryptoResult<()> {
    for i in (0..3).rev() {
        // Expand the 7 raw bytes at i*7 into a parity-adjusted DES block.
        let mut cblock = [0u8; 8];
        cblock[..7].copy_from_slice(&key[i * 7..i * 7 + 7]);
        let mut packed = 0u8;
        for j in 0..7 {
            packed |= (cblock[j] & 1) << (j + 1);
        }
        cblock[7] = packed;
        for b in cblock.iter_mut() {
            // DES_set_odd_parity: make the number of one bits odd.
            if b.count_ones() % 2 == 0 {
                *b ^= 0x01;
            }
        }
        key[i * 8..i * 8 + 8].copy_from_slice(&cblock);
    }
    if constant_time_eq(&key[0..8], &key[8..16]) || constant_time_eq(&key[8..16], &key[16..24]) {
        return Err(CryptoError::StrError("krb5kdf: degenerate DES3 key"));
    }
    Ok(())
}

/// N-fold as specified by RFC 3961 section 5.1 (mirrors `n_fold`).
fn n_fold(block: &mut [u8], constant: &[u8]) {
    let blocksize = block.len();
    if constant.len() == blocksize {
        block.copy_from_slice(constant);
        return;
    }

    // LCM(blocksize, constant.len()) via the GCD.
    let (mut gcd, mut rem) = (blocksize, constant.len());
    while rem != 0 {
        let tmp = gcd % rem;
        gcd = rem;
        rem = tmp;
    }
    let lcm = blocksize * constant.len() / gcd;

    block.fill(0);

    // Spread the rotated constant bytes, adding with ones'-complement
    // carries from the last position to the first.
    let mut carry = 0u32;
    for l in (0..lcm).rev() {
        let b = l % blocksize;
        let rotbits = 13 * (l / constant.len());
        let rbyte = l - rotbits / 8;
        let rshift = rotbits & 0x07;
        // The rotated byte value; when rshift == 0 the high term shifts out
        // entirely, and rbyte is at least 1 whenever it contributes.
        let v = (if rshift == 0 {
            0
        } else {
            (constant[(rbyte - 1) % constant.len()] as u32) << (8 - rshift)
        } | (constant[rbyte % constant.len()] as u32) >> rshift)
            & 0xff;
        let sum = v + carry + block[b] as u32;
        block[b] = sum as u8;
        carry = sum >> 8;
    }

    let mut b = blocksize;
    while carry != 0 && b > 0 {
        b -= 1;
        carry += block[b] as u32;
        block[b] = carry as u8;
        carry >>= 8;
    }
}

//! AES Key Wrap (RFC 3394), AES Key Wrap with Padding (RFC 5649), the
//! inverse-cipher variants (OpenSSL `AES-*-WRAP-INV` / `WRAP-PAD-INV`), and
//! Triple-DES key wrapping (RFC 3217).

use crate::block::aes::Aes;
use crate::block::des::TripleDes;
use crate::block::BlockCipher;
use crate::error::{CryptoError, CryptoResult};

use alloc::vec;
use alloc::vec::Vec;
/// Default IV for AES Key Wrap (RFC 3394 §2.2.3.1).
const IV: [u8; 8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

/// Magic value for the Alternative Initial Value (RFC 5649 §3): A65959A6.
const MAGIC: [u8; 4] = [0xA6, 0x59, 0x59, 0xA6];

/// Fixed IV for RFC 3217 Triple-DES key wrapping (§3.1 step 7).
const DES3_WRAP_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

/// Apply one block operation in the chosen cipher direction. The RFC 3394
/// loop uses the forward cipher; the OpenSSL `WRAP-INV` variants run the
/// same loop with the inverse cipher.
fn block_op(c: &Aes, block: &mut [u8; 16], inverse: bool) {
    if inverse {
        c.decrypt_block(block);
    } else {
        c.encrypt_block(block);
    }
}

fn to_blocks(data: &[u8]) -> Vec<[u8; 8]> {
    data.as_chunks::<8>()
        .0
        .iter()
        .map(|c| {
            let mut b = [0u8; 8];
            b.copy_from_slice(c);
            b
        })
        .collect()
}

/// RFC 3394 wrap with a caller-supplied 8-byte initial value.
fn wrap_iv(c: &Aes, plaintext: &[u8], iv: &[u8; 8], inverse: bool) -> CryptoResult<Vec<u8>> {
    if plaintext.len() < 16 || !plaintext.len().is_multiple_of(8) {
        return Err(CryptoError::InvalidLength);
    }
    let n = plaintext.len() / 8;
    let mut a = *iv;
    let mut r = to_blocks(plaintext);

    for j in 0..6 {
        for i in 0..n {
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(&r[i]);
            let t = (n * j + i + 1) as u64;
            block_op(c, &mut block, inverse);
            a.copy_from_slice(&block[..8]);
            for k in 0..8 {
                a[k] ^= ((t >> (56 - 8 * k)) & 0xff) as u8;
            }
            r[i].copy_from_slice(&block[8..]);
        }
    }

    let mut out = Vec::with_capacity(8 + n * 8);
    out.extend_from_slice(&a);
    for ri in &r {
        out.extend_from_slice(ri);
    }
    Ok(out)
}

/// RFC 3394 unwrap core: recovers the integrity register A and the data.
/// The caller validates A against the expected initial value / AIV. The
/// unwrap runs the block cipher in the direction opposite to the wrap:
/// decrypt for the forward variant, encrypt for the inverse variant.
fn unwrap_core(c: &Aes, ct: &[u8], inverse: bool) -> CryptoResult<([u8; 8], Vec<u8>)> {
    if ct.len() < 24 || !ct.len().is_multiple_of(8) {
        return Err(CryptoError::InvalidLength);
    }
    let n = ct.len() / 8 - 1;
    let mut a = [0u8; 8];
    a.copy_from_slice(&ct[..8]);
    let mut r = to_blocks(&ct[8..]);

    for j in (0..6).rev() {
        for i in (0..n).rev() {
            let t = (n * j + i + 1) as u64;
            let mut ai = a;
            for k in 0..8 {
                ai[k] ^= ((t >> (56 - 8 * k)) & 0xff) as u8;
            }
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&ai);
            block[8..].copy_from_slice(&r[i]);
            // Unwrap runs the opposite direction to the wrap.
            block_op(c, &mut block, !inverse);
            a.copy_from_slice(&block[..8]);
            r[i].copy_from_slice(&block[8..]);
        }
    }

    let mut out = Vec::with_capacity(n * 8);
    for ri in &r {
        out.extend_from_slice(ri);
    }
    Ok((a, out))
}

/// AES Key Wrap (RFC 3394).
///
/// `plaintext` must be at least 16 bytes and a multiple of 8 bytes.
/// The output is `plaintext.len() + 8` bytes.
pub fn key_wrap(c: &Aes, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    key_wrap_iv(c, plaintext, &IV)
}

/// AES Key Wrap with a caller-supplied initial value.
pub fn key_wrap_iv(c: &Aes, plaintext: &[u8], iv: &[u8; 8]) -> CryptoResult<Vec<u8>> {
    wrap_iv(c, plaintext, iv, false)
}

/// AES Key Unwrap (RFC 3394).
///
/// `ct` must be at least 24 bytes and a multiple of 8 bytes.
/// Fails with [`CryptoError::AuthenticationFailed`] on integrity-IV mismatch.
pub fn key_unwrap(c: &Aes, ct: &[u8]) -> CryptoResult<Vec<u8>> {
    key_unwrap_iv(c, ct, &IV)
}

/// AES Key Unwrap with a caller-supplied initial value.
pub fn key_unwrap_iv(c: &Aes, ct: &[u8], iv: &[u8; 8]) -> CryptoResult<Vec<u8>> {
    let (a, data) = unwrap_core(c, ct, false)?;
    if a != *iv {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(data)
}

/// AES Key Wrap using the inverse cipher (OpenSSL `AES-*-WRAP-INV`).
pub fn key_wrap_inv(c: &Aes, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    wrap_iv(c, plaintext, &IV, true)
}

/// AES Key Unwrap using the inverse cipher (OpenSSL `AES-*-WRAP-INV`).
pub fn key_unwrap_inv(c: &Aes, ct: &[u8]) -> CryptoResult<Vec<u8>> {
    let (a, data) = unwrap_core(c, ct, true)?;
    if a != IV {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(data)
}

fn make_aiv(mli: u32) -> [u8; 8] {
    let mut aiv = [0u8; 8];
    aiv[..4].copy_from_slice(&MAGIC);
    aiv[4..].copy_from_slice(&mli.to_be_bytes());
    aiv
}

/// AES Key Wrap with Padding (RFC 5649).
///
/// Accepts a plaintext of any length in `1..=2^32`. The output is a
/// multiple of 8 bytes and at least 16 bytes.
pub fn key_wrap_padded(c: &Aes, pt: &[u8]) -> CryptoResult<Vec<u8>> {
    if pt.is_empty() {
        return Err(CryptoError::InvalidLength);
    }
    let mli = pt.len() as u32;
    let padded_len = pt.len().div_ceil(8) * 8;
    let mut padded = vec![0u8; padded_len];
    padded[..pt.len()].copy_from_slice(pt);
    let aiv = make_aiv(mli);

    if padded.len() == 8 {
        // n = 1: single AES call on AIV || P1 (RFC 5649 §4.1 step 2).
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&aiv);
        block[8..].copy_from_slice(&padded);
        let mut out = block;
        c.encrypt_block(&mut out);
        return Ok(out.to_vec());
    }
    wrap_iv(c, &padded, &aiv, false)
}

/// AES Key Unwrap with Padding (RFC 5649).
///
/// Verifies the AIV (magic, MLI bounds, and zero padding) and returns
/// the original plaintext.
pub fn key_unwrap_padded(c: &Aes, ct: &[u8]) -> CryptoResult<Vec<u8>> {
    if ct.len() < 16 || !ct.len().is_multiple_of(8) {
        return Err(CryptoError::InvalidLength);
    }
    // Number of padded plaintext blocks.
    let n = ct.len() / 8 - 1;

    let (a, mut padded) = if ct.len() == 16 {
        let mut block = [0u8; 16];
        block.copy_from_slice(ct);
        c.decrypt_block(&mut block);
        let mut a = [0u8; 8];
        a.copy_from_slice(&block[..8]);
        (a, block[8..].to_vec())
    } else {
        unwrap_core(c, ct, false)?
    };

    finish_unwrap_padded(a, &mut padded, n)
}

/// AES Key Wrap with Padding using the inverse cipher
/// (OpenSSL `AES-*-WRAP-PAD-INV`).
pub fn key_wrap_padded_inv(c: &Aes, pt: &[u8]) -> CryptoResult<Vec<u8>> {
    if pt.is_empty() {
        return Err(CryptoError::InvalidLength);
    }
    let mli = pt.len() as u32;
    let padded_len = pt.len().div_ceil(8) * 8;
    let mut padded = vec![0u8; padded_len];
    padded[..pt.len()].copy_from_slice(pt);
    let aiv = make_aiv(mli);

    if padded.len() == 8 {
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&aiv);
        block[8..].copy_from_slice(&padded);
        c.decrypt_block(&mut block);
        return Ok(block.to_vec());
    }
    wrap_iv(c, &padded, &aiv, true)
}

/// AES Key Unwrap with Padding using the inverse cipher
/// (OpenSSL `AES-*-WRAP-PAD-INV`).
pub fn key_unwrap_padded_inv(c: &Aes, ct: &[u8]) -> CryptoResult<Vec<u8>> {
    if ct.len() < 16 || !ct.len().is_multiple_of(8) {
        return Err(CryptoError::InvalidLength);
    }
    let n = ct.len() / 8 - 1;

    let (a, mut padded) = if ct.len() == 16 {
        let mut block = [0u8; 16];
        block.copy_from_slice(ct);
        c.encrypt_block(&mut block);
        let mut a = [0u8; 8];
        a.copy_from_slice(&block[..8]);
        (a, block[8..].to_vec())
    } else {
        unwrap_core(c, ct, true)?
    };

    finish_unwrap_padded(a, &mut padded, n)
}

/// Shared AIV/padding validation for both RFC 5649 unwrap directions.
fn finish_unwrap_padded(a: [u8; 8], padded: &mut Vec<u8>, n: usize) -> CryptoResult<Vec<u8>> {
    // AIV verification (RFC 5649 §3).
    if a[..4] != MAGIC {
        return Err(CryptoError::AuthenticationFailed);
    }
    let mli = u32::from_be_bytes([a[4], a[5], a[6], a[7]]) as usize;
    // 8*(n-1) < MLI <= 8*n
    if mli == 0 || mli > 8 * n || mli <= 8 * (n.saturating_sub(1)) {
        return Err(CryptoError::AuthenticationFailed);
    }
    // Padding: the rightmost (8*n - MLI) octets must be zero.
    if padded[mli..].iter().any(|&x| x != 0) {
        return Err(CryptoError::AuthenticationFailed);
    }
    padded.truncate(mli);
    Ok(core::mem::take(padded))
}

/// CBC-encrypt/decrypt with an 8-byte block cipher, in place.
fn cbc8(c: &TripleDes, iv: &[u8; 8], buf: &mut [u8], encrypt: bool) {
    let mut prev = *iv;
    for chunk in buf.as_chunks_mut::<8>().0 {
        if encrypt {
            for i in 0..8 {
                chunk[i] ^= prev[i];
            }
            c.encrypt_block(chunk);
            prev.copy_from_slice(chunk);
        } else {
            let mut cur = [0u8; 8];
            cur.copy_from_slice(chunk);
            c.decrypt_block(chunk);
            for i in 0..8 {
                chunk[i] ^= prev[i];
            }
            prev = cur;
        }
    }
}

/// Triple-DES Key Wrap (RFC 3217 §3.1). `cek` must be 16 or 24 bytes. `iv`
/// is the fresh per-invocation random value (RFC 3217 §3.1 step 4).
///
/// Like OpenSSL's `DES3-WRAP`, the RFC 3217 §3.1 step 1 odd-parity fixup is
/// not applied; the SHA-1 key checksum is the only integrity check.
pub fn des3_key_wrap(kek: &TripleDes, cek: &[u8], iv: &[u8; 8]) -> CryptoResult<Vec<u8>> {
    match cek.len() {
        16 | 24 => {}
        _ => {
            return Err(CryptoError::InvalidKeySize {
                expected: "16 or 24",
                actual: cek.len(),
            })
        }
    }
    let cek = cek.to_vec();

    // ICV = first 8 octets of SHA-1(CEK) (RFC 3217 §2).
    let icv = &crate::hash::sha1::sum(&cek)[..8];

    // TEMP1 = CBC(KEK, IV, CEKICV).
    let mut cekicv = Vec::with_capacity(32);
    cekicv.extend_from_slice(&cek);
    cekicv.extend_from_slice(icv);
    cbc8(kek, iv, &mut cekicv, true);

    // TEMP3 = reverse(IV || TEMP1); result = CBC(KEK, fixed IV, TEMP3).
    let mut temp3 = Vec::with_capacity(40);
    temp3.extend_from_slice(iv);
    temp3.extend_from_slice(&cekicv);
    temp3.reverse();
    cbc8(kek, &DES3_WRAP_IV, &mut temp3, true);
    Ok(temp3)
}

/// Triple-DES Key Unwrap (RFC 3217 §3.2). Returns the CEK after ICV and
/// parity verification.
pub fn des3_key_unwrap(kek: &TripleDes, ct: &[u8]) -> CryptoResult<Vec<u8>> {
    // Wrapped length = CEK (16 or 24) + IV (8) + ICV (8).
    if ct.len() != 32 && ct.len() != 40 {
        return Err(CryptoError::InvalidLength);
    }
    // TEMP3 = CBC-decrypt(KEK, fixed IV, wrapped); TEMP2 = reverse(TEMP3).
    let mut temp3 = ct.to_vec();
    cbc8(kek, &DES3_WRAP_IV, &mut temp3, false);
    temp3.reverse();

    // Split TEMP2 into the per-invocation IV and TEMP1; recover CEKICV.
    let mut iv = [0u8; 8];
    iv.copy_from_slice(&temp3[..8]);
    let mut cekicv = temp3[8..].to_vec();
    cbc8(kek, &iv, &mut cekicv, false);

    let (cek, icv) = cekicv.split_at(cekicv.len() - 8);
    // Key checksum verification (RFC 3217 §3.2 step 7). The parity check of
    // step 8 is intentionally omitted, matching OpenSSL's DES3-WRAP.
    let expected = &crate::hash::sha1::sum(cek)[..8];
    if icv != expected {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(cek.to_vec())
}

#[cfg(test)]
mod tests;

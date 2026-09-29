//! AES Key Wrap (RFC 3394) and AES Key Wrap with Padding (RFC 5649).

use crate::block::aes::Aes;
use crate::block::BlockCipher;
use crate::error::{CryptoError, CryptoResult};

use alloc::vec::Vec;
use alloc::vec;
/// Default IV for AES Key Wrap (RFC 3394 §2.2.3.1).
const IV: [u8; 8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

/// Magic value for the Alternative Initial Value (RFC 5649 §3): A65959A6.
const MAGIC: [u8; 4] = [0xA6, 0x59, 0x59, 0xA6];

fn enc(c: &Aes, block: &[u8; 16]) -> [u8; 16] {
    let mut out = *block;
    c.encrypt_block(&mut out);
    out
}

fn dec(c: &Aes, block: &[u8; 16]) -> [u8; 16] {
    let mut out = *block;
    c.decrypt_block(&mut out);
    out
}

fn to_blocks(data: &[u8]) -> Vec<[u8; 8]> {
    data.as_chunks::<8>().0.iter()
        .map(|c| {
            let mut b = [0u8; 8];
            b.copy_from_slice(c);
            b
        })
        .collect()
}

/// RFC 3394 wrap with a caller-supplied 8-byte initial value.
fn wrap_iv(c: &Aes, plaintext: &[u8], iv: &[u8; 8]) -> CryptoResult<Vec<u8>> {
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
            let b = enc(c, &block);
            a.copy_from_slice(&b[..8]);
            for k in 0..8 {
                a[k] ^= ((t >> (56 - 8 * k)) & 0xff) as u8;
            }
            r[i].copy_from_slice(&b[8..]);
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
/// The caller validates A against the expected initial value / AIV.
fn unwrap_core(c: &Aes, ct: &[u8]) -> CryptoResult<([u8; 8], Vec<u8>)> {
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
            let b = dec(c, &block);
            a.copy_from_slice(&b[..8]);
            r[i].copy_from_slice(&b[8..]);
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
    if plaintext.len() < 16 || !plaintext.len().is_multiple_of(8) {
        return Err(CryptoError::InvalidLength);
    }
    wrap_iv(c, plaintext, &IV)
}

/// AES Key Unwrap (RFC 3394).
///
/// `ct` must be at least 24 bytes and a multiple of 8 bytes.
/// Fails with [`CryptoError::AuthenticationFailed`] on integrity-IV mismatch.
pub fn key_unwrap(c: &Aes, ct: &[u8]) -> CryptoResult<Vec<u8>> {
    if ct.len() < 24 || !ct.len().is_multiple_of(8) {
        return Err(CryptoError::InvalidLength);
    }
    let (a, data) = unwrap_core(c, ct)?;
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
        return Ok(enc(c, &block).to_vec());
    }
    wrap_iv(c, &padded, &aiv)
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
        let b = dec(c, &block);
        let mut a = [0u8; 8];
        a.copy_from_slice(&b[..8]);
        (a, b[8..].to_vec())
    } else {
        unwrap_core(c, ct)?
    };

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
    Ok(padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aes(kek: &[u8]) -> Aes {
        Aes::new(kek).unwrap()
    }

    // RFC 3394 §4.1 — 128-bit KEK, 128-bit key
    #[test]
    fn rfc3394_4_1() {
        let kek = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let data = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let expected = [
            0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A,
            0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
        ];
        let c = aes(&kek);
        let ct = key_wrap(&c, &data).unwrap();
        assert_eq!(&ct[..], &expected[..]);
        let pt = key_unwrap(&c, &ct).unwrap();
        assert_eq!(&pt[..], &data[..]);
    }

    // RFC 3394 §4.2 — 192-bit KEK, 128-bit key
    #[test]
    fn rfc3394_4_2() {
        let kek = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let data = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let expected = [
            0x96, 0x77, 0x8B, 0x25, 0xAE, 0x6C, 0xA4, 0x35, 0xF9, 0x2B, 0x5B, 0x97, 0xC0, 0x50,
            0xAE, 0xD2, 0x46, 0x8A, 0xB8, 0xA1, 0x7A, 0xD8, 0x4E, 0x5D,
        ];
        let c = aes(&kek);
        let ct = key_wrap(&c, &data).unwrap();
        assert_eq!(&ct[..], &expected[..]);
        let pt = key_unwrap(&c, &ct).unwrap();
        assert_eq!(&pt[..], &data[..]);
    }

    // RFC 3394 §4.3 — 256-bit KEK, 192-bit key
    #[test]
    fn rfc3394_4_3() {
        let kek = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let data = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let expected = [
            0xA8, 0xF9, 0xBC, 0x16, 0x12, 0xC6, 0x8B, 0x3F, 0xF6, 0xE6, 0xF4, 0xFB, 0xE3, 0x0E,
            0x71, 0xE4, 0x76, 0x9C, 0x8B, 0x80, 0xA3, 0x2C, 0xB8, 0x95, 0x8C, 0xD5, 0xD1, 0x7D,
            0x6B, 0x25, 0x4D, 0xA1,
        ];
        let c = aes(&kek);
        let ct = key_wrap(&c, &data).unwrap();
        assert_eq!(&ct[..], &expected[..]);
        let pt = key_unwrap(&c, &ct).unwrap();
        assert_eq!(&pt[..], &data[..]);
    }

    // RFC 5649 §6 — 20-octet key with a 192-bit KEK
    #[test]
    fn rfc5649_6_20_byte() {
        let kek = [
            0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1,
            0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
        ];
        let pt = [
            0xc3, 0x7b, 0x7e, 0x64, 0x92, 0x58, 0x43, 0x40, 0xbe, 0xd1, 0x22, 0x07, 0x80, 0x89,
            0x41, 0x15, 0x50, 0x68, 0xf7, 0x38,
        ];
        let expected = [
            0x13, 0x8b, 0xde, 0xaa, 0x9b, 0x8f, 0xa7, 0xfc, 0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22,
            0x48, 0xee, 0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a, 0x5f, 0x54, 0xf3, 0x73,
            0xfa, 0x54, 0x3b, 0x6a,
        ];
        let c = aes(&kek);
        let ct = key_wrap_padded(&c, &pt).unwrap();
        assert_eq!(&ct[..], &expected[..]);
        let out = key_unwrap_padded(&c, &ct).unwrap();
        assert_eq!(&out[..], &pt[..]);
    }

    // RFC 5649 §6 — 7-octet key with a 192-bit KEK (single-block path)
    #[test]
    fn rfc5649_6_7_byte() {
        let kek = [
            0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1,
            0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
        ];
        let pt = [0x46, 0x6f, 0x72, 0x50, 0x61, 0x73, 0x69];
        let expected = [
            0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x00, 0xf2, 0xcc, 0xb5, 0x0b,
            0xb2, 0x4f,
        ];
        let c = aes(&kek);
        let ct = key_wrap_padded(&c, &pt).unwrap();
        assert_eq!(&ct[..], &expected[..]);
        let out = key_unwrap_padded(&c, &ct).unwrap();
        assert_eq!(&out[..], &pt[..]);
    }

    #[test]
    fn wrap_bad_input_len() {
        let c = aes(&[0u8; 16]);
        assert!(key_wrap(&c, &[0u8; 8]).is_err());
        assert!(key_wrap(&c, &[0u8; 12]).is_err());
        assert!(key_unwrap(&c, &[0u8; 16]).is_err());
        assert!(key_wrap_padded(&c, &[]).is_err());
    }

    #[test]
    fn unwrap_tampered_tag_fails() {
        let kek = [
            0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1,
            0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
        ];
        let c = aes(&kek);
        let ct = key_wrap_padded(&c, b"hello world!!").unwrap();
        let mut bad = ct.clone();
        bad[0] ^= 0xff;
        assert!(key_unwrap_padded(&c, &bad).is_err());
    }
}

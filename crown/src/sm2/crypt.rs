//! SM2 public-key encryption (GB/T 32918.4-2016 / GM/T 0003.4).
//!
//! Construction over the SM2-P-256 curve with SM3 as both the KDF and the
//! digest:
//!
//! * C1 = [k]G (the ephemeral point),
//! * (x2, y2) = [k]P (the shared point),
//! * t = KDF(x2 || y2, len(M)) — ANSI X9.63 with SM3, counter from 1,
//! * C2 = M ⊕ t (all-zero KDF output restarts with a fresh k),
//! * C3 = SM3(x2 || M || y2).
//!
//! [`encrypt_raw`]/[`decrypt_raw`] use the raw wire form
//! `04 || x1 || y1 || C3 || C2` (C1C3C2 order, uncompressed point).
//! [`encrypt`]/[`decrypt`] use the DER form
//! `SEQUENCE { C1x, C1y, C3, C2 }` that OpenSSL's `pkeyutl` produces and
//! consumes — the two interop in both directions.
//!
//! The curve is explicit on every entry point (matching OpenSSL, where the
//! SM2 cipher operates on the key's group); the `_sm2_curve` suffixed
//! helpers default to SM2-P-256. Note that the GB/T 32918.4-2016 and
//! GB/T 32918.3-2016 worked examples use the example curve of
//! GB/T 32918.1-2016 annex A (a different 256-bit curve), not SM2-P-256.

use crate::bn::Bn;
use crate::ec::{coord32, Curve, Point};
use crate::error::{CryptoError, CryptoResult};
use crate::hash::sm3::sum_sm3;
use crate::kdf::{sskdf::x963_derive_hash, HashFactory};
use crate::rng::Rng;
use crate::sm2::{sample_k, sm2_curve};

use alloc::vec::Vec;

const KDF_SECRET_LEN: usize = 64;
const C3_LEN: usize = 32;

fn sm3_factory() -> HashFactory {
    crate::envelope::EvpHash::new_sm3
}

/// KDF output of exactly `msg.len()` bytes, or `None` when the mask is all
/// zeros (the caller restarts with a fresh k, GB/T 32918.4 step C5).
fn kdf_mask(x2: &[u8; 32], y2: &[u8; 32], msg_len: usize) -> CryptoResult<Option<Vec<u8>>> {
    if msg_len == 0 {
        return Ok(Some(Vec::new()));
    }
    let mut z = Vec::with_capacity(KDF_SECRET_LEN);
    z.extend_from_slice(x2);
    z.extend_from_slice(y2);
    let mask = x963_derive_hash(sm3_factory(), &z, &[], msg_len)?;
    if mask.iter().all(|&b| b == 0) {
        return Ok(None);
    }
    Ok(Some(mask))
}

/// C3 = SM3(x2 || M || y2).
fn compute_c3(x2: &[u8; 32], msg: &[u8], y2: &[u8; 32]) -> [u8; C3_LEN] {
    let mut buf = Vec::with_capacity(KDF_SECRET_LEN + msg.len());
    buf.extend_from_slice(x2);
    buf.extend_from_slice(msg);
    buf.extend_from_slice(y2);
    sum_sm3(&buf)
}

/// XOR `msg` with the KDF mask.
fn xor_mask(msg: &[u8], mask: &[u8]) -> Vec<u8> {
    msg.iter().zip(mask).map(|(a, b)| a ^ b).collect()
}

/// Encrypt on SM2-P-256 with the raw wire form `04 || x1 || y1 || C3 || C2`.
pub fn encrypt_raw_sm2_curve(
    pub_key: &Point,
    msg: &[u8],
    rng: &mut impl Rng,
) -> CryptoResult<Vec<u8>> {
    encrypt_raw(&sm2_curve(), pub_key, msg, rng)
}

/// Encrypt with the raw wire form `04 || x1 || y1 || C3 || C2`.
pub fn encrypt_raw(
    c: &Curve,
    pub_key: &Point,
    msg: &[u8],
    rng: &mut impl Rng,
) -> CryptoResult<Vec<u8>> {
    let n = &c.n;
    if pub_key.is_infinity() || !pub_key.is_on_curve(c) {
        return Err(CryptoError::StrError("sm2: public key not on curve"));
    }
    for _ in 0..128 {
        let k = sample_k(n, rng);
        let c1 = crate::ec::mul_base(c, &k);
        let kp = pub_key.mul_with(c, &k);
        if kp.is_infinity() {
            continue;
        }
        let x2 = coord32(&kp.x);
        let y2 = coord32(&kp.y);
        let Some(mask) = kdf_mask(&x2, &y2, msg.len())? else {
            continue;
        };
        let c3 = compute_c3(&x2, msg, &y2);
        let mut out = Vec::with_capacity(1 + 64 + C3_LEN + msg.len());
        out.push(0x04);
        out.extend_from_slice(&coord32(&c1.x));
        out.extend_from_slice(&coord32(&c1.y));
        out.extend_from_slice(&c3);
        out.extend_from_slice(&xor_mask(msg, &mask));
        return Ok(out);
    }
    Err(CryptoError::StrError("sm2: failed to produce ciphertext"))
}

/// Decrypt on SM2-P-256 the raw wire form produced by [`encrypt_raw`].
pub fn decrypt_raw_sm2_curve(d: &Bn, ct: &[u8]) -> CryptoResult<Vec<u8>> {
    decrypt_raw(&sm2_curve(), d, ct)
}

/// Decrypt the raw wire form produced by [`encrypt_raw`].
pub fn decrypt_raw(c: &Curve, d: &Bn, ct: &[u8]) -> CryptoResult<Vec<u8>> {
    let n = &c.n;
    if ct.len() < 1 + 64 + C3_LEN {
        return Err(CryptoError::InvalidLength);
    }
    if ct[0] != 0x04 {
        return Err(CryptoError::StrError("sm2: expected uncompressed point"));
    }
    let c1 = Point {
        x: Bn::from_be_bytes(&ct[1..33]),
        y: Bn::from_be_bytes(&ct[33..65]),
        infinity: false,
    };
    if c1.is_infinity() || !c1.is_on_curve(c) {
        return Err(CryptoError::StrError("sm2: C1 not on curve"));
    }
    let c3 = &ct[65..65 + C3_LEN];
    let c2 = &ct[65 + C3_LEN..];

    let shared = c1.mul_with(c, &d.modulus(n));
    if shared.is_infinity() {
        return Err(CryptoError::StrError("sm2: [d]C1 is infinity"));
    }
    let x2 = coord32(&shared.x);
    let y2 = coord32(&shared.y);
    let Some(mask) = kdf_mask(&x2, &y2, c2.len())? else {
        return Err(CryptoError::AuthenticationFailed);
    };
    let pt = xor_mask(c2, &mask);

    let expected = compute_c3(&x2, &pt, &y2);
    if !crate::utils::subtle::constant_time_eq(c3, &expected) {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(pt)
}

/// Encrypt on SM2-P-256 with the DER form OpenSSL produces.
pub fn encrypt_sm2_curve(pub_key: &Point, msg: &[u8], rng: &mut impl Rng) -> CryptoResult<Vec<u8>> {
    encrypt(&sm2_curve(), pub_key, msg, rng)
}

/// Encrypt with the DER form OpenSSL produces:
/// `SEQUENCE { C1x INTEGER, C1y INTEGER, C3 OCTET STRING, C2 OCTET STRING }`.
pub fn encrypt(
    c: &Curve,
    pub_key: &Point,
    msg: &[u8],
    rng: &mut impl Rng,
) -> CryptoResult<Vec<u8>> {
    let raw = encrypt_raw(c, pub_key, msg, rng)?;
    let mut inner = Vec::with_capacity(raw.len());
    // x1 || y1 are each 32 bytes starting after the 0x04 marker.
    inner.extend_from_slice(&crate::rsa::der::encode_integer(&raw[1..33]));
    inner.extend_from_slice(&crate::rsa::der::encode_integer(&raw[33..65]));
    inner.extend_from_slice(&encode_octet_string(&raw[65..65 + C3_LEN]));
    inner.extend_from_slice(&encode_octet_string(&raw[65 + C3_LEN..]));
    Ok(encode_sequence(&inner))
}

/// Decrypt on SM2-P-256 the DER form consumed by OpenSSL.
pub fn decrypt_sm2_curve(d: &Bn, ct: &[u8]) -> CryptoResult<Vec<u8>> {
    decrypt(&sm2_curve(), d, ct)
}

/// Decrypt the DER form consumed by OpenSSL.
pub fn decrypt(c: &Curve, d: &Bn, ct: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut top = crate::rsa::der::Parser::new(ct);
    let mut seq = top.read_sequence()?;
    let x1 = seq.read_integer()?;
    let y1 = seq.read_integer()?;
    let (tag, c3) = seq.next_tlv()?;
    if tag != 0x04 {
        return Err(CryptoError::StrError("sm2: expected OCTET STRING C3"));
    }
    let (tag, c2) = seq.next_tlv()?;
    if tag != 0x04 {
        return Err(CryptoError::StrError("sm2: expected OCTET STRING C2"));
    }
    let x1 = strip_leading_zero(&x1)?;
    let y1 = strip_leading_zero(&y1)?;
    if x1.len() > 32 || y1.len() > 32 {
        return Err(CryptoError::StrError("sm2: C1 coordinates out of range"));
    }
    let mut raw = Vec::with_capacity(1 + 64 + c3.len() + c2.len());
    raw.push(0x04);
    // Right-align the INTEGER contents to the 32-byte field size.
    raw.resize(raw.len() + 32 - x1.len(), 0);
    raw.extend_from_slice(x1);
    raw.resize(raw.len() + 32 - y1.len(), 0);
    raw.extend_from_slice(y1);
    if c3.len() != C3_LEN {
        return Err(CryptoError::StrError("sm2: C3 length mismatch"));
    }
    raw.extend_from_slice(c3);
    raw.extend_from_slice(c2);
    decrypt_raw(c, d, &raw)
}

/// DER INTEGER contents may carry a leading zero for the sign bit.
fn strip_leading_zero(v: &[u8]) -> CryptoResult<&[u8]> {
    if v.len() > 1 && v[0] == 0 && v[1] & 0x80 == 0 {
        return Err(CryptoError::StrError("sm2: non-canonical DER integer"));
    }
    let start = usize::from(v.len() > 1 && v[0] == 0 && v[1] & 0x80 != 0);
    Ok(&v[start..])
}

fn encode_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        alloc::vec![len as u8]
    } else if len <= 0xff {
        alloc::vec![0x81, len as u8]
    } else {
        alloc::vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    out.extend_from_slice(&encode_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn encode_sequence(content: &[u8]) -> Vec<u8> {
    encode_tlv(0x30, content)
}

fn encode_octet_string(content: &[u8]) -> Vec<u8> {
    encode_tlv(0x04, content)
}

/// A ciphertext split into its components (C1C3C2 layout).
pub struct Sm2Ciphertext {
    pub c1: [u8; 64],
    pub c3: [u8; C3_LEN],
    pub c2: Vec<u8>,
}

/// Parse the raw wire form into components.
pub fn parse_raw(ct: &[u8]) -> CryptoResult<Sm2Ciphertext> {
    if ct.len() < 1 + 64 + C3_LEN || ct[0] != 0x04 {
        return Err(CryptoError::InvalidLength);
    }
    let mut c1 = [0u8; 64];
    c1.copy_from_slice(&ct[1..65]);
    let mut c3 = [0u8; C3_LEN];
    c3.copy_from_slice(&ct[65..65 + C3_LEN]);
    Ok(Sm2Ciphertext {
        c1,
        c3,
        c2: ct[65 + C3_LEN..].to_vec(),
    })
}

/// Reassemble the raw wire form from components.
pub fn to_raw(ct: &Sm2Ciphertext) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 64 + C3_LEN + ct.c2.len());
    out.push(0x04);
    out.extend_from_slice(&ct.c1);
    out.extend_from_slice(&ct.c3);
    out.extend_from_slice(&ct.c2);
    out
}

/// Serialize components to the OpenSSL-compatible DER form.
pub fn to_der(ct: &Sm2Ciphertext) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&crate::rsa::der::encode_integer(&ct.c1[..32]));
    inner.extend_from_slice(&crate::rsa::der::encode_integer(&ct.c1[32..]));
    inner.extend_from_slice(&encode_octet_string(&ct.c3));
    inner.extend_from_slice(&encode_octet_string(&ct.c2));
    encode_sequence(&inner)
}

#[cfg(test)]
mod tests;

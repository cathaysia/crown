//! C ABI for the public-key primitives a protocol stack needs outside of the
//! X.509 world: X25519 key agreement, NIST-curve ECDH/ECDSA and RSA with
//! PKCS#1 v1.5 signatures over a *precomputed* digest (the form both TLS and
//! SSH hand their crypto backends).

use super::*;
use crate::math::OsRng;
use crown::bn::Bn;
use crown::ec::{self, CurveId, Point};
use crown::ecdsa;
use crown::rsa::{RsaPrivateKey, RsaPublicKey};
use crown::x25519;

fn curve_of(id: u32) -> Option<CurveId> {
    match id {
        0 => Some(CurveId::P256),
        1 => Some(CurveId::P384),
        2 => Some(CurveId::P521),
        _ => None,
    }
}

/// Curve identifiers shared with the C side: 0 = P-256, 1 = P-384,
/// 2 = P-521.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_ec_curve_field_bytes(curve: u32) -> usize {
    match curve_of(curve) {
        Some(id) => ec::field_bytes(&ec::curve(id)),
        None => 0,
    }
}

/*******************************************************************/
/*
 * X25519
 */

/// Derive the public value for a 32-byte X25519 private key.
///
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_x25519_public(private: *const u8, public: *mut u8) -> i32 {
    let Some(private) = (unsafe { slice_from_raw_parts(private, 32) }) else {
        return -1;
    };
    if public.is_null() {
        return -1;
    }
    let Ok(private) = <[u8; 32]>::try_from(private) else {
        return -1;
    };
    let out = x25519::public_from_private(&private);
    unsafe { std::ptr::copy_nonoverlapping(out.as_ptr(), public, 32) };
    0
}

/// X25519 key agreement. Returns 0 on success, -1 when the shared secret is
/// the all-zero value (low-order peer point) or an argument is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_x25519(
    private: *const u8,
    peer_public: *const u8,
    shared: *mut u8,
) -> i32 {
    let (Some(private), Some(peer)) = (unsafe { slice_from_raw_parts(private, 32) }, unsafe {
        slice_from_raw_parts(peer_public, 32)
    }) else {
        return -1;
    };
    if shared.is_null() {
        return -1;
    }
    let (Ok(private), Ok(peer)) = (<[u8; 32]>::try_from(private), <[u8; 32]>::try_from(peer))
    else {
        return -1;
    };
    match x25519::x25519(&private, &peer) {
        Some(out) => {
            unsafe { std::ptr::copy_nonoverlapping(out.as_ptr(), shared, 32) };
            0
        }
        None => -1,
    }
}

/// Generate a fresh X25519 key pair into `private`/`public` (32 bytes each).
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_x25519_keypair(private: *mut u8, public: *mut u8) -> i32 {
    if private.is_null() || public.is_null() {
        return -1;
    }
    let mut rng = OsRng::new();
    let (sk, pk) = x25519::keypair(&mut rng);
    if rng.failed {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(sk.as_ptr(), private, 32);
        std::ptr::copy_nonoverlapping(pk.as_ptr(), public, 32);
    }
    0
}

/*******************************************************************/
/*
 * NIST curves: key objects, ECDH and ECDSA
 */

/// Opaque EC key handle: always carries the public point, optionally the
/// private scalar.
pub struct EcKeyHandle {
    id: CurveId,
    private: Option<Bn>,
    public: Point,
}

/// Generate a fresh key pair on `curve` (0 = P-256, 1 = P-384, 2 = P-521).
/// Returns NULL on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_ec_key_generate(curve: u32) -> *mut EcKeyHandle {
    let Some(id) = curve_of(curve) else {
        return std::ptr::null_mut();
    };
    let mut rng = OsRng::new();
    let (private, public) = match crown::ecdh::generate(id, &mut rng) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };
    if rng.failed {
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(EcKeyHandle {
        id,
        private: Some(private),
        public,
    }))
}

/// Build a key from its components. `public_point` is the SEC1 encoding
/// (`0x04 || X || Y`); when it is NULL/empty the point is derived from the
/// private scalar. `private_scalar` may be NULL for a public-only key.
///
/// Returns NULL on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_ec_key_new(
    curve: u32,
    private_scalar: *const u8,
    scalar_len: usize,
    public_point: *const u8,
    point_len: usize,
) -> *mut EcKeyHandle {
    let Some(id) = curve_of(curve) else {
        return std::ptr::null_mut();
    };
    let c = ec::curve(id);
    let private = match unsafe { slice_from_raw_parts(private_scalar, scalar_len) } {
        Some(bytes) if !bytes.is_empty() => Some(Bn::from_be_bytes(bytes)),
        _ => None,
    };
    let public = match unsafe { slice_from_raw_parts(public_point, point_len) } {
        Some(bytes) if !bytes.is_empty() => match Point::from_bytes(&c, bytes) {
            Ok(p) if p.is_on_curve(&c) => p,
            _ => return std::ptr::null_mut(),
        },
        _ => match &private {
            Some(d) => ec::mul_base(&c, d),
            None => return std::ptr::null_mut(),
        },
    };
    Box::into_raw(Box::new(EcKeyHandle {
        id,
        private,
        public,
    }))
}

/// Curve id of a key handle (0 = P-256, 1 = P-384, 2 = P-521), or
/// `UINT32_MAX` on a NULL argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_ec_key_curve(key: *const EcKeyHandle) -> u32 {
    if key.is_null() {
        return u32::MAX;
    }
    match unsafe { (*key).id } {
        CurveId::P256 => 0,
        CurveId::P384 => 1,
        CurveId::P521 => 2,
    }
}

/// Release a key handle. NULL is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_ec_key_free(key: *mut EcKeyHandle) {
    if !key.is_null() {
        drop(unsafe { Box::from_raw(key) });
    }
}

/// Write the SEC1 uncompressed public point into `out`.
///
/// Returns the number of bytes written, or 0 on failure (including `out` too
/// small — the required size is `2 * field_bytes + 1`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_ec_key_public(
    key: *const EcKeyHandle,
    out: *mut u8,
    out_len: usize,
) -> usize {
    if key.is_null() || out.is_null() {
        return 0;
    }
    let key = unsafe { &*key };
    let bytes = key.public.to_bytes_with(&ec::curve(key.id));
    if bytes.len() > out_len {
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    bytes.len()
}

/// ECDH: compute the shared secret (the X coordinate, left-padded to the
/// field size) between `key` (which must hold a private scalar) and the SEC1
/// `peer_point`.
///
/// Returns the number of bytes written, or 0 on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_ecdh_compute(
    key: *const EcKeyHandle,
    peer_point: *const u8,
    peer_len: usize,
    out: *mut u8,
    out_len: usize,
) -> usize {
    if key.is_null() || out.is_null() || peer_point.is_null() {
        return 0;
    }
    let key = unsafe { &*key };
    let Some(Some(private)) = Some(key.private.as_ref()) else {
        return 0;
    };
    let c = ec::curve(key.id);
    let Some(peer_bytes) = (unsafe { slice_from_raw_parts(peer_point, peer_len) }) else {
        return 0;
    };
    let Ok(peer) = Point::from_bytes(&c, peer_bytes) else {
        return 0;
    };
    let Ok(shared) = crown::ecdh::agree(key.id, private, &peer) else {
        return 0;
    };
    if shared.len() > out_len {
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(shared.as_ptr(), out, shared.len()) };
    shared.len()
}

/// ECDSA signature over an already-computed digest. The signature is
/// `r || s`, each left-padded to the field size (RFC 5656 / RFC 4253 wire
/// form).
///
/// Returns the number of bytes written, or 0 on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_ecdsa_sign_digest(
    key: *const EcKeyHandle,
    digest: *const u8,
    digest_len: usize,
    out: *mut u8,
    out_len: usize,
) -> usize {
    if key.is_null() || out.is_null() {
        return 0;
    }
    let key = unsafe { &*key };
    let Some(private) = key.private.as_ref() else {
        return 0;
    };
    let Some(digest) = (unsafe { slice_from_raw_parts(digest, digest_len) }) else {
        return 0;
    };
    let mut rng = OsRng::new();
    let Ok((r, s)) = ecdsa::sign_digest(key.id, private, digest, &mut rng) else {
        return 0;
    };
    if rng.failed {
        return 0;
    }
    let c = ec::curve(key.id);
    let n = ec::field_bytes(&c);
    let need = n * 2;
    if out_len < need {
        return 0;
    }
    let (Ok(r), Ok(s)) = (r.to_be_bytes_padded(n), s.to_be_bytes_padded(n)) else {
        return 0;
    };
    unsafe {
        std::ptr::copy_nonoverlapping(r.as_ptr(), out, n);
        std::ptr::copy_nonoverlapping(s.as_ptr(), out.add(n), n);
    }
    need
}

/// ECDSA verification over an already-computed digest. `sig` is `r || s`,
/// each left-padded to the field size.
///
/// Returns 1 when the signature is valid, 0 otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_ecdsa_verify_digest(
    curve: u32,
    public_point: *const u8,
    point_len: usize,
    digest: *const u8,
    digest_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    let Some(id) = curve_of(curve) else {
        return 0;
    };
    let (Some(point), Some(digest), Some(sig)) = (
        unsafe { slice_from_raw_parts(public_point, point_len) },
        unsafe { slice_from_raw_parts(digest, digest_len) },
        unsafe { slice_from_raw_parts(sig, sig_len) },
    ) else {
        return 0;
    };
    let c = ec::curve(id);
    let n = ec::field_bytes(&c);
    if sig.len() != n * 2 {
        return 0;
    }
    let Ok(public) = Point::from_bytes(&c, point) else {
        return 0;
    };
    let r = Bn::from_be_bytes(&sig[..n]);
    let s = Bn::from_be_bytes(&sig[n..]);
    matches!(ecdsa::verify_digest(id, &public, digest, &r, &s), Ok(true)) as i32
}

/*******************************************************************/
/*
 * RSA (PKCS#1 v1.5 over a precomputed digest)
 */

/// Opaque RSA key handle: the public part is always present, the private
/// part only for keys loaded with `crown_rsa_new_private`.
pub struct RsaKeyHandle {
    public: RsaPublicKey,
    private: Option<RsaPrivateKey>,
}

/// Build a public-only RSA key from `n` and `e`. Returns NULL on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_rsa_new_public(
    n: *const u8,
    n_len: usize,
    e: *const u8,
    e_len: usize,
) -> *mut RsaKeyHandle {
    let (Some(n), Some(e)) = (unsafe { slice_from_raw_parts(n, n_len) }, unsafe {
        slice_from_raw_parts(e, e_len)
    }) else {
        return std::ptr::null_mut();
    };
    match RsaPublicKey::from_components(n, e) {
        Ok(public) => Box::into_raw(Box::new(RsaKeyHandle {
            public,
            private: None,
        })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Build an RSA key from its components. `d` and the CRT parameters
/// (`p`, `q`, `dp`, `dq`, `qinv`) may be NULL/empty for a public-only key;
/// the CRT parameters are optional even when `d` is present.
///
/// Returns NULL on failure.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_rsa_new_private(
    n: *const u8,
    n_len: usize,
    e: *const u8,
    e_len: usize,
    d: *const u8,
    d_len: usize,
    p: *const u8,
    p_len: usize,
    q: *const u8,
    q_len: usize,
    dp: *const u8,
    dp_len: usize,
    dq: *const u8,
    dq_len: usize,
    qinv: *const u8,
    qinv_len: usize,
) -> *mut RsaKeyHandle {
    let part = |ptr: *const u8, len: usize| -> Option<&[u8]> {
        match unsafe { slice_from_raw_parts(ptr, len) } {
            Some(bytes) if !bytes.is_empty() => Some(bytes),
            _ => None,
        }
    };
    let (Some(n), Some(e)) = (part(n, n_len), part(e, e_len)) else {
        return std::ptr::null_mut();
    };
    let public = match RsaPublicKey::from_components(n, e) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };
    let Some(d) = part(d, d_len) else {
        return Box::into_raw(Box::new(RsaKeyHandle {
            public,
            private: None,
        }));
    };
    match RsaPrivateKey::from_components(
        n,
        e,
        d,
        part(p, p_len),
        part(q, q_len),
        part(dp, dp_len),
        part(dq, dq_len),
        part(qinv, qinv_len),
    ) {
        Ok(private) => Box::into_raw(Box::new(RsaKeyHandle {
            public,
            private: Some(private),
        })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Release an RSA key handle. NULL is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_rsa_free(key: *mut RsaKeyHandle) {
    if !key.is_null() {
        drop(unsafe { Box::from_raw(key) });
    }
}

/// Write the RSA modulus (minimal big-endian) into `out`.
///
/// Returns the number of bytes written, or 0 on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_rsa_n(
    key: *const RsaKeyHandle,
    out: *mut u8,
    out_len: usize,
) -> usize {
    if key.is_null() || out.is_null() {
        return 0;
    }
    let bytes = unsafe { (*key).public.n() };
    if bytes.len() > out_len {
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    bytes.len()
}

/// Write the RSA public exponent (minimal big-endian) into `out`.
///
/// Returns the number of bytes written, or 0 on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_rsa_e(
    key: *const RsaKeyHandle,
    out: *mut u8,
    out_len: usize,
) -> usize {
    if key.is_null() || out.is_null() {
        return 0;
    }
    let bytes = unsafe { (*key).public.e() };
    if bytes.len() > out_len {
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    bytes.len()
}

/// Modulus size in bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_rsa_size(key: *const RsaKeyHandle) -> usize {
    if key.is_null() {
        return 0;
    }
    unsafe { (*key).public.size() }
}

/// DigestInfo prefixes (RFC 8017 section 9.2 notes) for the hashes SSH and
/// TLS use, keyed by digest length: 20 = SHA-1, 32 = SHA-256, 48 = SHA-384,
/// 64 = SHA-512.
fn digest_info_prefix(digest_len: usize) -> Option<&'static [u8]> {
    const SHA1: &[u8] = &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
    const SHA256: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    const SHA384: &[u8] = &[
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];
    const SHA512: &[u8] = &[
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ];
    match digest_len {
        20 => Some(SHA1),
        32 => Some(SHA256),
        48 => Some(SHA384),
        64 => Some(SHA512),
        _ => None,
    }
}

/// Build the EMSA-PKCS1-v1_5 encoded message for `digest`: the hash is
/// identified by its length (see `digest_info_prefix`).
fn emsa_pkcs1_v1_5(digest: &[u8], key_size: usize) -> Option<Vec<u8>> {
    let prefix = digest_info_prefix(digest.len())?;
    let t_len = prefix.len() + digest.len();
    if key_size < t_len + 11 {
        return None;
    }
    let mut em = vec![0u8; key_size];
    em[0] = 0x00;
    em[1] = 0x01;
    let ps_len = key_size - t_len - 3;
    for b in &mut em[2..2 + ps_len] {
        *b = 0xff;
    }
    em[2 + ps_len] = 0x00;
    em[3 + ps_len..3 + ps_len + prefix.len()].copy_from_slice(prefix);
    em[3 + ps_len + prefix.len()..].copy_from_slice(digest);
    Some(em)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// PKCS#1 v1.5 signature over an already-computed digest.
///
/// Returns the number of signature bytes written, or 0 on failure (wrong key
/// type, unknown digest length, or `out` too small).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_rsa_sign_digest(
    key: *const RsaKeyHandle,
    digest: *const u8,
    digest_len: usize,
    out: *mut u8,
    out_len: usize,
) -> usize {
    if key.is_null() || out.is_null() {
        return 0;
    }
    let key = unsafe { &*key };
    let Some(private) = key.private.as_ref() else {
        return 0;
    };
    let Some(digest) = (unsafe { slice_from_raw_parts(digest, digest_len) }) else {
        return 0;
    };
    let Some(em) = emsa_pkcs1_v1_5(digest, key.public.size()) else {
        return 0;
    };
    let Ok(sig) = private.decrypt_raw(&em) else {
        return 0;
    };
    if sig.len() > out_len {
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(sig.as_ptr(), out, sig.len()) };
    sig.len()
}

/// PKCS#1 v1.5 verification of a signature over an already-computed digest.
///
/// Returns 1 when the signature is valid, 0 otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_rsa_verify_digest(
    key: *const RsaKeyHandle,
    digest: *const u8,
    digest_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    if key.is_null() {
        return 0;
    }
    let key = unsafe { &*key };
    let (Some(digest), Some(sig)) = (
        unsafe { slice_from_raw_parts(digest, digest_len) },
        unsafe { slice_from_raw_parts(sig, sig_len) },
    ) else {
        return 0;
    };
    let size = key.public.size();
    if sig.len() != size {
        return 0;
    }
    let Some(expected) = emsa_pkcs1_v1_5(digest, size) else {
        return 0;
    };
    let Ok(recovered) = key.public.encrypt_raw(sig) else {
        return 0;
    };
    constant_time_eq(&recovered, &expected) as i32
}

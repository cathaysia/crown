//! X.509 / PKCS C ABI.
//!
//! Parsing and verification for certificates, CSRs, CRLs, CMS (PKCS#7),
//! PKCS#12 containers and PKCS#8 encrypted keys. Output-producing functions
//! use the query pattern: call once with a null/too-small buffer to get the
//! required length (return value `-2`), then again with a large enough
//! buffer. `-1` is an error, `0` success, `1` true/verified, `0` false where
//! the function is a predicate.

use super::*;
use crown::asn1::pem;
use crown::pkcs12::{Bag, Pfx, SafeBag};
use crown::pkcs7::Pkcs7 as InnerPkcs7;
use crown::x509::{
    Certificate as InnerCertificate, CertificateList, CertificationRequest, Hash, PrivateKeyInfo,
    PublicKey, SignatureAlgorithm,
};

/// An opaque parsed X.509 certificate.
pub struct Certificate(InnerCertificate);

/// An opaque parsed PKCS#10 certification request.
pub struct Csr(CertificationRequest);

/// An opaque parsed X.509 CRL.
pub struct Crl(CertificateList);

/// An opaque parsed PKCS#7 / CMS object.
pub struct Pkcs7(InnerPkcs7);

/// An opaque parsed PKCS#12 PFX with its bags decrypted.
pub struct Pkcs12 {
    bags: Vec<SafeBag>,
    mac_verified: Option<bool>,
}

fn crypto_result(result: crown::error::CryptoResult<bool>) -> i32 {
    match result {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

/// Write `data` into a caller buffer, using the query pattern.
unsafe fn write_buffer(data: &[u8], out: *mut u8, out_len: *mut usize) -> i32 {
    if out_len.is_null() {
        return -1;
    }
    let needed = data.len();
    unsafe {
        if out.is_null() || *out_len < needed {
            *out_len = needed;
            return -2;
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), out, needed);
        *out_len = needed;
    }
    0
}

/// Read a byte slice argument, treating a null pointer with a zero length as
/// an empty slice.
unsafe fn optional_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        if len == 0 {
            Some(&[])
        } else {
            None
        }
    } else {
        unsafe { slice_from_raw_parts(ptr, len) }
    }
}

fn parse_certificate(data: &[u8]) -> crown::error::CryptoResult<InnerCertificate> {
    if let Ok(text) = core::str::from_utf8(data) {
        if text.contains("-----BEGIN") {
            return InnerCertificate::from_pem(text);
        }
    }
    InnerCertificate::parse(data)
}

fn hash_from_id(id: u32) -> Option<Hash> {
    Some(match id {
        0 => Hash::Sha256,
        1 => Hash::Sha1,
        2 => Hash::Sha384,
        3 => Hash::Sha512,
        4 => Hash::Sha3_256,
        5 => Hash::Sm3,
        6 => Hash::Ripemd160,
        7 => Hash::Md5,
        _ => return None,
    })
}

/// Parse a certificate from PEM or DER. Returns an opaque handle, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_parse(data: *const u8, len: usize) -> *mut Certificate {
    let Some(data) = (unsafe { slice_from_raw_parts(data, len) }) else {
        return std::ptr::null_mut();
    };
    match parse_certificate(data) {
        Ok(certificate) => Box::into_raw(Box::new(Certificate(certificate))),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a certificate handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_free(certificate: *mut Certificate) {
    if !certificate.is_null() {
        drop(unsafe { Box::from_raw(certificate) });
    }
}

/// The DER encoding of the certificate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_encode(
    certificate: *const Certificate,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(certificate) = (unsafe { ref_from_ptr(certificate) }) else {
        return -1;
    };
    unsafe { write_buffer(&certificate.0.encode(), out, out_len) }
}

/// The PEM encoding of the certificate (with a trailing newline).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_to_pem(
    certificate: *const Certificate,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(certificate) = (unsafe { ref_from_ptr(certificate) }) else {
        return -1;
    };
    unsafe { write_buffer(certificate.0.to_pem().as_bytes(), out, out_len) }
}

/// The subject name in RFC 4514 form.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_subject(
    certificate: *const Certificate,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(certificate) = (unsafe { ref_from_ptr(certificate) }) else {
        return -1;
    };
    let text = format!("{}", certificate.0.subject());
    unsafe { write_buffer(text.as_bytes(), out, out_len) }
}

/// The issuer name in RFC 4514 form.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_issuer(
    certificate: *const Certificate,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(certificate) = (unsafe { ref_from_ptr(certificate) }) else {
        return -1;
    };
    let text = format!("{}", certificate.0.issuer());
    unsafe { write_buffer(text.as_bytes(), out, out_len) }
}

/// The serial number magnitude (big-endian, without the sign octet).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_serial(
    certificate: *const Certificate,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(certificate) = (unsafe { ref_from_ptr(certificate) }) else {
        return -1;
    };
    unsafe { write_buffer(certificate.0.serial_number(), out, out_len) }
}

/// The validity window as Unix timestamps.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_validity(
    certificate: *const Certificate,
    not_before: *mut i64,
    not_after: *mut i64,
) -> i32 {
    if not_before.is_null() || not_after.is_null() {
        return -1;
    }
    let Some(certificate) = (unsafe { ref_from_ptr(certificate) }) else {
        return -1;
    };
    let validity = certificate.0.validity();
    unsafe {
        *not_before = validity.not_before.to_unix();
        *not_after = validity.not_after.to_unix();
    }
    0
}

/// Fingerprint with `hash`: 0=SHA-256, 1=SHA-1, 2=SHA-384, 3=SHA-512,
/// 4=SHA3-256, 5=SM3, 6=RIPEMD-160, 7=MD5.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_fingerprint(
    certificate: *const Certificate,
    hash: u32,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(certificate) = (unsafe { ref_from_ptr(certificate) }) else {
        return -1;
    };
    let Some(hash) = hash_from_id(hash) else {
        return -1;
    };
    match certificate.0.fingerprint(hash) {
        Ok(digest) => unsafe { write_buffer(&digest, out, out_len) },
        Err(_) => -1,
    }
}

/// The DER `SubjectPublicKeyInfo` of the certificate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_subject_public_key_info(
    certificate: *const Certificate,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(certificate) = (unsafe { ref_from_ptr(certificate) }) else {
        return -1;
    };
    let der = certificate.0.subject_public_key_info().encode();
    unsafe { write_buffer(&der, out, out_len) }
}

/// 1 when the subject equals the issuer, 0 otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_is_self_signed(certificate: *const Certificate) -> i32 {
    let Some(certificate) = (unsafe { ref_from_ptr(certificate) }) else {
        return -1;
    };
    i32::from(certificate.0.is_self_signed())
}

/// 1 when the certificate has the CA basic constraint, 0 otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_is_ca(certificate: *const Certificate) -> i32 {
    let Some(certificate) = (unsafe { ref_from_ptr(certificate) }) else {
        return -1;
    };
    i32::from(certificate.0.tbs().is_ca())
}

/// Verify the certificate signature with the issuer's public key.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_verify_signature(
    certificate: *const Certificate,
    issuer: *const Certificate,
) -> i32 {
    let (Some(certificate), Some(issuer)) =
        (unsafe { (ref_from_ptr(certificate), ref_from_ptr(issuer)) })
    else {
        return -1;
    };
    crypto_result(certificate.0.verify_signature(issuer.0.public_key()))
}

/// Verify a certificate against its issuer: name chaining, CA constraints,
/// the signature and, when `check_time` is non-zero, the validity window at
/// `now` (Unix seconds; 0 means the current time is unavailable, which is
/// treated as expired).
///
/// `sm2_id` selects the SM2 identity; pass null for the GM/T default.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_verify(
    certificate: *const Certificate,
    issuer: *const Certificate,
    now: i64,
    check_time: i32,
    sm2_id: *const u8,
    sm2_id_len: usize,
) -> i32 {
    let (Some(certificate), Some(issuer)) =
        (unsafe { (ref_from_ptr(certificate), ref_from_ptr(issuer)) })
    else {
        return -1;
    };
    let Some(sm2_id) = (unsafe { optional_slice(sm2_id, sm2_id_len) }) else {
        return -1;
    };
    let now = if check_time != 0 { Some(now) } else { None };
    let result = if sm2_id.is_empty() {
        certificate.0.verify(&issuer.0, now)
    } else {
        certificate.0.verify_with_sm2_id(&issuer.0, now, sm2_id)
    };
    match result {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

/// Parse a CSR from PEM or DER.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn csr_parse(data: *const u8, len: usize) -> *mut Csr {
    let Some(data) = (unsafe { slice_from_raw_parts(data, len) }) else {
        return std::ptr::null_mut();
    };
    let parsed = match core::str::from_utf8(data) {
        Ok(text) if text.contains("-----BEGIN") => CertificationRequest::from_pem(text),
        _ => CertificationRequest::parse(data),
    };
    match parsed {
        Ok(csr) => Box::into_raw(Box::new(Csr(csr))),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a CSR handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn csr_free(csr: *mut Csr) {
    if !csr.is_null() {
        drop(unsafe { Box::from_raw(csr) });
    }
}

/// The DER encoding of the CSR.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn csr_encode(csr: *const Csr, out: *mut u8, out_len: *mut usize) -> i32 {
    let Some(csr) = (unsafe { ref_from_ptr(csr) }) else {
        return -1;
    };
    unsafe { write_buffer(&csr.0.encode(), out, out_len) }
}

/// The subject name in RFC 4514 form.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn csr_subject(csr: *const Csr, out: *mut u8, out_len: *mut usize) -> i32 {
    let Some(csr) = (unsafe { ref_from_ptr(csr) }) else {
        return -1;
    };
    let text = format!("{}", csr.0.info().subject);
    unsafe { write_buffer(text.as_bytes(), out, out_len) }
}

/// The DER `SubjectPublicKeyInfo` of the CSR.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn csr_public_key_info(
    csr: *const Csr,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(csr) = (unsafe { ref_from_ptr(csr) }) else {
        return -1;
    };
    let der = csr.0.info().subject_public_key_info.encode();
    unsafe { write_buffer(&der, out, out_len) }
}

/// Verify the CSR self-signature. `sm2_id` may be null for the GM/T default.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn csr_verify_signature(
    csr: *const Csr,
    sm2_id: *const u8,
    sm2_id_len: usize,
) -> i32 {
    let Some(csr) = (unsafe { ref_from_ptr(csr) }) else {
        return -1;
    };
    let Some(sm2_id) = (unsafe { optional_slice(sm2_id, sm2_id_len) }) else {
        return -1;
    };
    let result = if sm2_id.is_empty() {
        csr.0.verify_signature()
    } else {
        csr.0.verify_signature_with_sm2_id(sm2_id)
    };
    crypto_result(result)
}

/// Parse a CRL from PEM or DER.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crl_parse(data: *const u8, len: usize) -> *mut Crl {
    let Some(data) = (unsafe { slice_from_raw_parts(data, len) }) else {
        return std::ptr::null_mut();
    };
    let parsed = match core::str::from_utf8(data) {
        Ok(text) if text.contains("-----BEGIN") => CertificateList::from_pem(text),
        _ => CertificateList::parse(data),
    };
    match parsed {
        Ok(crl) => Box::into_raw(Box::new(Crl(crl))),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a CRL handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crl_free(crl: *mut Crl) {
    if !crl.is_null() {
        drop(unsafe { Box::from_raw(crl) });
    }
}

/// The DER encoding of the CRL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crl_encode(crl: *const Crl, out: *mut u8, out_len: *mut usize) -> i32 {
    let Some(crl) = (unsafe { ref_from_ptr(crl) }) else {
        return -1;
    };
    unsafe { write_buffer(&crl.0.encode(), out, out_len) }
}

/// The issuer name in RFC 4514 form.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crl_issuer(crl: *const Crl, out: *mut u8, out_len: *mut usize) -> i32 {
    let Some(crl) = (unsafe { ref_from_ptr(crl) }) else {
        return -1;
    };
    let text = format!("{}", crl.0.tbs().issuer);
    unsafe { write_buffer(text.as_bytes(), out, out_len) }
}

/// Verify the CRL signature with the issuer certificate. `sm2_id` may be
/// null for the GM/T default.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crl_verify_signature(
    crl: *const Crl,
    issuer: *const Certificate,
    sm2_id: *const u8,
    sm2_id_len: usize,
) -> i32 {
    let (Some(crl), Some(issuer)) = (unsafe { (ref_from_ptr(crl), ref_from_ptr(issuer)) }) else {
        return -1;
    };
    let Some(sm2_id) = (unsafe { optional_slice(sm2_id, sm2_id_len) }) else {
        return -1;
    };
    let result = if sm2_id.is_empty() {
        crl.0.verify_signature(issuer.0.public_key())
    } else {
        crl.0
            .verify_signature_with_sm2_id(issuer.0.public_key(), sm2_id)
    };
    crypto_result(result)
}

/// 1 when `serial` (big-endian magnitude) is listed in the CRL, 0 when not.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crl_is_revoked(
    crl: *const Crl,
    serial: *const u8,
    serial_len: usize,
) -> i32 {
    let Some(crl) = (unsafe { ref_from_ptr(crl) }) else {
        return -1;
    };
    let Some(serial) = (unsafe { slice_from_raw_parts(serial, serial_len) }) else {
        return -1;
    };
    i32::from(crl.0.is_revoked(serial).is_some())
}

fn parse_pkcs7(data: &[u8]) -> crown::error::CryptoResult<InnerPkcs7> {
    if let Ok(text) = core::str::from_utf8(data) {
        if text.contains("-----BEGIN") {
            let block = pem::parse_first(text)?;
            return InnerPkcs7::parse(&block.data);
        }
    }
    InnerPkcs7::parse(data)
}

/// Parse a PKCS#7 / CMS object from PEM or DER.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs7_parse(data: *const u8, len: usize) -> *mut Pkcs7 {
    let Some(data) = (unsafe { slice_from_raw_parts(data, len) }) else {
        return std::ptr::null_mut();
    };
    match parse_pkcs7(data) {
        Ok(pkcs7) => Box::into_raw(Box::new(Pkcs7(pkcs7))),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a PKCS#7 handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs7_free(pkcs7: *mut Pkcs7) {
    if !pkcs7.is_null() {
        drop(unsafe { Box::from_raw(pkcs7) });
    }
}

/// 1 when the object is CMS SignedData, 0 otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs7_is_signed_data(pkcs7: *const Pkcs7) -> i32 {
    let Some(pkcs7) = (unsafe { ref_from_ptr(pkcs7) }) else {
        return -1;
    };
    i32::from(matches!(pkcs7.0, InnerPkcs7::SignedData(_)))
}

/// Number of signers, or -1 when the object is not SignedData.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs7_signer_count(pkcs7: *const Pkcs7) -> i64 {
    let Some(pkcs7) = (unsafe { ref_from_ptr(pkcs7) }) else {
        return -1;
    };
    match &pkcs7.0 {
        InnerPkcs7::SignedData(data) => data.signer_infos.len() as i64,
        _ => -1,
    }
}

/// Number of embedded certificates, or -1 when not SignedData.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs7_certificate_count(pkcs7: *const Pkcs7) -> i64 {
    let Some(pkcs7) = (unsafe { ref_from_ptr(pkcs7) }) else {
        return -1;
    };
    match &pkcs7.0 {
        InnerPkcs7::SignedData(data) => data.certificates.len() as i64,
        _ => -1,
    }
}

/// Clone the embedded certificate at `index` into a new handle, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs7_certificate(pkcs7: *const Pkcs7, index: usize) -> *mut Certificate {
    let Some(pkcs7) = (unsafe { ref_from_ptr(pkcs7) }) else {
        return std::ptr::null_mut();
    };
    let InnerPkcs7::SignedData(data) = &pkcs7.0 else {
        return std::ptr::null_mut();
    };
    match data.certificates.get(index) {
        Some(certificate) => Box::into_raw(Box::new(Certificate(certificate.clone()))),
        None => std::ptr::null_mut(),
    }
}

/// The encapsulated content (fails for detached signatures).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs7_content(
    pkcs7: *const Pkcs7,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(pkcs7) = (unsafe { ref_from_ptr(pkcs7) }) else {
        return -1;
    };
    match &pkcs7.0 {
        InnerPkcs7::SignedData(data) => match data.content(None) {
            Ok(content) => unsafe { write_buffer(content, out, out_len) },
            Err(_) => -1,
        },
        InnerPkcs7::Data(content) => unsafe { write_buffer(content, out, out_len) },
        InnerPkcs7::Other(_) => -1,
    }
}

/// Verify every signer. For detached signatures pass the content in
/// `detached`; pass null for attached content. `sm2_id` may be null for the
/// GM/T default. Returns 1 verified, 0 not, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs7_verify(
    pkcs7: *const Pkcs7,
    detached: *const u8,
    detached_len: usize,
    sm2_id: *const u8,
    sm2_id_len: usize,
) -> i32 {
    let Some(pkcs7) = (unsafe { ref_from_ptr(pkcs7) }) else {
        return -1;
    };
    let Some(detached) = (unsafe { optional_slice(detached, detached_len) }) else {
        return -1;
    };
    let Some(sm2_id) = (unsafe { optional_slice(sm2_id, sm2_id_len) }) else {
        return -1;
    };
    let InnerPkcs7::SignedData(data) = &pkcs7.0 else {
        return -1;
    };
    let detached = if detached.is_empty() {
        None
    } else {
        Some(detached)
    };
    let result = if sm2_id.is_empty() {
        data.verify(detached)
    } else {
        data.verify_with_sm2_id(detached, sm2_id)
    };
    match result {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

/// Parse a PKCS#12 PFX (DER or PEM) with its password. Shrouded key bags are
/// decrypted with the password; the MAC is verified when present and its
/// result is exposed through `pkcs12_mac_verified`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs12_parse(
    data: *const u8,
    len: usize,
    password: *const u8,
    password_len: usize,
) -> *mut Pkcs12 {
    let Some(data) = (unsafe { slice_from_raw_parts(data, len) }) else {
        return std::ptr::null_mut();
    };
    let Some(password) = (unsafe { optional_slice(password, password_len) }) else {
        return std::ptr::null_mut();
    };
    let parsed = match core::str::from_utf8(data) {
        Ok(text) if text.contains("-----BEGIN") => Pfx::from_pem(text),
        _ => Pfx::parse(data),
    };
    let Ok(pfx) = parsed else {
        return std::ptr::null_mut();
    };
    let mac_verified = pfx.mac.as_ref().map(|_| pfx.verify_mac(password).is_ok());
    let Ok(bags) = pfx.decoded_bags(password) else {
        return std::ptr::null_mut();
    };
    // Decrypt every individually shrouded key bag so callers see plain keys.
    let mut decoded = Vec::with_capacity(bags.len());
    for bag in bags {
        match bag.bag {
            Bag::ShroudedKey(ref info) => {
                match crown::x509::pbe::decrypt_private_key(info, password) {
                    Ok(key) => decoded.push(SafeBag {
                        bag: Bag::Key(key),
                        attributes: bag.attributes.clone(),
                    }),
                    Err(_) => return std::ptr::null_mut(),
                }
            }
            _ => decoded.push(bag),
        }
    }
    Box::into_raw(Box::new(Pkcs12 {
        bags: decoded,
        mac_verified,
    }))
}

/// Free a PKCS#12 handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs12_free(pkcs12: *mut Pkcs12) {
    if !pkcs12.is_null() {
        drop(unsafe { Box::from_raw(pkcs12) });
    }
}

/// 1 when the PFX MAC verified, 0 when there is no MAC, -1 when it did not
/// verify.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs12_mac_verified(pkcs12: *const Pkcs12) -> i32 {
    let Some(pkcs12) = (unsafe { ref_from_ptr(pkcs12) }) else {
        return -1;
    };
    match pkcs12.mac_verified {
        Some(true) => 1,
        Some(false) => -1,
        None => 0,
    }
}

/// Number of bags in the PFX.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs12_bag_count(pkcs12: *const Pkcs12) -> i64 {
    let Some(pkcs12) = (unsafe { ref_from_ptr(pkcs12) }) else {
        return -1;
    };
    pkcs12.bags.len() as i64
}

/// Kind of the bag at `index`: 0 certificate, 1 private key, 2 CRL,
/// 3 secret, 4 safeContents, 5 other; -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs12_bag_kind(pkcs12: *const Pkcs12, index: usize) -> i32 {
    let Some(pkcs12) = (unsafe { ref_from_ptr(pkcs12) }) else {
        return -1;
    };
    match pkcs12.bags.get(index).map(|bag| &bag.bag) {
        Some(Bag::Cert(_)) => 0,
        Some(Bag::Key(_) | Bag::ShroudedKey(_)) => 1,
        Some(Bag::Crl(_)) => 2,
        Some(Bag::Secret { .. }) => 3,
        Some(Bag::SafeContents(_)) => 4,
        Some(Bag::Other { .. }) => 5,
        None => -1,
    }
}

/// The `friendlyName` of the bag at `index`: 1 present, 0 absent, -1 error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs12_bag_friendly_name(
    pkcs12: *const Pkcs12,
    index: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(pkcs12) = (unsafe { ref_from_ptr(pkcs12) }) else {
        return -1;
    };
    let Some(bag) = pkcs12.bags.get(index) else {
        return -1;
    };
    match bag.friendly_name() {
        Some(name) => {
            if unsafe { write_buffer(name.as_bytes(), out, out_len) } == 0 {
                1
            } else {
                -2
            }
        }
        None => 0,
    }
}

/// Clone the certificate bag at `index` into a new handle, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs12_bag_certificate(
    pkcs12: *const Pkcs12,
    index: usize,
) -> *mut Certificate {
    let Some(pkcs12) = (unsafe { ref_from_ptr(pkcs12) }) else {
        return std::ptr::null_mut();
    };
    match pkcs12.bags.get(index).map(|bag| &bag.bag) {
        Some(Bag::Cert(certificate)) => Box::into_raw(Box::new(Certificate(certificate.clone()))),
        _ => std::ptr::null_mut(),
    }
}

/// Clone the CRL bag at `index` into a new handle, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs12_bag_crl(pkcs12: *const Pkcs12, index: usize) -> *mut Crl {
    let Some(pkcs12) = (unsafe { ref_from_ptr(pkcs12) }) else {
        return std::ptr::null_mut();
    };
    match pkcs12.bags.get(index).map(|bag| &bag.bag) {
        Some(Bag::Crl(crl)) => Box::into_raw(Box::new(Crl(crl.clone()))),
        _ => std::ptr::null_mut(),
    }
}

/// The PKCS#8 DER of the key bag at `index`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs12_bag_private_key(
    pkcs12: *const Pkcs12,
    index: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(pkcs12) = (unsafe { ref_from_ptr(pkcs12) }) else {
        return -1;
    };
    match pkcs12.bags.get(index).map(|bag| &bag.bag) {
        Some(Bag::Key(info)) => unsafe { write_buffer(&info.encode(), out, out_len) },
        _ => -1,
    }
}

/// Decrypt a PKCS#8 `EncryptedPrivateKeyInfo` DER, writing plain PKCS#8 DER.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs8_decrypt(
    data: *const u8,
    len: usize,
    password: *const u8,
    password_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(data) = (unsafe { slice_from_raw_parts(data, len) }) else {
        return -1;
    };
    let Some(password) = (unsafe { optional_slice(password, password_len) }) else {
        return -1;
    };
    let encrypted = match core::str::from_utf8(data) {
        Ok(text) if text.contains("-----BEGIN") => match pem::parse_first(text) {
            Ok(block) => crown::x509::EncryptedPrivateKeyInfo::parse(&block.data),
            Err(_) => return -1,
        },
        _ => crown::x509::EncryptedPrivateKeyInfo::parse(data),
    };
    let Ok(encrypted) = encrypted else {
        return -1;
    };
    match crown::x509::pbe::decrypt_private_key(&encrypted, password) {
        Ok(info) => unsafe { write_buffer(&info.encode(), out, out_len) },
        Err(_) => -1,
    }
}

/// Encrypt PKCS#8 DER with PBES2. `cipher`: 0=AES-128-CBC, 1=AES-192-CBC,
/// 2=AES-256-CBC, 3=3DES.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs8_encrypt(
    data: *const u8,
    len: usize,
    password: *const u8,
    password_len: usize,
    cipher: u32,
    iterations: u32,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    use crown::x509::pbe::{encrypt_private_key, Pbes2Cipher};
    let Some(data) = (unsafe { slice_from_raw_parts(data, len) }) else {
        return -1;
    };
    let Some(password) = (unsafe { optional_slice(password, password_len) }) else {
        return -1;
    };
    let cipher = match cipher {
        0 => Pbes2Cipher::Aes128Cbc { iv: Vec::new() },
        1 => Pbes2Cipher::Aes192Cbc { iv: Vec::new() },
        2 => Pbes2Cipher::Aes256Cbc { iv: Vec::new() },
        3 => Pbes2Cipher::DesEde3Cbc { iv: Vec::new() },
        _ => return -1,
    };
    let mut rng = OsRng;
    match encrypt_private_key(data, password, cipher, iterations, &mut rng) {
        Ok(encrypted) => unsafe { write_buffer(&encrypted.encode(), out, out_len) },
        Err(_) => -1,
    }
}

/// The DER `SubjectPublicKeyInfo` of a PKCS#8 key.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs8_public_key_info(
    data: *const u8,
    len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(data) = (unsafe { slice_from_raw_parts(data, len) }) else {
        return -1;
    };
    let parsed = match core::str::from_utf8(data) {
        Ok(text) if text.contains("-----BEGIN") => match pem::parse_first(text) {
            Ok(block) => PrivateKeyInfo::parse(&block.data),
            Err(_) => return -1,
        },
        _ => PrivateKeyInfo::parse(data),
    };
    let Ok(info) = parsed else {
        return -1;
    };
    let Ok(key) = info.decode() else {
        return -1;
    };
    let Ok(public) = key.public_key() else {
        return -1;
    };
    match crown::x509::SubjectPublicKeyInfo::from_public_key(&public) {
        Ok(spki) => unsafe { write_buffer(&spki.encode(), out, out_len) },
        Err(_) => -1,
    }
}

/// The algorithm OID (dotted string) of a public key, e.g.
/// `"1.2.840.113549.1.1.1"` for RSA.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn public_key_algorithm(
    data: *const u8,
    len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(data) = (unsafe { slice_from_raw_parts(data, len) }) else {
        return -1;
    };
    let parsed = match core::str::from_utf8(data) {
        Ok(text) if text.contains("-----BEGIN") => match pem::parse_first(text) {
            Ok(block) => crown::x509::SubjectPublicKeyInfo::parse(&block.data),
            Err(_) => return -1,
        },
        _ => crown::x509::SubjectPublicKeyInfo::parse(data),
    };
    let Ok(spki) = parsed else {
        return -1;
    };
    let name = match &spki.public_key {
        PublicKey::Rsa(_) => "rsaEncryption".to_string(),
        PublicKey::Ec { .. } => "id-ecPublicKey".to_string(),
        PublicKey::Ed25519(_) => "Ed25519".to_string(),
        PublicKey::Ed448(_) => "Ed448".to_string(),
        PublicKey::X25519(_) => "X25519".to_string(),
        PublicKey::X448(_) => "X448".to_string(),
        PublicKey::Sm2(_) => "SM2".to_string(),
        PublicKey::Dsa { .. } => "dsaEncryption".to_string(),
        PublicKey::MlDsa(key) => format!("{:?}", key.variant()),
        PublicKey::SlhDsa(key) => key.variant().name().to_string(),
        PublicKey::Unknown { algorithm, .. } => algorithm.oid.to_string(),
    };
    unsafe { write_buffer(name.as_bytes(), out, out_len) }
}

/// Number of bits of a public key, or -1 when not meaningful.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn public_key_bits(data: *const u8, len: usize) -> i64 {
    let Some(data) = (unsafe { slice_from_raw_parts(data, len) }) else {
        return -1;
    };
    let parsed = match core::str::from_utf8(data) {
        Ok(text) if text.contains("-----BEGIN") => match pem::parse_first(text) {
            Ok(block) => crown::x509::SubjectPublicKeyInfo::parse(&block.data),
            Err(_) => return -1,
        },
        _ => crown::x509::SubjectPublicKeyInfo::parse(data),
    };
    let Ok(spki) = parsed else {
        return -1;
    };
    match &spki.public_key {
        PublicKey::Rsa(key) => key.size() as i64 * 8,
        PublicKey::Ec { curve, .. } => match curve {
            crown::ec::CurveId::P256 => 256,
            crown::ec::CurveId::P384 => 384,
            crown::ec::CurveId::P521 => 521,
        },
        PublicKey::Sm2(_) => 256,
        PublicKey::Dsa { params, .. } => params.p.bit_len() as i64,
        PublicKey::Ed25519(_) => 256,
        PublicKey::X25519(_) => 256,
        PublicKey::Ed448(_) => 456,
        PublicKey::X448(_) => 448,
        _ => -1,
    }
}

/// `/dev/urandom` byte source for the randomized PKCS#8 encryption.
struct OsRng;

impl crown::rng::Rng for OsRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        use std::io::Read;
        let _ = std::fs::File::open("/dev/urandom").and_then(|mut file| file.read_exact(out));
    }
}

/// The signature algorithm OID of a certificate as a dotted string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_signature_algorithm(
    certificate: *const Certificate,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let Some(certificate) = (unsafe { ref_from_ptr(certificate) }) else {
        return -1;
    };
    let text = certificate.0.signature_algorithm().oid.to_string();
    unsafe { write_buffer(text.as_bytes(), out, out_len) }
}

/// Whether the certificate signature algorithm is one crown can verify.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_signature_supported(certificate: *const Certificate) -> i32 {
    let Some(certificate) = (unsafe { ref_from_ptr(certificate) }) else {
        return -1;
    };
    i32::from(SignatureAlgorithm::from_identifier(certificate.0.signature_algorithm()).is_ok())
}

/// An opaque trust store for RFC 5280 path validation.
pub struct CertificateStore {
    store: crown::x509::Store,
    untrusted: Vec<InnerCertificate>,
}

/// Create an empty certificate store.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_store_new() -> *mut CertificateStore {
    Box::into_raw(Box::new(CertificateStore {
        store: crown::x509::Store::new(),
        untrusted: Vec::new(),
    }))
}

/// Free a certificate store.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_store_free(store: *mut CertificateStore) {
    if !store.is_null() {
        drop(unsafe { Box::from_raw(store) });
    }
}

/// Add a trust anchor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_store_add_trusted(
    store: *mut CertificateStore,
    certificate: *const Certificate,
) -> i32 {
    let (Some(store), Some(certificate)) = (unsafe { (store.as_mut(), ref_from_ptr(certificate)) })
    else {
        return -1;
    };
    store.store.add_trusted_certificate(certificate.0.clone());
    0
}

/// Add an untrusted intermediate certificate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_store_add_untrusted(
    store: *mut CertificateStore,
    certificate: *const Certificate,
) -> i32 {
    let (Some(store), Some(certificate)) = (unsafe { (store.as_mut(), ref_from_ptr(certificate)) })
    else {
        return -1;
    };
    store.untrusted.push(certificate.0.clone());
    0
}

/// Add a CRL (DER) to the store.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_store_add_crl(
    store: *mut CertificateStore,
    crl: *const u8,
    crl_len: usize,
) -> i32 {
    let Some(store) = (unsafe { store.as_mut() }) else {
        return -1;
    };
    let Some(data) = (unsafe { slice_from_raw_parts(crl, crl_len) }) else {
        return -1;
    };
    match crown::x509::CertificateList::parse(data) {
        Ok(parsed) => {
            store.store.add_crl(parsed);
            0
        }
        Err(_) => -1,
    }
}

/// Verify `certificate` against the store.
///
/// `purpose`: 0 any, 1 sslServer, 2 sslClient, 3 smimeSign, 4 smimeEncrypt,
/// 5 codeSigning, 6 ocspHelper, 7 timeStamping, 8 crlSign.
/// `flags` bitmask: 1 CRL check, 2 CRL check all, 4 policy check,
/// 8 explicit policy, 16 inhibit anyPolicy, 32 x509 strict.
/// Returns 1 verified, 0 not, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn certificate_store_verify(
    store: *const CertificateStore,
    certificate: *const Certificate,
    now: i64,
    check_time: i32,
    purpose: u32,
    flags: u32,
) -> i32 {
    let (Some(store), Some(certificate)) =
        (unsafe { (ref_from_ptr(store), ref_from_ptr(certificate)) })
    else {
        return -1;
    };
    use crown::x509::Purpose;
    let purpose = match purpose {
        0 => Purpose::Any,
        1 => Purpose::SslServer,
        2 => Purpose::SslClient,
        3 => Purpose::SmimeSign,
        4 => Purpose::SmimeEncrypt,
        5 => Purpose::CodeSigning,
        6 => Purpose::OcspHelper,
        7 => Purpose::TimeStamping,
        8 => Purpose::CrlSign,
        _ => return -1,
    };
    let options = crown::x509::VerifyOptions {
        time: (check_time != 0).then_some(now),
        purpose,
        flags: crown::x509::VerifyFlags {
            crl_check: flags & 1 != 0,
            crl_check_all: flags & 2 != 0,
            policy_check: flags & 4 != 0,
            explicit_policy: flags & 8 != 0,
            inhibit_any_policy: flags & 16 != 0,
            x509_strict: flags & 32 != 0,
        },
        untrusted: store.untrusted.clone(),
        ..Default::default()
    };
    match crown::x509::verify_certificate(&store.store, &certificate.0, &options) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

/// Encrypt `content` to one RSA recipient certificate (AES-256-CBC).
/// Output is a DER `ContentInfo`; use the query pattern for `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cms_encrypt(
    content: *const u8,
    content_len: usize,
    recipient: *const Certificate,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let (Some(content), Some(recipient)) = (unsafe {
        (
            slice_from_raw_parts(content, content_len),
            ref_from_ptr(recipient),
        )
    }) else {
        return -1;
    };
    let enveloped = match crown::cms::EnvelopedDataBuilder::new(content.to_vec())
        .add_rsa_recipient(&recipient.0, crown::cms::Cipher::Aes256Cbc, &mut OsRng)
        .build(&mut OsRng)
    {
        Ok(enveloped) => enveloped,
        Err(_) => return -1,
    };
    let der = enveloped.to_content_info().encode();
    unsafe { write_buffer(&der, out, out_len) }
}

/// Decrypt a CMS EnvelopedData (DER) with an RSA key (PKCS#8 DER) and its
/// certificate. Returns the plaintext with the query pattern.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cms_decrypt(
    data: *const u8,
    data_len: usize,
    key: *const u8,
    key_len: usize,
    certificate: *const Certificate,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let (Some(data), Some(key), Some(certificate)) = (unsafe {
        (
            slice_from_raw_parts(data, data_len),
            slice_from_raw_parts(key, key_len),
            ref_from_ptr(certificate),
        )
    }) else {
        return -1;
    };
    let Ok(info) = PrivateKeyInfo::parse(key) else {
        return -1;
    };
    let Ok(private_key) = info.decode() else {
        return -1;
    };
    let Ok(content_info) = crown::pkcs7::ContentInfo::parse(data) else {
        return -1;
    };
    let Ok(enveloped) = crown::cms::EnvelopedData::from_content_info(&content_info) else {
        return -1;
    };
    match enveloped.decrypt_with_key(&private_key, &certificate.0) {
        Ok(plaintext) => unsafe { write_buffer(&plaintext, out, out_len) },
        Err(_) => -1,
    }
}

/// Decrypt a CMS EnvelopedData (DER) with a password recipient.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cms_decrypt_password(
    data: *const u8,
    data_len: usize,
    password: *const u8,
    password_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let (Some(data), Some(password)) = (unsafe {
        (
            slice_from_raw_parts(data, data_len),
            optional_slice(password, password_len),
        )
    }) else {
        return -1;
    };
    let Ok(content_info) = crown::pkcs7::ContentInfo::parse(data) else {
        return -1;
    };
    let Ok(enveloped) = crown::cms::EnvelopedData::from_content_info(&content_info) else {
        return -1;
    };
    match enveloped.decrypt_with_password(password) {
        Ok(plaintext) => unsafe { write_buffer(&plaintext, out, out_len) },
        Err(_) => -1,
    }
}

/// Verify an OCSP response (DER or PEM) against its issuer certificate.
/// Returns 1 verified, 0 not, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ocsp_response_verify(
    response: *const u8,
    response_len: usize,
    issuer: *const Certificate,
) -> i32 {
    let (Some(response), Some(issuer)) = (unsafe {
        (
            slice_from_raw_parts(response, response_len),
            ref_from_ptr(issuer),
        )
    }) else {
        return -1;
    };
    let parsed = match core::str::from_utf8(response) {
        Ok(text) if text.contains("-----BEGIN") => crown::ocsp::OcspResponse::from_pem(text),
        _ => crown::ocsp::OcspResponse::parse(response),
    };
    let Ok(parsed) = parsed else {
        return -1;
    };
    match parsed.verify(&issuer.0) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

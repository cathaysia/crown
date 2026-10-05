//! CMS (RFC 5652) content types beyond `SignedData`.
//!
//! `EnvelopedData` (RSA key transport, ECDH key agreement, KEK and password
//! recipients), `AuthEnvelopedData` (RFC 5083), `EncryptedData` and
//! `DigestedData`, with builder, parser and decryption entry points.
//!
//! ```
//! use crown::cms::{ContentInfo, EnvelopedData};
//! use crown::x509::cert::Certificate;
//! use crown::x509::keys::PrivateKeyInfo;
//!
//! # let der = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pki/cms_env_rsa.der"));
//! # let cert = Certificate::from_pem(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pki/leaf.pem")))?;
//! # let key_pem = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pki/rsa_pkcs8.pem"));
//! let info = ContentInfo::parse(der)?;
//! let message = EnvelopedData::from_content_info(&info)?;
//! let key_der = crown::asn1::pem::parse_first(key_pem)?.data;
//! let key = PrivateKeyInfo::parse(&key_der)?.decode()?;
//! assert_eq!(message.decrypt_with_key(&key, &cert)?, b"crown pkcs7 test payload\r\n");
//! # Ok::<(), crown::error::CryptoError>(())
//! ```
//!
//! The structures interoperate with OpenSSL's `cms` command: RSA PKCS#1 v1.5
//! and OAEP key transport, ECDH key agreement (`dhSinglePass-stdDH-*-kdf`),
//! AES key wrap for KEK recipients, PBKDF2 password recipients, and the
//! AES-CBC/AES-GCM/3DES content ciphers.

use crate::asn1::oid::ObjectIdentifier;
use crate::error::{CryptoError, CryptoResult};

/// Re-export of [`crate::pkcs7::ContentInfo`], the outer CMS container.
pub use crate::pkcs7::ContentInfo;

mod auth;
mod cipher;
mod digested;
mod encrypted;
mod enveloped;
mod recipient;

pub use auth::AuthEnvelopedData;
pub use cipher::{Cipher, ContentCipher, KeyWrapAlgorithm};
pub use digested::DigestedData;
pub use encrypted::EncryptedData;
pub use enveloped::{EncryptedContentInfo, EnvelopedData, EnvelopedDataBuilder, OriginatorInfo};
pub use recipient::{
    IssuerAndSerialNumber, KekIdentifier, KekRecipientInfo, KeyAgreeRecipientIdentifier,
    KeyAgreeRecipientInfo, KeyTransRecipientInfo, OriginatorIdentifierOrKey, OriginatorPublicKey,
    PasswordRecipientInfo, RecipientEncryptedKey, RecipientIdentifier, RecipientInfo,
    RecipientKeyIdentifier, RsaKeyEncryption,
};

/// Error unless `info` wraps the expected content type.
pub(crate) fn check_content_type(
    info: &ContentInfo,
    expected: &[u64],
    name: &str,
) -> CryptoResult<()> {
    if info.content_type.matches(expected) {
        Ok(())
    } else {
        Err(CryptoError::UnsupportedOperation(alloc::format!(
            "cms: not {name} (content type {})",
            info.content_type
        )))
    }
}

// ---------------------------------------------------------------------------
// CMS-specific object identifiers
// ---------------------------------------------------------------------------

/// `rsaesOaep` (1.2.840.113549.1.1.7).
pub(crate) const OID_RSAES_OAEP: &[u64] = &[1, 2, 840, 113549, 1, 1, 7];
/// `pSpecified` (1.2.840.113549.1.1.9).
pub(crate) const OID_PSPECIFIED: &[u64] = &[1, 2, 840, 113549, 1, 1, 9];
/// `aes-128-gcm` (2.16.840.1.101.3.4.1.6).
pub(crate) const OID_AES_128_GCM: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 6];
/// `aes-192-gcm` (2.16.840.1.101.3.4.1.26).
pub(crate) const OID_AES_192_GCM: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 26];
/// `aes-256-gcm` (2.16.840.1.101.3.4.1.46).
pub(crate) const OID_AES_256_GCM: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 46];
/// `id-aes128-wrap` (2.16.840.1.101.3.4.1.5).
pub(crate) const OID_AES_128_WRAP: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 5];
/// `id-aes192-wrap` (2.16.840.1.101.3.4.1.25).
pub(crate) const OID_AES_192_WRAP: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 25];
/// `id-aes256-wrap` (2.16.840.1.101.3.4.1.45).
pub(crate) const OID_AES_256_WRAP: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 45];
/// `id-alg-PWRI-KEK` (1.2.840.113549.1.9.16.3.9).
pub(crate) const OID_PWRI_KEK: &[u64] = &[1, 2, 840, 113549, 1, 9, 16, 3, 9];
/// `id-smime-ct-authEnvelopedData` (1.2.840.113549.1.9.16.1.23).
pub(crate) const OID_AUTH_ENVELOPED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 9, 16, 1, 23];

/// `dhSinglePass-stdDH-sha224kdf-scheme` (1.3.132.1.11.0, SECG).
pub(crate) const OID_DH_STD_SHA224: &[u64] = &[1, 3, 132, 1, 11, 0];
/// `dhSinglePass-stdDH-sha256kdf-scheme` (1.3.132.1.11.1, SECG).
pub(crate) const OID_DH_STD_SHA256: &[u64] = &[1, 3, 132, 1, 11, 1];
/// `dhSinglePass-stdDH-sha384kdf-scheme` (1.3.132.1.11.2, SECG).
pub(crate) const OID_DH_STD_SHA384: &[u64] = &[1, 3, 132, 1, 11, 2];
/// `dhSinglePass-stdDH-sha512kdf-scheme` (1.3.132.1.11.3, SECG).
pub(crate) const OID_DH_STD_SHA512: &[u64] = &[1, 3, 132, 1, 11, 3];
/// `dhSinglePass-stdDH-sha1kdf-scheme` (1.3.133.16.840.63.0.2, ANSI X9.63).
pub(crate) const OID_DH_STD_SHA1: &[u64] = &[1, 3, 133, 16, 840, 63, 0, 2];

/// Build an [`ObjectIdentifier`] from trusted literal arcs.
pub(crate) fn oid_of(arcs: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::new(arcs).expect("static oid")
}

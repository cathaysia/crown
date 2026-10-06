//! X.509 certificates, CSRs, CRLs, PKCS#8 keys and PBE.
//!
//! Parsing, encoding, signing and signature verification for the PKI
//! structures used by TLS, S/MIME and key containers:
//!
//! - [`Certificate`] parses/encodes certificates, PEM armour, X.509 v3
//!   extensions, and verifies or creates signatures;
//! - [`CertificationRequest`] handles PKCS#10 CSRs;
//! - [`CertificateList`] handles CRLs;
//! - [`SubjectPublicKeyInfo`] / [`PrivateKeyInfo`] cover key structures for
//!   RSA, NIST EC, Ed25519/Ed448, X25519/X448, SM2, DSA, ML-DSA and SLH-DSA;
//! - [`EncryptedPrivateKeyInfo`] handles PKCS#8 encrypted keys via [`pbe`]
//!   (PBES2 and the legacy PKCS#12 schemes).
//!
//! Signature algorithms are dispatched by OID through
//! [`SignatureAlgorithm`], which covers RSA PKCS#1 v1.5 and PSS, ECDSA,
//! Ed25519/Ed448, SM2, DSA, ML-DSA and SLH-DSA.
//!
//! ```
//! use crown::x509::Certificate;
//!
//! # let pem = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pki/ca.pem"));
//! let certificate = Certificate::from_pem(pem)?;
//! assert!(certificate.is_self_signed());
//! assert!(certificate.verify_signature(certificate.public_key())?);
//! # Ok::<(), crown::error::CryptoError>(())
//! ```
//!
//! Full RFC 5280 path validation (chain building, name constraints, policy
//! processing, CRL/Delta-CRL revocation) lives in [`verify`]; OCSP support in
//! [`crate::ocsp`], and `check_host`/`check_email`/`check_ip` name matching
//! on [`Certificate`].

pub mod ac;
pub mod algorithm;
pub mod attribute;
pub mod cert;
pub mod crl;
pub mod csr;
pub mod extensions;
#[cfg(feature = "std")]
pub mod http;
pub mod keys;
pub mod matching;
pub mod name;
pub mod pbe;
pub mod verify;

pub use ac::{
    AttCertIssuer, AttCertValidityPeriod, AttributeCertificate, AttributeCertificateInfo, Holder,
    IssuerSerial, ObjectDigestInfo, V2Form,
};
pub use algorithm::{AlgorithmIdentifier, Hash, SignatureAlgorithm};
pub use attribute::Attribute;
pub use cert::{Certificate, CertificateBuilder, TbsCertificate, Validity};
pub use crl::{CertificateList, RevokedCertificate, TbsCertList};
pub use csr::{CertificationRequest, CertificationRequestInfo};
pub use extensions::{
    AccessDescription, AuthorityInfoAccess, AuthorityKeyIdentifier, BasicConstraints,
    CertificateIssuer, CertificatePolicies, CrlDistributionPoints, CrlNumber, CrlReason,
    DeltaCrlIndicator, DisplayText, DistributionPoint, DistributionPointName, ExtendedKeyUsage,
    Extension, GeneralName, GeneralSubtree, InhibitAnyPolicy, InvalidityDate,
    IssuingDistributionPoint, KeyUsage, NameConstraints, NoticeReference, ParsedExtension,
    PolicyConstraints, PolicyInformation, PolicyMapping, PolicyMappings, PolicyQualifier,
    SubjectDirectoryAttributes, SubjectInfoAccess, TlsFeature, UserNotice,
};
pub use keys::{
    EncryptedPrivateKeyInfo, PrivateKey, PrivateKeyInfo, PublicKey, SubjectPublicKeyInfo,
};
pub use name::{AttributeTypeAndValue, Name, Rdn};
pub use verify::{
    verify_certificate, Purpose, Store, VerifyError, VerifyFlags, VerifyOptions, VerifyResult,
};

#[cfg(test)]
mod tests;

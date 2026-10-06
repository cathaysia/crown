//! RFC 5280 certificate path validation.
//!
//! A [`Store`] holds trust anchors and CRLs; [`verify_certificate`] builds and
//! validates a chain from a leaf certificate to a trust anchor with
//! OpenSSL `X509_verify_cert` semantics: signature and validity checks, CA
//! basic-constraints/key-usage/path-length checks, extended-key-usage
//! purposes, name constraints, policy processing and CRL/Delta-CRL revocation
//! checking.
//!
//! Network fetching (AIA/CRL Distribution Point downloads) and OCSP are out of
//! scope: intermediates and CRLs are supplied by the caller.

use alloc::vec::Vec;

use crate::asn1::oid::{self, ObjectIdentifier};
use crate::error::CryptoError;

use super::cert::Certificate;
use super::crl::CertificateList;
use super::extensions::{
    CertificatePolicies, CrlReason, DeltaCrlIndicator, Extension, GeneralName, InhibitAnyPolicy,
    IssuingDistributionPoint, NameConstraints, PolicyConstraints, PolicyMappings,
};
use super::Hash;

/// Certificate purpose, mirroring OpenSSL's `X509_PURPOSE_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Purpose {
    /// Any purpose: no extended-key-usage requirement.
    #[default]
    Any,
    /// TLS server (`serverAuth`).
    SslServer,
    /// TLS client (`clientAuth`).
    SslClient,
    /// S/MIME signing (`emailProtection`).
    SmimeSign,
    /// S/MIME encryption (`emailProtection`).
    SmimeEncrypt,
    /// Code signing (`codeSigning`).
    CodeSigning,
    /// OCSP responder (`ocspSigning`).
    OcspHelper,
    /// RFC 3161 timestamp authority (`timeStamping`).
    TimeStamping,
    /// CRL signing; the certificate must be a CA.
    CrlSign,
}

impl Purpose {
    fn eku_oid(self) -> Option<&'static [u64]> {
        Some(match self {
            Purpose::Any => return None,
            Purpose::CrlSign => return None,
            Purpose::SslServer => oid::OID_KP_SERVER_AUTH,
            Purpose::SslClient => oid::OID_KP_CLIENT_AUTH,
            Purpose::SmimeSign | Purpose::SmimeEncrypt => oid::OID_KP_EMAIL_PROTECTION,
            Purpose::CodeSigning => oid::OID_KP_CODE_SIGNING,
            Purpose::OcspHelper => oid::OID_KP_OCSP_SIGNING,
            Purpose::TimeStamping => oid::OID_KP_TIME_STAMPING,
        })
    }

    fn requires_ca(self) -> bool {
        matches!(self, Purpose::CrlSign)
    }
}

/// Verification flags, mirroring the commonly used `X509_V_FLAG_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerifyFlags {
    /// Check the leaf certificate for revocation.
    pub crl_check: bool,
    /// Check every certificate in the chain (except the trust anchor).
    pub crl_check_all: bool,
    /// Enable certificate policy processing.
    pub policy_check: bool,
    /// Require an explicit policy.
    pub explicit_policy: bool,
    /// Inhibit `anyPolicy` from the start.
    pub inhibit_any_policy: bool,
    /// Stricter extension checks (all CAs must have `basicConstraints`).
    pub x509_strict: bool,
    /// Accept a chain that ends in a non-self-signed trusted certificate
    /// (`X509_V_FLAG_PARTIAL_CHAIN`): any store certificate that issued the
    /// previous element terminates the chain.
    pub partial_chain: bool,
}

/// A set of trust anchors and CRLs used for path validation.
#[derive(Debug, Clone, Default)]
pub struct Store {
    trusted: Vec<Certificate>,
    crls: Vec<CertificateList>,
}

impl Store {
    /// An empty store.
    pub fn new() -> Self {
        Store::default()
    }

    /// Add a trust anchor.
    pub fn add_trusted_certificate(&mut self, certificate: Certificate) {
        self.trusted.push(certificate);
    }

    /// Add a CRL to the revocation set.
    pub fn add_crl(&mut self, crl: CertificateList) {
        self.crls.push(crl);
    }

    /// Add several CRLs.
    pub fn add_crls(&mut self, crls: impl IntoIterator<Item = CertificateList>) {
        self.crls.extend(crls);
    }

    /// The configured trust anchors.
    pub fn trusted_certificates(&self) -> &[Certificate] {
        &self.trusted
    }

    /// The configured CRLs.
    pub fn crls(&self) -> &[CertificateList] {
        &self.crls
    }

    fn anchor_for(&self, certificate: &Certificate) -> Option<&Certificate> {
        self.trusted.iter().find(|anchor| {
            anchor.subject() == certificate.subject() && same_public_key(anchor, certificate)
        })
    }
}

/// Inputs for [`verify_certificate`].
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// Verification time as Unix seconds; `None` uses the system clock (or
    /// disables time checks when built without `std`).
    pub time: Option<i64>,
    /// Maximum chain length including the leaf (OpenSSL's default is 100).
    pub max_depth: usize,
    /// Required purpose of the leaf certificate.
    pub purpose: Purpose,
    /// Verification flags.
    pub flags: VerifyFlags,
    /// Intermediate certificates supplied by the caller.
    pub untrusted: Vec<Certificate>,
    /// Extra CRLs supplied by the caller.
    pub untrusted_crls: Vec<CertificateList>,
    /// Initial policy set for policy processing; empty means `anyPolicy`.
    pub initial_policy_set: Vec<ObjectIdentifier>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        VerifyOptions {
            time: None,
            max_depth: 100,
            purpose: Purpose::Any,
            flags: VerifyFlags::default(),
            untrusted: Vec::new(),
            untrusted_crls: Vec::new(),
            initial_policy_set: Vec::new(),
        }
    }
}

impl VerifyOptions {
    /// Options with a fixed verification time.
    pub fn at(time: i64) -> Self {
        VerifyOptions {
            time: Some(time),
            ..Default::default()
        }
    }

    /// Set the required leaf purpose.
    pub fn purpose(mut self, purpose: Purpose) -> Self {
        self.purpose = purpose;
        self
    }

    /// Set the flags.
    pub fn flags(mut self, flags: VerifyFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Add an untrusted intermediate.
    pub fn untrusted(mut self, certificate: Certificate) -> Self {
        self.untrusted.push(certificate);
        self
    }

    /// Add an untrusted CRL.
    pub fn untrusted_crl(mut self, crl: CertificateList) -> Self {
        self.untrusted_crls.push(crl);
        self
    }
}

/// A successful verification.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    /// The validated chain, leaf first and trust anchor last.
    pub chain: Vec<Certificate>,
}

impl VerifyResult {
    /// The trust anchor (the last chain element).
    pub fn trust_anchor(&self) -> &Certificate {
        self.chain.last().expect("verified chains are never empty")
    }

    /// The leaf certificate.
    pub fn leaf(&self) -> &Certificate {
        self.chain.first().expect("verified chains are never empty")
    }
}

/// Path validation errors, with the OpenSSL `X509_V_ERR_*` code.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyError {
    /// X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT (2).
    UnableToGetIssuerCertificate,
    /// X509_V_ERR_UNABLE_TO_GET_CRL (3).
    UnableToGetCrl,
    /// X509_V_ERR_CERT_SIGNATURE_FAILURE (7).
    CertificateSignatureFailure,
    /// X509_V_ERR_CRL_SIGNATURE_FAILURE (8).
    CrlSignatureFailure,
    /// X509_V_ERR_CERT_NOT_YET_VALID (9).
    CertificateNotYetValid,
    /// X509_V_ERR_CERT_HAS_EXPIRED (10).
    CertificateExpired,
    /// X509_V_ERR_CRL_NOT_YET_VALID (11).
    CrlNotYetValid,
    /// X509_V_ERR_CRL_HAS_EXPIRED (12).
    CrlExpired,
    /// X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT (18).
    DepthZeroSelfSignedCertificate,
    /// X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN (19).
    SelfSignedCertificateInChain,
    /// X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY (20).
    UnableToGetIssuerCertificateLocally,
    /// X509_V_ERR_CERT_REVOKED (23).
    CertificateRevoked,
    /// X509_V_ERR_PATH_LENGTH_EXCEEDED (25).
    PathLengthExceeded,
    /// X509_V_ERR_INVALID_PURPOSE (26).
    InvalidPurpose,
    /// X509_V_ERR_CERT_UNTRUSTED (27).
    CertificateUntrusted,
    /// X509_V_ERR_AKID_SKID_MISMATCH (30).
    AuthorityKeyIdentifierMismatch,
    /// X509_V_ERR_KEYUSAGE_NO_CERTSIGN (32).
    KeyUsageNoCertSign,
    /// X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION (34).
    UnhandledCriticalExtension,
    /// X509_V_ERR_KEYUSAGE_NO_CRL_SIGN (35).
    KeyUsageNoCrlSign,
    /// X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION (36).
    UnhandledCriticalCrlExtension,
    /// X509_V_ERR_INVALID_NON_CA (37).
    InvalidNonCa,
    /// X509_V_ERR_INVALID_POLICY_EXTENSION (42).
    InvalidPolicyExtension,
    /// X509_V_ERR_NO_EXPLICIT_POLICY (43).
    NoExplicitPolicy,
    /// X509_V_ERR_DIFFERENT_CRL_SCOPE (44).
    DifferentCrlScope,
    /// X509_V_ERR_PERMITTED_VIOLATION (47).
    PermittedViolation,
    /// X509_V_ERR_EXCLUDED_VIOLATION (48).
    ExcludedViolation,
    /// X509_V_ERR_SUBTREE_MINMAX (49).
    UnsupportedConstraintDistance,
    /// X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE (51).
    UnsupportedConstraintType,
    /// X509_V_ERR_UNSUPPORTED_NAME_SYNTAX (53).
    UnsupportedNameSyntax,
    /// X509_V_ERR_INVALID_CA (79).
    InvalidCa,
    /// An error from the underlying parsers or signature checks.
    Other(CryptoError),
}

impl VerifyError {
    /// The OpenSSL error code.
    pub fn code(&self) -> i32 {
        match self {
            VerifyError::UnableToGetIssuerCertificate => 2,
            VerifyError::UnableToGetCrl => 3,
            VerifyError::CertificateSignatureFailure => 7,
            VerifyError::CrlSignatureFailure => 8,
            VerifyError::CertificateNotYetValid => 9,
            VerifyError::CertificateExpired => 10,
            VerifyError::CrlNotYetValid => 11,
            VerifyError::CrlExpired => 12,
            VerifyError::DepthZeroSelfSignedCertificate => 18,
            VerifyError::SelfSignedCertificateInChain => 19,
            VerifyError::UnableToGetIssuerCertificateLocally => 20,
            VerifyError::CertificateRevoked => 23,
            VerifyError::PathLengthExceeded => 25,
            VerifyError::InvalidPurpose => 26,
            VerifyError::CertificateUntrusted => 27,
            VerifyError::AuthorityKeyIdentifierMismatch => 30,
            VerifyError::KeyUsageNoCertSign => 32,
            VerifyError::UnhandledCriticalExtension => 34,
            VerifyError::KeyUsageNoCrlSign => 35,
            VerifyError::UnhandledCriticalCrlExtension => 36,
            VerifyError::InvalidNonCa => 37,
            VerifyError::InvalidPolicyExtension => 42,
            VerifyError::NoExplicitPolicy => 43,
            VerifyError::DifferentCrlScope => 44,
            VerifyError::PermittedViolation => 47,
            VerifyError::ExcludedViolation => 48,
            VerifyError::UnsupportedConstraintDistance => 49,
            VerifyError::UnsupportedConstraintType => 51,
            VerifyError::UnsupportedNameSyntax => 53,
            VerifyError::InvalidCa => 79,
            VerifyError::Other(_) => -1,
        }
    }

    /// The OpenSSL error text for this condition.
    pub fn text(&self) -> &'static str {
        match self {
            VerifyError::UnableToGetIssuerCertificate => "unable to get issuer certificate",
            VerifyError::UnableToGetCrl => "unable to get certificate CRL",
            VerifyError::CertificateSignatureFailure => "certificate signature failure",
            VerifyError::CrlSignatureFailure => "CRL signature failure",
            VerifyError::CertificateNotYetValid => "certificate is not yet valid",
            VerifyError::CertificateExpired => "certificate has expired",
            VerifyError::CrlNotYetValid => "CRL is not yet valid",
            VerifyError::CrlExpired => "CRL has expired",
            VerifyError::DepthZeroSelfSignedCertificate => "self-signed certificate",
            VerifyError::SelfSignedCertificateInChain => "self-signed certificate in chain",
            VerifyError::UnableToGetIssuerCertificateLocally => {
                "unable to get local issuer certificate"
            }
            VerifyError::CertificateRevoked => "certificate revoked",
            VerifyError::PathLengthExceeded => "path length constraint exceeded",
            VerifyError::InvalidPurpose => "unsupported certificate purpose",
            VerifyError::CertificateUntrusted => "certificate not trusted",
            VerifyError::AuthorityKeyIdentifierMismatch => "authority key identifier mismatch",
            VerifyError::KeyUsageNoCertSign => "key usage does not include certificate signing",
            VerifyError::UnhandledCriticalExtension => "unhandled critical extension",
            VerifyError::KeyUsageNoCrlSign => "key usage does not include CRL signing",
            VerifyError::UnhandledCriticalCrlExtension => "unhandled critical CRL extension",
            VerifyError::InvalidNonCa => "invalid non-CA certificate (has CA markings)",
            VerifyError::InvalidPolicyExtension => "invalid policy extension",
            VerifyError::NoExplicitPolicy => "no explicit policy",
            VerifyError::DifferentCrlScope => "different CRL scope",
            VerifyError::PermittedViolation => "permitted subtree violation",
            VerifyError::ExcludedViolation => "excluded subtree violation",
            VerifyError::UnsupportedConstraintDistance => {
                "name constraints minimum and maximum not supported"
            }
            VerifyError::UnsupportedConstraintType => "unsupported name constraint type",
            VerifyError::UnsupportedNameSyntax => "unsupported or invalid name syntax",
            VerifyError::InvalidCa => "invalid CA certificate",
            VerifyError::Other(_) => "certificate verification error",
        }
    }
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::Other(error) => write!(f, "{}", error),
            _ => f.write_str(self.text()),
        }
    }
}

impl From<CryptoError> for VerifyError {
    fn from(error: CryptoError) -> Self {
        VerifyError::Other(error)
    }
}

/// Verify `certificate` against `store` with the given options.
pub fn verify_certificate(
    store: &Store,
    certificate: &Certificate,
    options: &VerifyOptions,
) -> Result<VerifyResult, VerifyError> {
    let now = options.time.or_else(system_time);
    let chain = build_chain(store, certificate, options)?;
    check_chain(store, &chain, now, options)?;
    Ok(VerifyResult { chain })
}

fn system_time() -> Option<i64> {
    #[cfg(feature = "std")]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs() as i64)
    }
    #[cfg(not(feature = "std"))]
    {
        None
    }
}

fn same_public_key(left: &Certificate, right: &Certificate) -> bool {
    let left = left.subject_public_key_info();
    let right = right.subject_public_key_info();
    left.algorithm.oid == right.algorithm.oid && left.key == right.key
}

fn same_certificate(left: &Certificate, right: &Certificate) -> bool {
    left.tbs_der() == right.tbs_der()
}

/// The key identifier OpenSSL computes when no SKI is present.
fn key_identifier(certificate: &Certificate) -> Vec<u8> {
    if let Some(key_id) = certificate.tbs().subject_key_identifier() {
        return key_id;
    }
    Hash::Sha1
        .digest(&certificate.subject_public_key_info().key)
        .unwrap_or_default()
}

fn build_chain(
    store: &Store,
    leaf: &Certificate,
    options: &VerifyOptions,
) -> Result<Vec<Certificate>, VerifyError> {
    let mut chain = alloc::vec![leaf.clone()];
    loop {
        let current = chain.last().expect("chain is never empty");
        if let Some(anchor) = store.anchor_for(current) {
            // A trusted certificate that is a chain element terminates the
            // chain when it is self-signed, or — matching OpenSSL's
            // X509_V_FLAG_PARTIAL_CHAIN — when the flag is set. Otherwise it
            // is only a link and the chain keeps building towards a
            // self-signed anchor.
            if anchor.is_self_signed() || options.flags.partial_chain {
                let last = chain.len() - 1;
                chain[last] = anchor.clone();
                return Ok(chain);
            }
        }
        if current.subject() == current.issuer()
            && current
                .verify_signature(current.public_key())
                .unwrap_or(false)
        {
            return Err(if chain.len() == 1 {
                VerifyError::DepthZeroSelfSignedCertificate
            } else {
                VerifyError::SelfSignedCertificateInChain
            });
        }
        let Some(issuer) = find_issuer(store, &chain, options) else {
            // OpenSSL reports "unable to get local issuer certificate" at
            // depth zero and "unable to get issuer certificate" further up.
            return Err(if chain.len() == 1 {
                VerifyError::UnableToGetIssuerCertificateLocally
            } else {
                VerifyError::UnableToGetIssuerCertificate
            });
        };
        // With `partial_chain`, a trusted non-self-signed issuer terminates
        // the chain like a trust anchor.
        if options.flags.partial_chain
            && store
                .trusted_certificates()
                .iter()
                .any(|anchor| same_certificate(anchor, &issuer))
        {
            chain.push(issuer);
            return Ok(chain);
        }
        if chain.len() > options.max_depth {
            return Err(VerifyError::PathLengthExceeded);
        }
        chain.push(issuer);
    }
}

fn find_issuer(
    store: &Store,
    chain: &[Certificate],
    options: &VerifyOptions,
) -> Option<Certificate> {
    let current = chain.last().expect("chain is never empty");
    let issuer_name = current.issuer();
    let authority = current.tbs().authority_key_identifier();
    let candidates: Vec<&Certificate> = options
        .untrusted
        .iter()
        .chain(store.trusted_certificates().iter())
        .filter(|candidate| candidate.subject() == issuer_name)
        // Never reuse a chain element (loop protection).
        .filter(|candidate| {
            !chain
                .iter()
                .any(|element| same_certificate(element, candidate))
        })
        .collect();
    if candidates.is_empty() {
        return None;
    }
    let mut candidates = candidates;
    if let Some(authority) = &authority {
        if let Some(key_id) = &authority.key_identifier {
            let matching: Vec<&Certificate> = candidates
                .iter()
                .copied()
                .filter(|candidate| &key_identifier(candidate) == key_id)
                .collect();
            if !matching.is_empty() {
                candidates = matching;
            }
        }
        if let Some(serial) = &authority.authority_cert_serial {
            let matching: Vec<&Certificate> = candidates
                .iter()
                .copied()
                .filter(|candidate| candidate.serial_number() == serial.as_slice())
                .collect();
            if !matching.is_empty() {
                candidates = matching;
            }
        }
    }
    candidates
        .into_iter()
        .find(|candidate| {
            current
                .verify_signature(candidate.public_key())
                .unwrap_or(false)
        })
        .cloned()
}

fn check_chain(
    store: &Store,
    chain: &[Certificate],
    now: Option<i64>,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let anchor_index = chain.len() - 1;
    for (index, certificate) in chain.iter().enumerate() {
        check_certificate_time(certificate, now)?;
        check_critical_extensions(certificate)?;
        if index == 0 {
            check_leaf_purpose(certificate, options)?;
        } else {
            check_ca(certificate, index, chain, options.flags.x509_strict)?;
            check_authority_key_identifier(&chain[index - 1], certificate)?;
        }
        if index < anchor_index {
            let issuer = &chain[index + 1];
            if !certificate
                .verify_signature(issuer.public_key())
                .map_err(VerifyError::Other)?
            {
                return Err(VerifyError::CertificateSignatureFailure);
            }
        }
    }
    check_name_constraints(chain)?;
    if options.flags.policy_check {
        check_policies(chain, options)?;
    }
    check_revocation(store, chain, now, options)?;
    Ok(())
}

fn check_certificate_time(certificate: &Certificate, now: Option<i64>) -> Result<(), VerifyError> {
    let Some(now) = now else {
        return Ok(());
    };
    let validity = certificate.validity();
    if now < validity.not_before.to_unix() {
        return Err(VerifyError::CertificateNotYetValid);
    }
    if now > validity.not_after.to_unix() {
        return Err(VerifyError::CertificateExpired);
    }
    Ok(())
}

/// Extensions crown understands well enough to accept as critical.
fn is_known_critical_extension(oid: &ObjectIdentifier) -> bool {
    const KNOWN: &[&[u64]] = &[
        oid::OID_BASIC_CONSTRAINTS,
        oid::OID_KEY_USAGE,
        oid::OID_EXTENDED_KEY_USAGE,
        oid::OID_SUBJECT_ALT_NAME,
        oid::OID_ISSUER_ALT_NAME,
        oid::OID_SUBJECT_KEY_IDENTIFIER,
        oid::OID_AUTHORITY_KEY_IDENTIFIER,
        oid::OID_CRL_DISTRIBUTION_POINTS,
        oid::OID_AUTHORITY_INFO_ACCESS,
        oid::OID_SUBJECT_INFO_ACCESS,
        oid::OID_CERTIFICATE_POLICIES,
        oid::OID_NAME_CONSTRAINTS,
        oid::OID_POLICY_CONSTRAINTS,
        oid::OID_INHIBIT_ANY_POLICY,
        oid::OID_POLICY_MAPPINGS,
        oid::OID_FRESHEST_CRL,
        oid::OID_TLS_FEATURE,
        oid::OID_OCSP_NOCHECK,
        oid::OID_SUBJECT_DIRECTORY_ATTRIBUTES,
        oid::OID_NO_REV_AVAIL,
    ];
    KNOWN.iter().any(|known| oid.matches(known))
}

fn check_critical_extensions(certificate: &Certificate) -> Result<(), VerifyError> {
    for extension in certificate.extensions() {
        if !extension.critical {
            continue;
        }
        if !is_known_critical_extension(&extension.oid) {
            return Err(VerifyError::UnhandledCriticalExtension);
        }
        if let Ok(super::extensions::ParsedExtension::Other) = extension.parsed() {
            return Err(VerifyError::UnhandledCriticalExtension);
        }
    }
    Ok(())
}

fn check_leaf_purpose(
    certificate: &Certificate,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let purpose = options.purpose;
    if purpose.requires_ca() && !certificate.tbs().is_ca() {
        return Err(VerifyError::InvalidPurpose);
    }
    if let Some(usage) = certificate.tbs().key_usage() {
        let rejected = match purpose {
            Purpose::Any | Purpose::CrlSign => false,
            Purpose::SslServer => {
                !usage.digital_signature && !usage.key_encipherment && !usage.key_agreement
            }
            Purpose::SslClient
            | Purpose::CodeSigning
            | Purpose::OcspHelper
            | Purpose::TimeStamping => !usage.digital_signature,
            Purpose::SmimeSign => !usage.digital_signature && !usage.content_commitment,
            Purpose::SmimeEncrypt => {
                !usage.key_encipherment && !usage.key_agreement && !usage.data_encipherment
            }
        };
        if rejected {
            return Err(VerifyError::InvalidPurpose);
        }
    }
    if let Some(required) = purpose.eku_oid() {
        if let Some(eku) = certificate.tbs().extended_key_usage() {
            if !eku.contains(required) {
                return Err(VerifyError::InvalidPurpose);
            }
        }
    }
    Ok(())
}

/// Check a CA certificate's constraints in `chain[index]`.
fn check_ca(
    certificate: &Certificate,
    index: usize,
    chain: &[Certificate],
    strict: bool,
) -> Result<(), VerifyError> {
    let is_anchor = index == chain.len() - 1;
    match certificate.tbs().basic_constraints() {
        Some(constraints) => {
            if !constraints.ca {
                return Err(VerifyError::InvalidCa);
            }
            if let Some(path_len) = constraints.path_len {
                // RFC 5280 6.1.4 (l)-(m): the number of non-self-issued
                // intermediate CA certificates below this one.
                let below = (1..index)
                    .filter(|&below| {
                        let candidate = &chain[below];
                        candidate.tbs().is_ca() && candidate.subject() != candidate.issuer()
                    })
                    .count() as u32;
                if below > path_len {
                    return Err(VerifyError::PathLengthExceeded);
                }
            }
        }
        None => {
            // A v1 certificate (or a legacy trust anchor) may omit it.
            if certificate.tbs().version >= 2 && (!is_anchor || strict) {
                return Err(VerifyError::InvalidCa);
            }
        }
    }
    if let Some(usage) = certificate.tbs().key_usage() {
        if !usage.key_cert_sign {
            return Err(VerifyError::KeyUsageNoCertSign);
        }
    }
    Ok(())
}

fn check_authority_key_identifier(
    issued: &Certificate,
    issuer: &Certificate,
) -> Result<(), VerifyError> {
    let Some(authority) = issued.tbs().authority_key_identifier() else {
        return Ok(());
    };
    if let Some(key_id) = authority.key_identifier {
        if let Some(issuer_key_id) = issuer.tbs().subject_key_identifier() {
            if key_id != issuer_key_id {
                return Err(VerifyError::AuthorityKeyIdentifierMismatch);
            }
        }
    }
    Ok(())
}

/// Apply every name constraint in the chain (RFC 5280 4.2.1.10).
fn check_name_constraints(chain: &[Certificate]) -> Result<(), VerifyError> {
    // Constraints from a CA apply to every certificate below it.
    for constraint_index in 1..chain.len() {
        let ca = &chain[constraint_index];
        // Self-issued certificates do not add name constraints.
        if ca.subject() == ca.issuer() {
            continue;
        }
        let Some(extension) = ca.tbs().extension(oid::OID_NAME_CONSTRAINTS) else {
            continue;
        };
        let constraints = NameConstraints::parse(&extension.value).map_err(VerifyError::Other)?;
        if !constraints.is_supported() {
            return Err(VerifyError::UnsupportedConstraintDistance);
        }
        for certificate in chain.iter().take(constraint_index) {
            for name in constrained_names(certificate)? {
                if constraints.permits(&name) {
                    continue;
                }
                if constraints
                    .excluded
                    .as_ref()
                    .is_some_and(|excluded| excluded.iter().any(|subtree| subtree.matches(&name)))
                {
                    return Err(VerifyError::ExcludedViolation);
                }
                return Err(VerifyError::PermittedViolation);
            }
        }
    }
    Ok(())
}

/// Every name a certificate is constrained by: its subject DN, the
/// subjectAltName entries and any emailAddress attributes in the subject.
fn constrained_names(certificate: &Certificate) -> Result<Vec<GeneralName>, VerifyError> {
    let mut names = alloc::vec![GeneralName::DirectoryName(certificate.subject().clone())];
    if let Some(alt_names) = certificate.tbs().subject_alt_names() {
        names.extend(alt_names);
    }
    for rdn in &certificate.subject().rdns {
        for attribute in &rdn.attributes {
            if attribute.oid.matches(oid::OID_AT_EMAIL_ADDRESS) {
                let text = attribute.text().map_err(VerifyError::Other)?;
                names.push(GeneralName::Rfc822Name(text));
            }
        }
    }
    Ok(names)
}

// ---------------------------------------------------------------------------
// Policy processing (RFC 5280 6.1, OpenSSL-flavored)
// ---------------------------------------------------------------------------

const ANY_POLICY: &[u64] = &[2, 5, 29, 32, 0];

#[derive(Debug, Clone)]
struct PolicyNode {
    valid_policy: ObjectIdentifier,
    expected_policy_set: Vec<ObjectIdentifier>,
}

#[derive(Debug, Clone)]
struct PolicyTree {
    nodes: Vec<PolicyNode>,
    alive: Vec<bool>,
}

impl PolicyTree {
    fn new(initial_policy_set: &[ObjectIdentifier]) -> Self {
        let any = ObjectIdentifier::new(ANY_POLICY).expect("static oid");
        let expected = if initial_policy_set.is_empty() {
            alloc::vec![any.clone()]
        } else {
            initial_policy_set.to_vec()
        };
        let mut nodes = alloc::vec![PolicyNode {
            valid_policy: any.clone(),
            expected_policy_set: expected,
        }];
        for policy in initial_policy_set {
            nodes.push(PolicyNode {
                valid_policy: policy.clone(),
                expected_policy_set: alloc::vec![policy.clone()],
            });
        }
        let alive = alloc::vec![true; nodes.len()];
        PolicyTree { nodes, alive }
    }

    fn is_empty(&self) -> bool {
        self.alive.iter().all(|alive| !*alive)
    }

    fn alive_indices(&self) -> Vec<usize> {
        self.alive
            .iter()
            .enumerate()
            .filter_map(|(index, alive)| alive.then_some(index))
            .collect()
    }

    /// RFC 5280 6.1.3 (d): process one certificate's policies.
    fn apply_policies(&mut self, policies: &[ObjectIdentifier], any_policy_ok: bool) {
        let any = ObjectIdentifier::new(ANY_POLICY).expect("static oid");
        let mut new_nodes = Vec::new();
        for parent in self.alive_indices() {
            for policy in policies {
                if policy.matches(ANY_POLICY) {
                    if !any_policy_ok {
                        continue;
                    }
                    new_nodes.push(PolicyNode {
                        valid_policy: any.clone(),
                        expected_policy_set: self.nodes[parent].expected_policy_set.clone(),
                    });
                    continue;
                }
                let acceptable = self.nodes[parent]
                    .expected_policy_set
                    .iter()
                    .any(|expected| expected.matches(ANY_POLICY) || expected == policy);
                if acceptable {
                    new_nodes.push(PolicyNode {
                        valid_policy: policy.clone(),
                        expected_policy_set: alloc::vec![policy.clone()],
                    });
                }
            }
        }
        // Nodes that produced no child at this depth are pruned.
        self.alive = alloc::vec![true; new_nodes.len()];
        self.nodes = new_nodes;
    }

    /// RFC 5280 6.1.4 (c): apply `policyMappings`.
    fn apply_mappings(&mut self, mappings: &PolicyMappings) {
        let mut children = Vec::new();
        for mapping in &mappings.mappings {
            for index in self.alive_indices() {
                if self.nodes[index].valid_policy == mapping.issuer_domain_policy
                    && !self.nodes[index]
                        .expected_policy_set
                        .contains(&mapping.subject_domain_policy)
                {
                    self.nodes[index]
                        .expected_policy_set
                        .push(mapping.subject_domain_policy.clone());
                }
                if self.nodes[index]
                    .expected_policy_set
                    .iter()
                    .any(|expected| expected == &mapping.issuer_domain_policy)
                {
                    children.push(PolicyNode {
                        valid_policy: mapping.subject_domain_policy.clone(),
                        expected_policy_set: alloc::vec![mapping.subject_domain_policy.clone()],
                    });
                }
            }
        }
        for child in children {
            self.nodes.push(child);
            self.alive.push(true);
        }
    }
}

fn check_policies(chain: &[Certificate], options: &VerifyOptions) -> Result<(), VerifyError> {
    let mut tree = Some(PolicyTree::new(&options.initial_policy_set));
    let mut explicit_policy: u32 = if options.flags.explicit_policy {
        0
    } else {
        chain.len() as u32 + 1
    };
    let mut inhibit_mapping: u32 = 0;
    let mut inhibit_any: u32 = if options.flags.inhibit_any_policy {
        0
    } else {
        u32::MAX
    };
    // Process from the trust anchor down to the leaf.
    for certificate in chain.iter().rev() {
        match certificate_policies(certificate)? {
            Some(policies) if !policies.is_empty() => {
                if let Some(tree) = tree.as_mut() {
                    tree.apply_policies(&policies, inhibit_any > 0);
                }
            }
            _ => tree = None,
        }
        if certificate.tbs().is_ca() && certificate.subject() != certificate.issuer() {
            if let Some(extension) = certificate.tbs().extension(oid::OID_POLICY_MAPPINGS) {
                let mappings =
                    PolicyMappings::parse(&extension.value).map_err(VerifyError::Other)?;
                if inhibit_mapping == 0 {
                    if let Some(tree) = tree.as_mut() {
                        tree.apply_mappings(&mappings);
                    }
                }
            }
        }
        if let Some(extension) = certificate.tbs().extension(oid::OID_POLICY_CONSTRAINTS) {
            let constraints =
                PolicyConstraints::parse(&extension.value).map_err(VerifyError::Other)?;
            if let Some(skip) = constraints.require_explicit_policy {
                explicit_policy = explicit_policy.min(skip);
            }
            if let Some(skip) = constraints.inhibit_policy_mapping {
                inhibit_mapping = inhibit_mapping.min(skip);
            }
        }
        if let Some(extension) = certificate.tbs().extension(oid::OID_INHIBIT_ANY_POLICY) {
            let inhibit = InhibitAnyPolicy::parse(&extension.value).map_err(VerifyError::Other)?;
            inhibit_any = inhibit_any.min(inhibit.skip_certs);
        }
        if explicit_policy == 0 && tree.as_ref().is_none_or(PolicyTree::is_empty) {
            return Err(VerifyError::NoExplicitPolicy);
        }
        if explicit_policy > 0 && explicit_policy != u32::MAX {
            explicit_policy -= 1;
        }
        inhibit_mapping = inhibit_mapping.saturating_sub(1);
        if inhibit_any != u32::MAX {
            inhibit_any = inhibit_any.saturating_sub(1);
        }
    }
    if explicit_policy == 0 && tree.as_ref().is_none_or(PolicyTree::is_empty) {
        return Err(VerifyError::NoExplicitPolicy);
    }
    Ok(())
}

fn certificate_policies(
    certificate: &Certificate,
) -> Result<Option<Vec<ObjectIdentifier>>, VerifyError> {
    let Some(extension) = certificate.tbs().extension(oid::OID_CERTIFICATE_POLICIES) else {
        return Ok(None);
    };
    let parsed = CertificatePolicies::parse(&extension.value).map_err(VerifyError::Other)?;
    Ok(Some(parsed.policy_identifiers()))
}

// ---------------------------------------------------------------------------
// Revocation (CRLs and delta CRLs)
// ---------------------------------------------------------------------------

fn crl_extension<'a>(crl: &'a CertificateList, arcs: &[u64]) -> Option<&'a Extension> {
    crl.tbs()
        .extensions
        .iter()
        .find(|extension| extension.oid.matches(arcs))
}

fn crl_number(crl: &CertificateList) -> Option<Vec<u8>> {
    crl_extension(crl, oid::OID_CRL_NUMBER)
        .and_then(|extension| super::extensions::CrlNumber::parse(&extension.value).ok())
        .map(|number| number.number)
}

fn delta_base_number(crl: &CertificateList) -> Result<Option<Vec<u8>>, VerifyError> {
    let Some(extension) = crl_extension(crl, oid::OID_DELTA_CRL_INDICATOR) else {
        return Ok(None);
    };
    Ok(Some(
        DeltaCrlIndicator::parse(&extension.value)
            .map_err(VerifyError::Other)?
            .base_crl_number,
    ))
}

fn is_known_crl_extension(oid: &ObjectIdentifier) -> bool {
    const KNOWN: &[&[u64]] = &[
        oid::OID_CRL_NUMBER,
        oid::OID_DELTA_CRL_INDICATOR,
        oid::OID_ISSUING_DISTRIBUTION_POINT,
        oid::OID_AUTHORITY_KEY_IDENTIFIER,
        oid::OID_FRESHEST_CRL,
        oid::OID_AUTHORITY_INFO_ACCESS,
    ];
    KNOWN.iter().any(|known| oid.matches(known))
}

fn check_crl_critical_extensions(crl: &CertificateList) -> Result<(), VerifyError> {
    for extension in &crl.tbs().extensions {
        if extension.critical && !is_known_crl_extension(&extension.oid) {
            return Err(VerifyError::UnhandledCriticalCrlExtension);
        }
    }
    for entry in &crl.tbs().revoked_certificates {
        for extension in &entry.extensions {
            if !extension.critical {
                continue;
            }
            let known = extension.oid.matches(oid::OID_REASON_CODE)
                || extension.oid.matches(oid::OID_INVALIDITY_DATE)
                || extension.oid.matches(oid::OID_CERTIFICATE_ISSUER)
                || extension.oid.matches(oid::OID_AUTHORITY_KEY_IDENTIFIER);
            if !known {
                return Err(VerifyError::UnhandledCriticalCrlExtension);
            }
        }
    }
    Ok(())
}

fn check_crl_time(crl: &CertificateList, now: Option<i64>) -> Result<(), VerifyError> {
    let Some(now) = now else {
        return Ok(());
    };
    if now < crl.tbs().this_update.to_unix() {
        return Err(VerifyError::CrlNotYetValid);
    }
    if let Some(next_update) = crl.tbs().next_update {
        if now > next_update.to_unix() {
            return Err(VerifyError::CrlExpired);
        }
    }
    Ok(())
}

fn issuing_distribution_point(
    crl: &CertificateList,
) -> Result<Option<IssuingDistributionPoint>, VerifyError> {
    let Some(extension) = crl_extension(crl, oid::OID_ISSUING_DISTRIBUTION_POINT) else {
        return Ok(None);
    };
    IssuingDistributionPoint::parse(&extension.value)
        .map(Some)
        .map_err(VerifyError::Other)
}

fn crl_scope_matches(
    certificate: &Certificate,
    idp: Option<&IssuingDistributionPoint>,
) -> Result<bool, VerifyError> {
    let Some(idp) = idp else {
        return Ok(true);
    };
    if idp.only_contains_attribute_certs {
        return Ok(false);
    }
    let is_ca = certificate.tbs().is_ca();
    if idp.only_contains_user_certs && is_ca {
        return Ok(false);
    }
    if idp.only_contains_ca_certs && !is_ca {
        return Ok(false);
    }
    // When both the certificate and the CRL name distribution points, they
    // must intersect (RFC 5280 6.3.3 (e)-(f)).
    let Some(certificate_points) = certificate
        .tbs()
        .extension(oid::OID_CRL_DISTRIBUTION_POINTS)
    else {
        return Ok(true);
    };
    let crl_names: Vec<&GeneralName> = idp
        .distribution_point
        .as_ref()
        .and_then(|point| point.full_name.as_ref())
        .map(|names| names.iter().collect())
        .unwrap_or_default();
    if crl_names.is_empty() {
        return Ok(true);
    }
    let parsed = super::extensions::CrlDistributionPoints::parse(&certificate_points.value)
        .map_err(VerifyError::Other)?;
    // A distribution point without a name applies to any CRL of the issuer.
    Ok(parsed.points.iter().any(|point| {
        point
            .distribution_point
            .as_ref()
            .and_then(|name| name.full_name.as_ref())
            .is_none_or(|names| names.iter().any(|name| crl_names.contains(&name)))
    }))
}

/// The revocation status of `certificate` in one CRL.
fn crl_entry_status(certificate: &Certificate, crl: &CertificateList) -> Result<bool, VerifyError> {
    for entry in &crl.tbs().revoked_certificates {
        if entry.serial_number != certificate.serial_number() {
            continue;
        }
        let mut reason = None;
        for extension in &entry.extensions {
            if extension.oid.matches(oid::OID_REASON_CODE) {
                reason = Some(CrlReason::parse(&extension.value).map_err(VerifyError::Other)?);
            }
        }
        // `removeFromCRL` entries of a delta CRL undo a revocation.
        return Ok(reason != Some(CrlReason::RemoveFromCrl));
    }
    Ok(false)
}

fn check_certificate_revocation(
    certificate: &Certificate,
    issuer: &Certificate,
    crls: &[&CertificateList],
    now: Option<i64>,
) -> Result<(), VerifyError> {
    let issuer_crls: Vec<&CertificateList> = crls
        .iter()
        .copied()
        .filter(|crl| crl.tbs().issuer == *certificate.issuer())
        .collect();
    if issuer_crls.is_empty() {
        return Err(VerifyError::UnableToGetCrl);
    }
    let mut full = Vec::new();
    let mut deltas = Vec::new();
    for crl in &issuer_crls {
        if delta_base_number(crl)?.is_some() {
            deltas.push(*crl);
        } else {
            full.push(*crl);
        }
    }
    if full.is_empty() {
        return Err(VerifyError::UnableToGetCrl);
    }
    let mut scope_mismatch = false;
    for crl in &full {
        let idp = issuing_distribution_point(crl)?;
        if !crl_scope_matches(certificate, idp.as_ref())? {
            scope_mismatch = true;
            continue;
        }
        check_crl_critical_extensions(crl)?;
        if !crl
            .verify_signature(issuer.public_key())
            .map_err(VerifyError::Other)?
        {
            return Err(VerifyError::CrlSignatureFailure);
        }
        check_crl_time(crl, now)?;
        if crl_entry_status(certificate, crl)? {
            return Err(VerifyError::CertificateRevoked);
        }
        // A matching delta CRL overrides the base CRL's status.
        if let (Some(number), Some(idp)) = (crl_number(crl), idp) {
            let _ = idp;
            for delta in &deltas {
                if delta_base_number(delta)?.as_deref() != Some(number.as_slice()) {
                    continue;
                }
                let delta_idp = issuing_distribution_point(delta)?;
                if !crl_scope_matches(certificate, delta_idp.as_ref())? {
                    continue;
                }
                check_crl_critical_extensions(delta)?;
                if !delta
                    .verify_signature(issuer.public_key())
                    .map_err(VerifyError::Other)?
                {
                    return Err(VerifyError::CrlSignatureFailure);
                }
                check_crl_time(delta, now)?;
                if crl_entry_status(certificate, delta)? {
                    return Err(VerifyError::CertificateRevoked);
                }
            }
        }
        return Ok(());
    }
    Err(if scope_mismatch {
        VerifyError::DifferentCrlScope
    } else {
        VerifyError::UnableToGetCrl
    })
}

fn check_revocation(
    store: &Store,
    chain: &[Certificate],
    now: Option<i64>,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    if !options.flags.crl_check && !options.flags.crl_check_all {
        return Ok(());
    }
    let crls: Vec<&CertificateList> = store
        .crls()
        .iter()
        .chain(options.untrusted_crls.iter())
        .collect();
    let last = chain.len() - 1;
    for index in 0..last {
        if index > 0 && !options.flags.crl_check_all {
            break;
        }
        check_certificate_revocation(&chain[index], &chain[index + 1], &crls, now)?;
    }
    Ok(())
}

//! OCSP (RFC 6960): request/response parsing, building, signing and
//! verification.
//!
//! The module covers the certificate-status protocol used by TLS clients to
//! check revocation without downloading a CRL:
//!
//! - [`CertId`] identifies a certificate by the hash of its issuer's name and
//!   public key plus its serial number;
//! - [`OcspRequest`] builds, parses and (PEM) round-trips requests, including
//!   the `id-pkix-ocsp-nonce` request extension OpenSSL sends by default;
//! - [`OcspResponse`] parses responses and exposes
//!   [`BasicOcspResponse`], [`ResponseData`], [`SingleResponse`],
//!   [`ResponderId`], [`CertStatus`] and [`CrlReason`];
//! - [`BasicOcspResponse::verify`] verifies the response signature with the
//!   issuer (or a delegated responder certificate) following the semantics of
//!   OpenSSL's `OCSP_basic_verify`;
//! - [`OcspResponder`] signs responses with a caller-supplied
//!   [`Rng`](crate::rng::Rng).
//!
//! ```
//! use crown::ocsp::OcspResponse;
//! use crown::x509::Certificate;
//!
//! # let response_der = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pki/ocsp_response_good.der"));
//! # let issuer_pem = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pki/ec.pem"));
//! let response = OcspResponse::parse(response_der)?;
//! let issuer = Certificate::from_pem(issuer_pem)?;
//! response.verify(&issuer)?;
//! assert_eq!(response.status.name(), "successful");
//! # Ok::<(), crown::error::CryptoError>(())
//! ```
//!
//! Only the `id-pkix-ocsp-basic` response type is decoded. Requests can be
//! signed ([`OcspRequest::sign`]) and their signatures verified
//! ([`OcspRequest::verify_signature`]); with the `std` feature a request can
//! be posted to a responder URL ([`OcspRequest::post_to`]).

use alloc::string::String;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::{self, ObjectIdentifier};
use crate::asn1::pem;
use crate::asn1::time::Asn1Time;
use crate::error::{CryptoError, CryptoResult};
use crate::rng::Rng;
use crate::x509::algorithm::{AlgorithmIdentifier, Hash, SignatureAlgorithm};
use crate::x509::cert::Certificate;
use crate::x509::extensions::{Extension, GeneralName};
use crate::x509::keys::PrivateKey;
use crate::x509::name::Name;

/// `id-pkix-ocsp-basic` (1.3.6.1.5.5.7.48.1.1), the `BasicOCSPResponse`
/// response type.
pub const OID_ID_PKIX_OCSP_BASIC: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 1];

/// `id-pkix-ocsp-nonce` (1.3.6.1.5.5.7.48.1.2).
pub const OID_ID_PKIX_OCSP_NONCE: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 2];

/// `OCSPResponseStatus ::= ENUMERATED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspResponseStatus {
    /// `successful` (0).
    Successful,
    /// `malformedRequest` (1).
    MalformedRequest,
    /// `internalError` (2).
    InternalError,
    /// `tryLater` (3).
    TryLater,
    /// `sigRequired` (5).
    SigRequired,
    /// `unauthorized` (6).
    Unauthorized,
}

impl OcspResponseStatus {
    /// Decode the ENUMERATED value.
    pub fn from_u8(value: u8) -> CryptoResult<Self> {
        Ok(match value {
            0 => OcspResponseStatus::Successful,
            1 => OcspResponseStatus::MalformedRequest,
            2 => OcspResponseStatus::InternalError,
            3 => OcspResponseStatus::TryLater,
            5 => OcspResponseStatus::SigRequired,
            6 => OcspResponseStatus::Unauthorized,
            _ => {
                return Err(CryptoError::StrError("ocsp: unknown response status value"));
            }
        })
    }

    /// The wire value.
    pub fn as_u8(self) -> u8 {
        match self {
            OcspResponseStatus::Successful => 0,
            OcspResponseStatus::MalformedRequest => 1,
            OcspResponseStatus::InternalError => 2,
            OcspResponseStatus::TryLater => 3,
            OcspResponseStatus::SigRequired => 5,
            OcspResponseStatus::Unauthorized => 6,
        }
    }

    /// The RFC 6960 name (e.g. `malformedRequest`).
    pub fn name(self) -> &'static str {
        match self {
            OcspResponseStatus::Successful => "successful",
            OcspResponseStatus::MalformedRequest => "malformedRequest",
            OcspResponseStatus::InternalError => "internalError",
            OcspResponseStatus::TryLater => "tryLater",
            OcspResponseStatus::SigRequired => "sigRequired",
            OcspResponseStatus::Unauthorized => "unauthorized",
        }
    }

    /// A human-readable description.
    pub fn text(self) -> &'static str {
        match self {
            OcspResponseStatus::Successful => "the response was successfully produced",
            OcspResponseStatus::MalformedRequest => {
                "the request submitted was malformed and could not be parsed"
            }
            OcspResponseStatus::InternalError => "an internal error occurred in the responder",
            OcspResponseStatus::TryLater => {
                "the responder is temporarily unable to process the request"
            }
            OcspResponseStatus::SigRequired => "the request must be signed",
            OcspResponseStatus::Unauthorized => "the request is unauthorized",
        }
    }
}

impl core::fmt::Display for OcspResponseStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// `CRLReason ::= ENUMERATED` (RFC 5280 section 5.3.1).
///
/// Shared with the X.509 CRL entry extensions.
pub use crate::x509::extensions::CrlReason;

/// `CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash,
/// serialNumber }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertId {
    /// Digest algorithm used for both hashes.
    pub hash_algorithm: AlgorithmIdentifier,
    /// Hash of the DER `Name` of the certificate's issuer.
    pub issuer_name_hash: Vec<u8>,
    /// Hash of the issuer's `subjectPublicKey` BIT STRING contents.
    pub issuer_key_hash: Vec<u8>,
    /// Serial number magnitude.
    pub serial_number: Vec<u8>,
}

impl CertId {
    /// Build the `CertID` of `cert` issued by `issuer` with `hash`.
    ///
    /// This matches OpenSSL's `OCSP_cert_to_id`: `issuerNameHash` covers the
    /// DER encoding of the issuer's subject name and `issuerKeyHash` covers
    /// the `subjectPublicKey` bytes of the issuer's certificate (the BIT
    /// STRING contents without the tag, length and unused-bits octet).
    pub fn for_certificate(
        cert: &Certificate,
        issuer: &Certificate,
        hash: Hash,
    ) -> CryptoResult<Self> {
        let issuer_name_hash = hash.digest(&issuer.subject().encode())?;
        let issuer_key_hash = hash.digest(&issuer.subject_public_key_info().key)?;
        Ok(CertId {
            hash_algorithm: AlgorithmIdentifier::with_null(
                ObjectIdentifier::new(hash.oid()).expect("static oid"),
            ),
            issuer_name_hash,
            issuer_key_hash,
            serial_number: cert.serial_number().to_vec(),
        })
    }

    /// The digest algorithm named by `hashAlgorithm`, when supported.
    pub fn hash(&self) -> CryptoResult<Hash> {
        Hash::from_oid(&self.hash_algorithm.oid).ok_or_else(|| {
            CryptoError::UnsupportedOperation("ocsp: unsupported CertID hash algorithm".into())
        })
    }

    /// Whether this identifier names `cert` issued by `issuer`.
    pub fn matches(&self, cert: &Certificate, issuer: &Certificate) -> CryptoResult<bool> {
        let expected = Self::for_certificate(cert, issuer, self.hash()?)?;
        Ok(self.hash_algorithm.oid == expected.hash_algorithm.oid
            && crate::utils::subtle::constant_time_eq(
                &self.issuer_name_hash,
                &expected.issuer_name_hash,
            )
            && crate::utils::subtle::constant_time_eq(
                &self.issuer_key_hash,
                &expected.issuer_key_hash,
            )
            && self.serial_number == expected.serial_number)
    }

    /// Parse a `CertID`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let hash_algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        let issuer_name_hash = seq.read_octet_string_owned()?;
        let issuer_key_hash = seq.read_octet_string_owned()?;
        let serial_number = seq.read_integer()?.to_vec();
        seq.expect_end()?;
        Ok(CertId {
            hash_algorithm,
            issuer_name_hash,
            issuer_key_hash,
            serial_number,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.hash_algorithm.encode();
        content.extend_from_slice(&der::octet_string(&self.issuer_name_hash));
        content.extend_from_slice(&der::octet_string(&self.issuer_key_hash));
        content.extend_from_slice(&der::integer(&self.serial_number));
        der::sequence(&content)
    }
}

/// `Request ::= SEQUENCE { reqCert CertID, singleRequestExtensions [0]
/// EXPLICIT Extensions OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The certificate being queried.
    pub cert_id: CertId,
    /// Per-request extensions.
    pub single_request_extensions: Vec<Extension>,
}

impl Request {
    /// A request for one certificate identifier.
    pub fn new(cert_id: CertId) -> Self {
        Request {
            cert_id,
            single_request_extensions: Vec::new(),
        }
    }

    /// Parse a `Request`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let cert_id = CertId::parse(&mut seq)?;
        let single_request_extensions = parse_explicit_extensions(&mut seq, 0)?;
        seq.expect_end()?;
        Ok(Request {
            cert_id,
            single_request_extensions,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.cert_id.encode();
        if !self.single_request_extensions.is_empty() {
            content.extend_from_slice(&encode_explicit_extensions(
                0,
                &self.single_request_extensions,
            ));
        }
        der::sequence(&content)
    }
}

/// `Signature ::= SEQUENCE { signatureAlgorithm, signature BIT STRING,
/// certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }`.
#[derive(Debug, Clone)]
pub struct OcspSignature {
    /// Signature algorithm.
    pub signature_algorithm: AlgorithmIdentifier,
    /// The raw signature.
    pub signature: Vec<u8>,
    /// Certificates helping the recipient verify the signature.
    pub certs: Vec<Certificate>,
}

impl OcspSignature {
    /// Parse an `OcspSignature` from a reader positioned at the `SEQUENCE`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let signature_algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        let signature = seq.read_bit_string_bytes()?.to_vec();
        let mut certs = Vec::new();
        if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(0) {
            let mut inner = seq.read_explicit(0)?;
            let mut list = inner.read_sequence()?;
            while !list.is_empty() {
                certs.push(Certificate::parse(list.read_raw_tlv()?)?);
            }
        }
        seq.expect_end()?;
        Ok(OcspSignature {
            signature_algorithm,
            signature,
            certs,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.signature_algorithm.encode();
        content.extend_from_slice(&der::bit_string(0, &self.signature));
        if !self.certs.is_empty() {
            let mut certs = Vec::new();
            for certificate in &self.certs {
                certs.extend_from_slice(&certificate.encode());
            }
            content.extend_from_slice(&der::explicit(0, &der::sequence(&certs)));
        }
        der::sequence(&content)
    }
}

/// `OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest, optionalSignature [0]
/// EXPLICIT Signature OPTIONAL }`.
///
/// The common unsigned single-request form is the primary use case; the
/// request list and request extensions are kept general.
#[derive(Debug, Clone)]
pub struct OcspRequest {
    /// `TBSRequest.version`: `None` means the default v1.
    pub version: Option<u8>,
    /// `requestorName [1] EXPLICIT GeneralName`, kept as the raw TLV so
    /// re-encoding stays byte-exact (signed requests carry the requester's
    /// subject here).
    pub requestor_name: Option<Vec<u8>>,
    /// `requestList`.
    pub requests: Vec<Request>,
    /// `requestExtensions`, where OpenSSL places the nonce.
    pub request_extensions: Vec<Extension>,
    /// `optionalSignature`, parsed but not verified.
    pub optional_signature: Option<OcspSignature>,
}

impl OcspRequest {
    /// Parse a DER `OCSPRequest`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let request = Self::parse_reader(&mut reader)?;
        reader.expect_end()?;
        Ok(request)
    }

    /// Parse an `OCSPRequest` from a reader.
    pub fn parse_reader(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let mut tbs = seq.read_sequence()?;
        let version = if !tbs.is_empty() && tbs.peek_tag()? == der::Tag::context_constructed(0) {
            let mut inner = tbs.read_explicit(0)?;
            let value = inner.read_integer_i64()?;
            Some(
                u8::try_from(value)
                    .map_err(|_| CryptoError::StrError("ocsp: invalid request version"))?,
            )
        } else {
            None
        };
        // requestorName [1] EXPLICIT GeneralName is kept as the raw TLV.
        let mut requestor_name = None;
        if !tbs.is_empty() && tbs.peek_tag()? == der::Tag::context_constructed(1) {
            requestor_name = Some(tbs.read_raw_tlv()?.to_vec());
        }
        let mut list = tbs.read_sequence()?;
        let mut requests = Vec::new();
        while !list.is_empty() {
            requests.push(Request::parse(&mut list)?);
        }
        // RFC 6960 tags requestExtensions [2]; [0] is also accepted on input
        // for encoders that number the field after the version.
        let mut request_extensions = Vec::new();
        if !tbs.is_empty() {
            let tag = tbs.peek_tag()?;
            if tag.class == der::Class::ContextSpecific
                && tag.constructed
                && (tag.number == 2 || tag.number == 0)
            {
                let mut inner = tbs.read_explicit(tag.number)?;
                let mut ext_reader = inner.read_sequence()?;
                while !ext_reader.is_empty() {
                    request_extensions.push(Extension::parse(&mut ext_reader)?);
                }
            }
        }
        tbs.expect_end()?;
        let optional_signature =
            if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(0) {
                let mut inner = seq.read_explicit(0)?;
                Some(OcspSignature::parse(&mut inner)?)
            } else {
                None
            };
        seq.expect_end()?;
        Ok(OcspRequest {
            version,
            requestor_name,
            requests,
            request_extensions,
            optional_signature,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.tbs_der();
        if let Some(signature) = &self.optional_signature {
            content.extend_from_slice(&der::explicit(0, &signature.encode()));
        }
        der::sequence(&content)
    }

    /// The DER of the `TBSRequest` — the input covered by the request
    /// signature (RFC 6960 4.1.2).
    pub fn tbs_der(&self) -> Vec<u8> {
        let mut tbs = Vec::new();
        if let Some(version) = self.version {
            tbs.extend_from_slice(&der::explicit(0, &der::integer(&[version])));
        }
        if let Some(requestor) = &self.requestor_name {
            tbs.extend_from_slice(requestor);
        }
        let mut list = Vec::new();
        for request in &self.requests {
            list.extend_from_slice(&request.encode());
        }
        tbs.extend_from_slice(&der::sequence(&list));
        if !self.request_extensions.is_empty() {
            tbs.extend_from_slice(&encode_explicit_extensions(2, &self.request_extensions));
        }
        der::sequence(&tbs)
    }

    /// Parse a PEM `OCSP REQUEST`.
    pub fn from_pem(pem_text: &str) -> CryptoResult<Self> {
        let block = pem::parse_first(pem_text)?;
        if block.label != "OCSP REQUEST" {
            return Err(CryptoError::StrError("ocsp: not an OCSP request PEM block"));
        }
        Self::parse(&block.data)
    }

    /// Encode as a PEM `OCSP REQUEST`.
    pub fn to_pem(&self) -> String {
        pem::encode("OCSP REQUEST", &self.encode())
    }

    /// A version-less request for one certificate hashed with `hash`.
    pub fn request_for(cert: &Certificate, issuer: &Certificate, hash: Hash) -> CryptoResult<Self> {
        Ok(OcspRequest {
            version: None,
            requestor_name: None,
            requests: alloc::vec![Request::new(CertId::for_certificate(cert, issuer, hash)?)],
            request_extensions: Vec::new(),
            optional_signature: None,
        })
    }

    /// The `CertID` of the first request.
    pub fn cert_id(&self) -> CryptoResult<&CertId> {
        self.requests
            .first()
            .map(|request| &request.cert_id)
            .ok_or(CryptoError::StrError("ocsp: request has no cert id"))
    }

    /// The `id-pkix-ocsp-nonce` request extension, when present.
    pub fn nonce(&self) -> CryptoResult<Option<Vec<u8>>> {
        nonce_from_extensions(&self.request_extensions)
    }

    /// Set (or replace) the `id-pkix-ocsp-nonce` request extension.
    pub fn set_nonce(&mut self, nonce: &[u8]) {
        set_nonce_extension(&mut self.request_extensions, nonce);
    }

    /// Remove the `id-pkix-ocsp-nonce` request extension, if present.
    pub fn clear_nonce(&mut self) {
        self.request_extensions
            .retain(|extension| !extension.oid.matches(OID_ID_PKIX_OCSP_NONCE));
    }

    /// Sign the request (RFC 6960 `optionalSignature`): the signature covers
    /// the `TBSRequest` DER and the `requestorName` becomes the signer's
    /// subject, mirroring OpenSSL's `OCSP_request_sign`. The first of `certs`
    /// is the signer; attach enough of the chain for the receiver to verify.
    pub fn sign(
        &mut self,
        signature_algorithm: SignatureAlgorithm,
        key: &PrivateKey,
        certs: Vec<Certificate>,
        rng: &mut impl Rng,
    ) -> CryptoResult<()> {
        let signer = certs.first().ok_or(CryptoError::StrError(
            "ocsp: signing requires the signer certificate",
        ))?;
        self.requestor_name = Some(der::explicit(
            1,
            &GeneralName::DirectoryName(signer.subject().clone()).encode(),
        ));
        let tbs = self.tbs_der();
        let signature = signature_algorithm.sign(key, &tbs, rng)?;
        self.optional_signature = Some(OcspSignature {
            signature_algorithm: signature_algorithm.to_identifier(),
            signature,
            certs,
        });
        Ok(())
    }

    /// Verify the request signature (RFC 6960 `optionalSignature`).
    ///
    /// With `signer` given, its public key must verify the signature;
    /// otherwise every attached certificate is tried. A key of an
    /// incompatible type simply does not verify (returns `false`). Signed
    /// requests are rare in practice and RFC 6960 does not define trust
    /// semantics for them, so the caller decides what the signer's identity
    /// means.
    pub fn verify_signature(&self, signer: Option<&Certificate>) -> CryptoResult<bool> {
        let Some(signature) = &self.optional_signature else {
            return Ok(false);
        };
        let tbs = self.tbs_der();
        let verify = |certificate: &Certificate| -> CryptoResult<bool> {
            let algorithm = SignatureAlgorithm::from_identifier(&signature.signature_algorithm)?;
            match algorithm.verify(certificate.public_key(), &tbs, &signature.signature) {
                // The algorithm cannot apply to this key: it did not sign.
                Err(CryptoError::UnsupportedOperation(_)) => Ok(false),
                other => other,
            }
        };
        if let Some(signer) = signer {
            return verify(signer);
        }
        for certificate in &signature.certs {
            if verify(certificate)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(feature = "std")]
impl OcspRequest {
    /// `POST` the request to an OCSP responder URL and parse the response.
    ///
    /// Responder URLs come from a certificate's `authorityInfoAccess`
    /// ([`Certificate::ocsp_urls`](crate::x509::Certificate::ocsp_urls)).
    /// Only plain `http://` URLs are supported (see [`crate::x509::http`]).
    pub fn post_to(
        &self,
        url: &str,
        timeout: Option<std::time::Duration>,
    ) -> CryptoResult<OcspResponse> {
        let response =
            crate::x509::http::post(url, "application/ocsp-request", &self.encode(), timeout)?;
        if response.status != 200 {
            return Err(CryptoError::StrError("ocsp: HTTP error from responder"));
        }
        OcspResponse::parse(&response.body)
    }
}

/// `ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponderId {
    /// The responder's subject name.
    ByName(Name),
    /// SHA-1 of the responder's `subjectPublicKey` BIT STRING contents.
    ByKey(Vec<u8>),
}

impl ResponderId {
    /// Identify `certificate` by name (`by_key == false`) or by key hash.
    pub fn for_certificate(certificate: &Certificate, by_key: bool) -> CryptoResult<Self> {
        if by_key {
            Ok(ResponderId::ByKey(responder_key_hash(certificate)?))
        } else {
            Ok(ResponderId::ByName(certificate.subject().clone()))
        }
    }

    /// Parse a `ResponderID`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let tag = reader.peek_tag()?;
        if tag.class != der::Class::ContextSpecific {
            return Err(CryptoError::StrError("ocsp: invalid responder id"));
        }
        match tag.number {
            // Name is itself a CHOICE, so the tag is EXPLICIT.
            1 => {
                let mut inner = reader.read_explicit(1)?;
                Ok(ResponderId::ByName(Name::parse(&mut inner)?))
            }
            // KeyHash is [2] EXPLICIT OCTET STRING (the module uses EXPLICIT
            // TAGS).
            2 => {
                let mut inner = reader.read_explicit(2)?;
                Ok(ResponderId::ByKey(inner.read_octet_string_owned()?))
            }
            _ => Err(CryptoError::StrError("ocsp: invalid responder id")),
        }
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            ResponderId::ByName(name) => der::explicit(1, &name.encode()),
            ResponderId::ByKey(key_hash) => der::explicit(2, &der::octet_string(key_hash)),
        }
    }

    /// Whether this identifier names `certificate`.
    pub fn matches_certificate(&self, certificate: &Certificate) -> CryptoResult<bool> {
        match self {
            ResponderId::ByName(name) => Ok(*name == *certificate.subject()),
            ResponderId::ByKey(key_hash) => Ok(crate::utils::subtle::constant_time_eq(
                key_hash,
                &responder_key_hash(certificate)?,
            )),
        }
    }
}

/// `CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT
/// RevokedInfo, unknown [2] IMPLICIT UnknownInfo }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertStatus {
    /// The certificate is not revoked.
    Good,
    /// The certificate is revoked.
    Revoked {
        /// Revocation time.
        revocation_time: Asn1Time,
        /// Reason, when the responder supplied one.
        revocation_reason: Option<CrlReason>,
    },
    /// The responder is unable to provide a status.
    Unknown,
}

impl CertStatus {
    /// Parse a `CertStatus`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let tag = reader.peek_tag()?;
        if tag.class != der::Class::ContextSpecific {
            return Err(CryptoError::StrError("ocsp: invalid cert status"));
        }
        match tag.number {
            0 => {
                let content = reader.read_implicit(0, false)?;
                if !content.is_empty() {
                    return Err(CryptoError::StrError("ocsp: invalid good status"));
                }
                Ok(CertStatus::Good)
            }
            1 => {
                let mut inner = reader.read_implicit_constructed(1)?;
                let revocation_time = inner.read_time()?;
                let revocation_reason =
                    if !inner.is_empty() && inner.peek_tag()? == der::Tag::context_constructed(0) {
                        let mut reason = inner.read_explicit(0)?;
                        let value = read_enumerated(&mut reason)?;
                        let value = u8::try_from(value)
                            .map_err(|_| CryptoError::StrError("ocsp: invalid CRL reason"))?;
                        Some(CrlReason::from_u8(value)?)
                    } else {
                        None
                    };
                inner.expect_end()?;
                Ok(CertStatus::Revoked {
                    revocation_time,
                    revocation_reason,
                })
            }
            2 => {
                let content = reader.read_implicit(2, false)?;
                if !content.is_empty() {
                    return Err(CryptoError::StrError("ocsp: invalid unknown status"));
                }
                Ok(CertStatus::Unknown)
            }
            _ => Err(CryptoError::StrError("ocsp: invalid cert status")),
        }
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            CertStatus::Good => der::implicit(0, false, &[]),
            CertStatus::Revoked {
                revocation_time,
                revocation_reason,
            } => {
                let mut content = der::generalized_time(revocation_time);
                if let Some(reason) = revocation_reason {
                    content.extend_from_slice(&der::explicit(0, &enumerated(reason.as_u8())));
                }
                der::implicit(1, true, &content)
            }
            CertStatus::Unknown => der::implicit(2, false, &[]),
        }
    }
}

/// `SingleResponse ::= SEQUENCE { certID, certStatus, thisUpdate,
/// nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL, singleExtensions [1]
/// EXPLICIT Extensions OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleResponse {
    /// The certificate this status refers to.
    pub cert_id: CertId,
    /// The status.
    pub cert_status: CertStatus,
    /// When this status was known to be correct.
    pub this_update: Asn1Time,
    /// When newer information will be available.
    pub next_update: Option<Asn1Time>,
    /// Per-response extensions.
    pub single_extensions: Vec<Extension>,
}

impl SingleResponse {
    /// A response entry without extensions.
    pub fn new(cert_id: CertId, cert_status: CertStatus, this_update: Asn1Time) -> Self {
        SingleResponse {
            cert_id,
            cert_status,
            this_update,
            next_update: None,
            single_extensions: Vec::new(),
        }
    }

    /// Parse a `SingleResponse`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let cert_id = CertId::parse(&mut seq)?;
        let cert_status = CertStatus::parse(&mut seq)?;
        let this_update = seq.read_time()?;
        let next_update = if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(0)
        {
            let mut inner = seq.read_explicit(0)?;
            Some(inner.read_time()?)
        } else {
            None
        };
        let single_extensions = parse_explicit_extensions(&mut seq, 1)?;
        seq.expect_end()?;
        Ok(SingleResponse {
            cert_id,
            cert_status,
            this_update,
            next_update,
            single_extensions,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.cert_id.encode();
        content.extend_from_slice(&self.cert_status.encode());
        // RFC 6960 requires GeneralizedTime for every OCSP timestamp.
        content.extend_from_slice(&der::generalized_time(&self.this_update));
        if let Some(next_update) = &self.next_update {
            content.extend_from_slice(&der::explicit(0, &der::generalized_time(next_update)));
        }
        if !self.single_extensions.is_empty() {
            content.extend_from_slice(&encode_explicit_extensions(1, &self.single_extensions));
        }
        der::sequence(&content)
    }

    /// Whether this entry refers to `cert` issued by `issuer`.
    pub fn matches(&self, cert: &Certificate, issuer: &Certificate) -> CryptoResult<bool> {
        self.cert_id.matches(cert, issuer)
    }

    /// The `id-pkix-ocsp-nonce` extension from `singleExtensions`, if any.
    pub fn nonce(&self) -> CryptoResult<Option<Vec<u8>>> {
        nonce_from_extensions(&self.single_extensions)
    }
}

/// `ResponseData ::= SEQUENCE { version [0] EXPLICIT Version DEFAULT v1,
/// responderID, producedAt GeneralizedTime, responses SEQUENCE OF
/// SingleResponse, responseExtensions [1] EXPLICIT Extensions OPTIONAL }`.
#[derive(Debug, Clone)]
pub struct ResponseData {
    /// `None` means the default v1.
    pub version: Option<u8>,
    /// Who produced the response.
    pub responder_id: ResponderId,
    /// When the response was produced.
    pub produced_at: Asn1Time,
    /// The per-certificate statuses.
    pub responses: Vec<SingleResponse>,
    /// Response extensions (the nonce lives here).
    pub response_extensions: Vec<Extension>,
}

impl ResponseData {
    /// Parse a `ResponseData`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let version = if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(0) {
            let mut inner = seq.read_explicit(0)?;
            let value = inner.read_integer_i64()?;
            Some(
                u8::try_from(value)
                    .map_err(|_| CryptoError::StrError("ocsp: invalid response version"))?,
            )
        } else {
            None
        };
        let responder_id = ResponderId::parse(&mut seq)?;
        let produced_at = seq.read_time()?;
        let mut list = seq.read_sequence()?;
        let mut responses = Vec::new();
        while !list.is_empty() {
            responses.push(SingleResponse::parse(&mut list)?);
        }
        let response_extensions = parse_explicit_extensions(&mut seq, 1)?;
        seq.expect_end()?;
        Ok(ResponseData {
            version,
            responder_id,
            produced_at,
            responses,
            response_extensions,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if let Some(version) = self.version {
            content.extend_from_slice(&der::explicit(0, &der::integer(&[version])));
        }
        content.extend_from_slice(&self.responder_id.encode());
        content.extend_from_slice(&der::generalized_time(&self.produced_at));
        let mut list = Vec::new();
        for response in &self.responses {
            list.extend_from_slice(&response.encode());
        }
        content.extend_from_slice(&der::sequence(&list));
        if !self.response_extensions.is_empty() {
            content.extend_from_slice(&encode_explicit_extensions(1, &self.response_extensions));
        }
        der::sequence(&content)
    }

    /// The `id-pkix-ocsp-nonce` response extension, when present.
    pub fn nonce(&self) -> CryptoResult<Option<Vec<u8>>> {
        nonce_from_extensions(&self.response_extensions)
    }
}

/// `BasicOCSPResponse ::= SEQUENCE { tbsResponseData, signatureAlgorithm,
/// signature BIT STRING, certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
/// }`.
#[derive(Debug, Clone)]
pub struct BasicOcspResponse {
    /// The signed response data.
    pub tbs_response_data: ResponseData,
    /// Signature algorithm.
    pub signature_algorithm: AlgorithmIdentifier,
    /// The raw signature.
    pub signature: Vec<u8>,
    /// Certificates embedded by the responder.
    pub certs: Vec<Certificate>,
}

impl BasicOcspResponse {
    /// Parse a DER `BasicOCSPResponse`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let response = Self::parse_reader(&mut reader)?;
        reader.expect_end()?;
        Ok(response)
    }

    /// Parse a `BasicOCSPResponse` from a reader.
    pub fn parse_reader(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let tbs_response_data = ResponseData::parse(&mut seq)?;
        let signature_algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        let signature = seq.read_bit_string_bytes()?.to_vec();
        let mut certs = Vec::new();
        if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(0) {
            let mut inner = seq.read_explicit(0)?;
            let mut list = inner.read_sequence()?;
            while !list.is_empty() {
                certs.push(Certificate::parse(list.read_raw_tlv()?)?);
            }
        }
        seq.expect_end()?;
        Ok(BasicOcspResponse {
            tbs_response_data,
            signature_algorithm,
            signature,
            certs,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        // The TBS bytes the signature covers are re-encoded; parsed
        // structures round-trip byte-exactly.
        let mut content = self.tbs_response_data.encode();
        content.extend_from_slice(&self.signature_algorithm.encode());
        content.extend_from_slice(&der::bit_string(0, &self.signature));
        if !self.certs.is_empty() {
            let mut certs = Vec::new();
            for certificate in &self.certs {
                certs.extend_from_slice(&certificate.encode());
            }
            content.extend_from_slice(&der::explicit(0, &der::sequence(&certs)));
        }
        der::sequence(&content)
    }

    /// The `id-pkix-ocsp-nonce` response extension, when present.
    pub fn nonce(&self) -> CryptoResult<Option<Vec<u8>>> {
        self.tbs_response_data.nonce()
    }

    /// Verify the response against `issuer`, locating the responder
    /// certificate among the embedded certificates (or `issuer` itself).
    ///
    /// This follows the semantics of OpenSSL's `OCSP_basic_verify`: the
    /// response signature must verify under the responder's public key; a
    /// delegated responder (one that is not the issuer) must have a
    /// certificate signed by the issuer, valid at `producedAt`, carrying the
    /// `id-kp-OCSPSigning` extended key usage.
    pub fn verify(&self, issuer: &Certificate) -> CryptoResult<()> {
        self.verify_with_responder(issuer, None)
    }

    /// [`Self::verify`] with an explicit responder certificate.
    ///
    /// When `responder` is `None`, the responder is looked up among the
    /// embedded certificates and then `issuer` itself.
    pub fn verify_with_responder(
        &self,
        issuer: &Certificate,
        responder: Option<&Certificate>,
    ) -> CryptoResult<()> {
        let responder = match responder {
            Some(responder) => responder,
            None => self.find_responder(issuer)?,
        };
        if !self
            .tbs_response_data
            .responder_id
            .matches_certificate(responder)?
        {
            return Err(CryptoError::StrError(
                "ocsp: responder certificate does not match the responder id",
            ));
        }
        let algorithm = SignatureAlgorithm::from_identifier(&self.signature_algorithm)?;
        if !algorithm.verify(
            responder.public_key(),
            &self.tbs_response_data.encode(),
            &self.signature,
        )? {
            return Err(CryptoError::AuthenticationFailed);
        }
        if !same_certificate(responder, issuer) {
            // Delegated responder: signed by the issuer and valid at
            // producedAt, and authorized for OCSP signing.
            responder.verify(issuer, Some(self.tbs_response_data.produced_at.to_unix()))?;
            let eku = responder
                .tbs()
                .extended_key_usage()
                .ok_or(CryptoError::StrError(
                    "ocsp: delegated responder has no extended key usage",
                ))?;
            if !eku.contains(oid::OID_KP_OCSP_SIGNING) {
                return Err(CryptoError::StrError(
                    "ocsp: responder certificate is not authorized for OCSP signing",
                ));
            }
        }
        Ok(())
    }

    /// The responder certificate: the embedded certificate matching the
    /// responder id, or the issuer when it matches.
    pub fn find_responder<'a>(&'a self, issuer: &'a Certificate) -> CryptoResult<&'a Certificate> {
        if self
            .tbs_response_data
            .responder_id
            .matches_certificate(issuer)?
        {
            return Ok(issuer);
        }
        for certificate in &self.certs {
            if self
                .tbs_response_data
                .responder_id
                .matches_certificate(certificate)?
            {
                return Ok(certificate);
            }
        }
        Err(CryptoError::StrError(
            "ocsp: responder certificate not found",
        ))
    }
}

/// `OCSPResponse ::= SEQUENCE { responseStatus, responseBytes [0] EXPLICIT
/// ResponseBytes OPTIONAL }`.
#[derive(Debug, Clone)]
pub struct OcspResponse {
    /// The response status.
    pub status: OcspResponseStatus,
    /// `responseBytes`, present for `successful` responses.
    pub response_bytes: Option<ResponseBytes>,
}

/// `ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }`.
#[derive(Debug, Clone)]
pub struct ResponseBytes {
    /// The response type OID.
    pub response_type: ObjectIdentifier,
    /// The DER of the typed response.
    pub response: Vec<u8>,
}

impl OcspResponse {
    /// Parse a DER `OCSPResponse`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let response = Self::parse_reader(&mut reader)?;
        reader.expect_end()?;
        Ok(response)
    }

    /// Parse an `OCSPResponse` from a reader.
    pub fn parse_reader(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let value = read_enumerated(&mut seq)?;
        let value = u8::try_from(value)
            .map_err(|_| CryptoError::StrError("ocsp: invalid response status"))?;
        let status = OcspResponseStatus::from_u8(value)?;
        let response_bytes =
            if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(0) {
                let mut inner = seq.read_explicit(0)?;
                let mut bytes = inner.read_sequence()?;
                let response_type = bytes.read_oid()?;
                let response = bytes.read_octet_string_owned()?;
                bytes.expect_end()?;
                Some(ResponseBytes {
                    response_type,
                    response,
                })
            } else {
                None
            };
        seq.expect_end()?;
        Ok(OcspResponse {
            status,
            response_bytes,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = enumerated(self.status.as_u8());
        if let Some(bytes) = &self.response_bytes {
            let mut inner = der::oid(&bytes.response_type);
            inner.extend_from_slice(&der::octet_string(&bytes.response));
            content.extend_from_slice(&der::explicit(0, &der::sequence(&inner)));
        }
        der::sequence(&content)
    }

    /// Parse a PEM `OCSP RESPONSE`.
    pub fn from_pem(pem_text: &str) -> CryptoResult<Self> {
        let block = pem::parse_first(pem_text)?;
        if block.label != "OCSP RESPONSE" {
            return Err(CryptoError::StrError(
                "ocsp: not an OCSP response PEM block",
            ));
        }
        Self::parse(&block.data)
    }

    /// Encode as a PEM `OCSP RESPONSE`.
    pub fn to_pem(&self) -> String {
        pem::encode("OCSP RESPONSE", &self.encode())
    }

    /// Wrap a `BasicOCSPResponse` in a `successful` response.
    pub fn successful(basic: &BasicOcspResponse) -> Self {
        OcspResponse {
            status: OcspResponseStatus::Successful,
            response_bytes: Some(ResponseBytes {
                response_type: ObjectIdentifier::new(OID_ID_PKIX_OCSP_BASIC).expect("static oid"),
                response: basic.encode(),
            }),
        }
    }

    /// The decoded `BasicOCSPResponse` for a successful response.
    pub fn basic(&self) -> CryptoResult<BasicOcspResponse> {
        if self.status != OcspResponseStatus::Successful {
            return Err(CryptoError::StrError("ocsp: response is not successful"));
        }
        let bytes = self
            .response_bytes
            .as_ref()
            .ok_or(CryptoError::StrError("ocsp: response bytes missing"))?;
        if !bytes.response_type.matches(OID_ID_PKIX_OCSP_BASIC) {
            return Err(CryptoError::UnsupportedOperation(
                "ocsp: unsupported response type".into(),
            ));
        }
        BasicOcspResponse::parse(&bytes.response)
    }

    /// Verify the basic response signature against `issuer`.
    pub fn verify(&self, issuer: &Certificate) -> CryptoResult<()> {
        self.basic()?.verify(issuer)
    }

    /// [`Self::verify`] with an explicit responder certificate.
    pub fn verify_with_responder(
        &self,
        issuer: &Certificate,
        responder: Option<&Certificate>,
    ) -> CryptoResult<()> {
        self.basic()?.verify_with_responder(issuer, responder)
    }

    /// The `id-pkix-ocsp-nonce` response extension, when present.
    pub fn nonce(&self) -> CryptoResult<Option<Vec<u8>>> {
        self.basic()?.nonce()
    }

    /// Compare the response nonce with an expected value (usually the request
    /// nonce from [`OcspRequest::nonce`]).
    ///
    /// Both sides must agree: a missing nonce only matches a missing nonce.
    pub fn check_nonce(&self, expected: Option<&[u8]>) -> CryptoResult<()> {
        match (self.nonce()?, expected) {
            (None, None) => Ok(()),
            (Some(actual), Some(expected))
                if crate::utils::subtle::constant_time_eq(&actual, expected) =>
            {
                Ok(())
            }
            (None, Some(_)) => Err(CryptoError::StrError("ocsp: response has no nonce")),
            (Some(_), None) => Err(CryptoError::StrError("ocsp: unexpected response nonce")),
            _ => Err(CryptoError::AuthenticationFailed),
        }
    }

    /// [`Self::check_nonce`] against a request's nonce.
    pub fn check_request_nonce(&self, request: &OcspRequest) -> CryptoResult<()> {
        self.check_nonce(request.nonce()?.as_deref())
    }
}

/// A signer for `BasicOCSPResponse`s.
///
/// The caller supplies the responder identity, the certificates to embed, the
/// private key and the signature algorithm; [`Self::respond`] produces a
/// signed response over a list of [`SingleResponse`]s.
#[derive(Debug, Clone)]
pub struct OcspResponder {
    /// How the responder identifies itself in the response.
    pub responder_id: ResponderId,
    /// Certificates embedded in the response.
    pub certificates: Vec<Certificate>,
    /// The signing key.
    pub key: PrivateKey,
    /// The signature algorithm.
    pub signature_algorithm: SignatureAlgorithm,
}

impl OcspResponder {
    /// Build a responder.
    pub fn new(
        responder_id: ResponderId,
        certificates: Vec<Certificate>,
        key: PrivateKey,
        signature_algorithm: SignatureAlgorithm,
    ) -> Self {
        OcspResponder {
            responder_id,
            certificates,
            key,
            signature_algorithm,
        }
    }

    /// Build a responder from its certificate (embedding it), deriving the
    /// responder id by name or by key hash.
    pub fn for_certificate(
        certificate: &Certificate,
        key: PrivateKey,
        signature_algorithm: SignatureAlgorithm,
        by_key: bool,
    ) -> CryptoResult<Self> {
        Ok(OcspResponder {
            responder_id: ResponderId::for_certificate(certificate, by_key)?,
            certificates: alloc::vec![certificate.clone()],
            key,
            signature_algorithm,
        })
    }

    /// Sign a `BasicOCSPResponse`.
    ///
    /// `next_update`, when given, is applied to every response that does not
    /// already carry one. `nonce`, when given, is added to the response
    /// extensions (mirroring the request nonce).
    pub fn respond(
        &self,
        responses: Vec<SingleResponse>,
        produced_at: Asn1Time,
        next_update: Option<Asn1Time>,
        nonce: Option<&[u8]>,
        rng: &mut impl Rng,
    ) -> CryptoResult<BasicOcspResponse> {
        let responses = responses
            .into_iter()
            .map(|mut response| {
                if response.next_update.is_none() {
                    response.next_update = next_update;
                }
                response
            })
            .collect();
        let mut response_extensions = Vec::new();
        if let Some(nonce) = nonce {
            set_nonce_extension(&mut response_extensions, nonce);
        }
        let tbs_response_data = ResponseData {
            version: None,
            responder_id: self.responder_id.clone(),
            produced_at,
            responses,
            response_extensions,
        };
        let signature =
            self.signature_algorithm
                .sign(&self.key, &tbs_response_data.encode(), rng)?;
        Ok(BasicOcspResponse {
            tbs_response_data,
            signature_algorithm: self.signature_algorithm.to_identifier(),
            signature,
            certs: self.certificates.clone(),
        })
    }
}

/// SHA-1 of a certificate's `subjectPublicKey` BIT STRING contents, the
/// RFC 6960 `KeyHash` (excluding the unused-bits octet, as OpenSSL does).
fn responder_key_hash(certificate: &Certificate) -> CryptoResult<Vec<u8>> {
    Hash::Sha1.digest(&certificate.subject_public_key_info().key)
}

/// Whether two certificates are the same identity (subject name and public
/// key).
fn same_certificate(a: &Certificate, b: &Certificate) -> bool {
    (a.subject() == b.subject()
        && a.subject_public_key_info().key == b.subject_public_key_info().key)
        || a.encode() == b.encode()
}

/// Parse `[number] EXPLICIT Extensions`, returning an empty vector when the
/// field is absent.
fn parse_explicit_extensions(reader: &mut Reader<'_>, number: u32) -> CryptoResult<Vec<Extension>> {
    let mut extensions = Vec::new();
    if !reader.is_empty() && reader.peek_tag()? == der::Tag::context_constructed(number) {
        let mut inner = reader.read_explicit(number)?;
        let mut ext_reader = inner.read_sequence()?;
        while !ext_reader.is_empty() {
            extensions.push(Extension::parse(&mut ext_reader)?);
        }
    }
    Ok(extensions)
}

/// Encode `[number] EXPLICIT Extensions`.
fn encode_explicit_extensions(number: u32, extensions: &[Extension]) -> Vec<u8> {
    let mut content = Vec::new();
    for extension in extensions {
        content.extend_from_slice(&extension.encode());
    }
    der::explicit(number, &der::sequence(&content))
}

/// Read the `id-pkix-ocsp-nonce` extension from a list, unwrapping the OCTET
/// STRING inside the extension value.
fn nonce_from_extensions(extensions: &[Extension]) -> CryptoResult<Option<Vec<u8>>> {
    let Some(extension) = extensions
        .iter()
        .find(|extension| extension.oid.matches(OID_ID_PKIX_OCSP_NONCE))
    else {
        return Ok(None);
    };
    let mut reader = Reader::new(&extension.value);
    let nonce = reader.read_octet_string_owned()?;
    reader.expect_end()?;
    Ok(Some(nonce))
}

/// Set (or replace) the `id-pkix-ocsp-nonce` extension in a list.
fn set_nonce_extension(extensions: &mut Vec<Extension>, nonce: &[u8]) {
    extensions.retain(|extension| !extension.oid.matches(OID_ID_PKIX_OCSP_NONCE));
    extensions.push(Extension::new(
        ObjectIdentifier::new(OID_ID_PKIX_OCSP_NONCE).expect("static oid"),
        false,
        der::octet_string(nonce),
    ));
}

/// Read an ENUMERATED as a signed [`i64`].
fn read_enumerated(reader: &mut Reader<'_>) -> CryptoResult<i64> {
    let content = reader.read_expected(der::Tag::universal(0x0a))?;
    if content.is_empty() || content.len() > 8 {
        return Err(CryptoError::StrError("ocsp: enumerated out of range"));
    }
    let mut value: i64 = if content[0] & 0x80 != 0 { -1 } else { 0 };
    for &byte in content {
        value = (value << 8) | byte as i64;
    }
    Ok(value)
}

/// Encode a small ENUMERATED value.
fn enumerated(value: u8) -> Vec<u8> {
    let mut encoded = der::integer_i64(value as i64);
    encoded[0] = 0x0a;
    encoded
}

#[cfg(test)]
mod tests;

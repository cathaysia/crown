//! CRMF (RFC 4211) certificate request messages.
//!
//! CRMF carries certificate requests as [`CertReqMessages`], a sequence of
//! [`CertReqMsg`] values. Each message holds a [`CertRequest`] with a
//! [`CertTemplate`] describing the requested certificate plus an optional
//! proof of possession ([`ProofOfPossession`]) and registration info.
//!
//! The module parses and encodes the full RFC 4211 structures (certificate
//! templates, optional validity, signature and key-encipherment POPs,
//! `EncryptedValue`/`EncryptedKey`, `PKMACValue` and `PBMParameter`) and can
//! verify or create the two common POP forms:
//!
//! - signature POP: [`CertReqMsg::sign_popo`] signs the DER of the
//!   `CertRequest` (the encoding OpenSSL produces when the certificate
//!   template contains both subject and public key) and
//!   [`ProofOfPossession::verify_signature`] checks it against the requested
//!   public key;
//! - RA-verified POP: [`ProofOfPossession::RaVerified`].
//!
//! ```
//! use crown::crmf::{CertReqMsg, CertReqMessages};
//! use crown::x509::keys::SubjectPublicKeyInfo;
//! use crown::x509::Name;
//!
//! # fn main() -> Result<(), crown::error::CryptoError> {
//! # let key_der = crown::asn1::pem::parse_first(
//! #     include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pki/rsa_pkcs8.pem")))?.data;
//! # let key = crown::x509::PrivateKeyInfo::parse(&key_der)?.decode()?;
//! let spki = SubjectPublicKeyInfo::from_public_key(&key.public_key()?)?;
//! let msg = CertReqMsg::for_key(&spki, None, Name::from_common_name("Test"))?;
//! let messages = CertReqMessages::new(vec![msg]);
//! let der = messages.encode();
//! let parsed = CertReqMessages::parse(&der)?;
//! assert_eq!(parsed.messages.len(), 1);
//! # Ok(())
//! # }
//! ```
//!
//! Only request-side structures are covered; CRMF also defines response
//! controls (e.g. `PKIArchiveOptions` is carried as a raw
//! [`AttributeTypeAndValue`] control) which callers can decode themselves.

use alloc::vec;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::ObjectIdentifier;
use crate::asn1::time::Asn1Time;
use crate::error::{CryptoError, CryptoResult};
use crate::rng::Rng;
use crate::x509::algorithm::{AlgorithmIdentifier, Hash, SignatureAlgorithm};
use crate::x509::extensions::{Extension, GeneralName};
use crate::x509::keys::{PrivateKey, PublicKey, SubjectPublicKeyInfo};
use crate::x509::name::Name;

/// `id-PasswordBasedMac` (1.2.840.113533.7.66.13), the CMP/CRMF password MAC
/// algorithm used with [`PbmParameter`].
pub const OID_ID_PASSWORD_BASED_MAC: &[u64] = &[1, 2, 840, 113533, 7, 66, 13];

/// `id-regInfo-certReq` (1.3.6.1.5.5.7.5.2.2), the `regInfo` attribute that
/// embeds a complete `CertRequest`.
pub const OID_ID_REG_INFO_CERT_REQ: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 5, 2, 2];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The content octets of a TLV, or the input unchanged when it is not a
/// well-formed TLV (only possible for caller-supplied values).
fn tlv_content(der: &[u8]) -> &[u8] {
    let mut reader = Reader::new(der);
    match reader.read_tlv() {
        Ok((_, content)) => content,
        Err(_) => der,
    }
}

/// The content octets of an `INTEGER` encoding produced by [`der::integer`].
fn integer_content(magnitude: &[u8]) -> Vec<u8> {
    let encoded = der::integer(magnitude);
    let mut reader = Reader::new(&encoded);
    reader
        .read_tlv()
        .map(|(_, content)| content.to_vec())
        .unwrap_or_default()
}

/// Decode an unsigned `INTEGER` content into a magnitude.
fn unsigned_integer(content: &[u8]) -> CryptoResult<Vec<u8>> {
    match content {
        [] => Err(CryptoError::StrError("crmf: empty integer")),
        [0] => Ok(Vec::new()),
        [0, rest @ ..] => Ok(rest.to_vec()),
        [first, ..] if first & 0x80 != 0 => Err(CryptoError::StrError("crmf: negative integer")),
        _ => Ok(content.to_vec()),
    }
}

/// Read an `[n] IMPLICIT INTEGER` as an unsigned magnitude.
fn read_implicit_integer(reader: &mut Reader<'_>, number: u32) -> CryptoResult<Vec<u8>> {
    unsigned_integer(reader.read_implicit(number, false)?)
}

/// Read an `[n] IMPLICIT BIT STRING` payload (no unused bits).
fn read_implicit_bit_string(reader: &mut Reader<'_>, number: u32) -> CryptoResult<Vec<u8>> {
    let content = reader.read_implicit(number, false)?;
    let (unused, data) = content
        .split_first()
        .ok_or(CryptoError::StrError("crmf: empty bit string"))?;
    if *unused != 0 {
        return Err(CryptoError::StrError(
            "crmf: unsupported bit string padding",
        ));
    }
    Ok(data.to_vec())
}

/// Parse an `[n] IMPLICIT AlgorithmIdentifier`: the tag replaced the
/// SEQUENCE tag, so the content is re-wrapped before parsing.
fn parse_implicit_algorithm(content: &[u8]) -> CryptoResult<AlgorithmIdentifier> {
    let sequence = der::sequence(content);
    let mut reader = Reader::new(&sequence);
    AlgorithmIdentifier::parse(&mut reader)
}

// ---------------------------------------------------------------------------
// Time and validity
// ---------------------------------------------------------------------------

/// `Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeChoice {
    /// UTCTime.
    UtcTime(Asn1Time),
    /// GeneralizedTime.
    GeneralizedTime(Asn1Time),
}

impl TimeChoice {
    /// Parse a `Time`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        match reader.peek_tag()? {
            tag if tag == der::UTC_TIME => Ok(TimeChoice::UtcTime(reader.read_utc_time()?)),
            tag if tag == der::GENERALIZED_TIME => {
                Ok(TimeChoice::GeneralizedTime(reader.read_generalized_time()?))
            }
            _ => Err(CryptoError::StrError("crmf: invalid time")),
        }
    }

    /// The calendar value, independent of the wire form.
    pub fn time(&self) -> Asn1Time {
        match self {
            TimeChoice::UtcTime(time) | TimeChoice::GeneralizedTime(time) => *time,
        }
    }

    /// Encode in its chosen wire form.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            TimeChoice::UtcTime(time) => der::utc_time(time),
            TimeChoice::GeneralizedTime(time) => der::generalized_time(time),
        }
    }
}

impl From<Asn1Time> for TimeChoice {
    fn from(time: Asn1Time) -> Self {
        if time.utc && (1950..=2049).contains(&time.year) {
            TimeChoice::UtcTime(time)
        } else {
            TimeChoice::GeneralizedTime(time)
        }
    }
}

/// `OptionalValidity ::= SEQUENCE { notBefore [0] Time OPTIONAL,
/// notAfter [1] Time OPTIONAL }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OptionalValidity {
    /// `notBefore`.
    pub not_before: Option<TimeChoice>,
    /// `notAfter`.
    pub not_after: Option<TimeChoice>,
}

impl OptionalValidity {
    /// An empty validity (both fields absent).
    pub fn new() -> Self {
        OptionalValidity::default()
    }

    /// Set `notBefore` from a calendar time.
    pub fn with_not_before(mut self, time: Asn1Time) -> Self {
        self.not_before = Some(time.into());
        self
    }

    /// Set `notAfter` from a calendar time.
    pub fn with_not_after(mut self, time: Asn1Time) -> Self {
        self.not_after = Some(time.into());
        self
    }

    /// Whether both fields are absent.
    pub fn is_empty(&self) -> bool {
        self.not_before.is_none() && self.not_after.is_none()
    }

    fn parse_content(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut validity = OptionalValidity::new();
        while !reader.is_empty() {
            let tag = reader.peek_tag()?;
            if tag.class != der::Class::ContextSpecific {
                return Err(CryptoError::StrError("crmf: invalid OptionalValidity"));
            }
            match tag.number {
                0 => {
                    let mut inner = reader.read_explicit(0)?;
                    validity.not_before = Some(TimeChoice::parse(&mut inner)?);
                }
                1 => {
                    let mut inner = reader.read_explicit(1)?;
                    validity.not_after = Some(TimeChoice::parse(&mut inner)?);
                }
                _ => return Err(CryptoError::StrError("crmf: invalid OptionalValidity")),
            }
        }
        Ok(validity)
    }

    /// Parse a standalone `OptionalValidity` SEQUENCE.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let validity = Self::parse_content(&mut seq)?;
        reader.expect_end()?;
        Ok(validity)
    }

    fn encode_content(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if let Some(time) = &self.not_before {
            content.extend_from_slice(&der::explicit(0, &time.encode()));
        }
        if let Some(time) = &self.not_after {
            content.extend_from_slice(&der::explicit(1, &time.encode()));
        }
        content
    }

    /// Encode as a `SEQUENCE`.
    pub fn encode(&self) -> Vec<u8> {
        der::sequence(&self.encode_content())
    }
}

// ---------------------------------------------------------------------------
// AttributeTypeAndValue
// ---------------------------------------------------------------------------

/// CRMF `AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }`.
///
/// Unlike the X.509 name attribute, the value is an arbitrary DER element
/// kept raw. `value` is the complete TLV of the attribute value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeTypeAndValue {
    /// Attribute type OID.
    pub oid: ObjectIdentifier,
    /// Raw DER of the attribute value, when present.
    pub value: Option<Vec<u8>>,
}

impl AttributeTypeAndValue {
    /// Build an attribute from a raw value TLV.
    pub fn new(oid: ObjectIdentifier, value: Option<Vec<u8>>) -> Self {
        AttributeTypeAndValue { oid, value }
    }

    /// Build the `id-regInfo-certReq` attribute wrapping a `CertRequest`.
    pub fn cert_request(request: &CertRequest) -> Self {
        AttributeTypeAndValue {
            oid: ObjectIdentifier::new(OID_ID_REG_INFO_CERT_REQ).expect("static oid"),
            value: Some(request.encode()),
        }
    }

    /// Parse one `AttributeTypeAndValue`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let oid = seq.read_oid()?;
        let value = if seq.is_empty() {
            None
        } else {
            Some(seq.read_raw_tlv()?.to_vec())
        };
        seq.expect_end()?;
        Ok(AttributeTypeAndValue { oid, value })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::oid(&self.oid);
        if let Some(value) = &self.value {
            content.extend_from_slice(value);
        }
        der::sequence(&content)
    }

    /// Parse the value as an embedded `CertRequest`, when it is the
    /// `id-regInfo-certReq` attribute.
    pub fn cert_request_value(&self) -> CryptoResult<Option<CertRequest>> {
        if !self.oid.matches(OID_ID_REG_INFO_CERT_REQ) {
            return Ok(None);
        }
        let value = self
            .value
            .as_deref()
            .ok_or(CryptoError::StrError("crmf: empty regInfo value"))?;
        Ok(Some(CertRequest::parse(value)?))
    }
}

/// Parse a `SEQUENCE OF AttributeTypeAndValue`.
fn parse_attributes(reader: &mut Reader<'_>) -> CryptoResult<Vec<AttributeTypeAndValue>> {
    let mut seq = reader.read_sequence()?;
    let mut attributes = Vec::new();
    while !seq.is_empty() {
        attributes.push(AttributeTypeAndValue::parse(&mut seq)?);
    }
    Ok(attributes)
}

/// Encode a `SEQUENCE OF AttributeTypeAndValue`, including the SEQUENCE tag.
fn encode_attributes(attributes: &[AttributeTypeAndValue]) -> Vec<u8> {
    let mut content = Vec::new();
    for attribute in attributes {
        content.extend_from_slice(&attribute.encode());
    }
    der::sequence(&content)
}

// ---------------------------------------------------------------------------
// CertTemplate
// ---------------------------------------------------------------------------

/// `CertTemplate ::= SEQUENCE { ... }` with every field OPTIONAL.
#[derive(Debug, Clone, Default)]
pub struct CertTemplate {
    /// `[0] version` (0 = v1, 1 = v2, 2 = v3).
    pub version: Option<u8>,
    /// `[1] serialNumber`.
    pub serial_number: Option<Vec<u8>>,
    /// `[2] signingAlg`.
    pub signing_alg: Option<AlgorithmIdentifier>,
    /// `[3] issuer`.
    pub issuer: Option<Name>,
    /// `[4] validity`.
    pub validity: OptionalValidity,
    /// `[5] subject`.
    pub subject: Option<Name>,
    /// `[6] publicKey`.
    pub public_key: Option<SubjectPublicKeyInfo>,
    /// `[7] issuerUID` BIT STRING payload.
    pub issuer_uid: Option<Vec<u8>>,
    /// `[8] subjectUID` BIT STRING payload.
    pub subject_uid: Option<Vec<u8>>,
    /// `[9] extensions`.
    pub extensions: Vec<Extension>,
}

impl PartialEq for CertTemplate {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.serial_number == other.serial_number
            && self.signing_alg == other.signing_alg
            && self.issuer == other.issuer
            && self.validity == other.validity
            && self.subject == other.subject
            && match (&self.public_key, &other.public_key) {
                (None, None) => true,
                (Some(a), Some(b)) => a.encode() == b.encode(),
                _ => false,
            }
            && self.issuer_uid == other.issuer_uid
            && self.subject_uid == other.subject_uid
            && self.extensions == other.extensions
    }
}

impl CertTemplate {
    /// An empty template.
    pub fn new() -> Self {
        CertTemplate::default()
    }

    /// A template carrying a subject and public key, the usual shape for an
    /// initial registration request.
    pub fn for_key(public_key: SubjectPublicKeyInfo, subject: Name) -> Self {
        CertTemplate {
            subject: Some(subject),
            public_key: Some(public_key),
            ..CertTemplate::default()
        }
    }

    /// Parse a `CertTemplate` from a DER SEQUENCE.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let template = Self::parse_reader(&mut reader)?;
        reader.expect_end()?;
        Ok(template)
    }

    pub(crate) fn parse_reader(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        Self::parse_content(&mut seq)
    }

    fn parse_content(seq: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut template = CertTemplate::new();
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            if tag.class != der::Class::ContextSpecific {
                return Err(CryptoError::StrError("crmf: invalid CertTemplate"));
            }
            match tag.number {
                0 => {
                    let version = read_implicit_integer(seq, 0)?;
                    if version.len() > 1 {
                        return Err(CryptoError::StrError("crmf: invalid version"));
                    }
                    template.version = Some(version.first().copied().unwrap_or(0));
                }
                1 => template.serial_number = Some(read_implicit_integer(seq, 1)?),
                2 => {
                    let content = seq.read_implicit(2, true)?;
                    template.signing_alg = Some(parse_implicit_algorithm(content)?);
                }
                3 => {
                    let mut inner = seq.read_explicit(3)?;
                    template.issuer = Some(Name::parse(&mut inner)?);
                }
                4 => {
                    let mut inner = seq.read_implicit_constructed(4)?;
                    template.validity = OptionalValidity::parse_content(&mut inner)?;
                }
                5 => {
                    let mut inner = seq.read_explicit(5)?;
                    template.subject = Some(Name::parse(&mut inner)?);
                }
                6 => {
                    let content = seq.read_implicit(6, true)?;
                    let spki = der::sequence(content);
                    template.public_key = Some(SubjectPublicKeyInfo::parse(&spki)?);
                }
                7 => template.issuer_uid = Some(read_implicit_bit_string(seq, 7)?),
                8 => template.subject_uid = Some(read_implicit_bit_string(seq, 8)?),
                9 => {
                    let mut inner = seq.read_implicit_constructed(9)?;
                    while !inner.is_empty() {
                        template.extensions.push(Extension::parse(&mut inner)?);
                    }
                }
                _ => return Err(CryptoError::StrError("crmf: invalid CertTemplate")),
            }
        }
        Ok(template)
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if let Some(version) = self.version {
            content.extend_from_slice(&der::implicit(0, false, &[version]));
        }
        if let Some(serial) = &self.serial_number {
            content.extend_from_slice(&der::implicit(1, false, &integer_content(serial)));
        }
        if let Some(alg) = &self.signing_alg {
            content.extend_from_slice(&der::implicit(2, true, tlv_content(&alg.encode())));
        }
        if let Some(issuer) = &self.issuer {
            content.extend_from_slice(&der::explicit(3, &issuer.encode()));
        }
        if !self.validity.is_empty() {
            content.extend_from_slice(&der::implicit(4, true, &self.validity.encode_content()));
        }
        if let Some(subject) = &self.subject {
            content.extend_from_slice(&der::explicit(5, &subject.encode()));
        }
        if let Some(public_key) = &self.public_key {
            let spki = public_key.encode();
            content.extend_from_slice(&der::implicit(6, true, tlv_content(&spki)));
        }
        if let Some(uid) = &self.issuer_uid {
            content.extend_from_slice(&der::implicit(7, false, &der::bit_string_payload(uid)));
        }
        if let Some(uid) = &self.subject_uid {
            content.extend_from_slice(&der::implicit(8, false, &der::bit_string_payload(uid)));
        }
        if !self.extensions.is_empty() {
            let mut extensions = Vec::new();
            for extension in &self.extensions {
                extensions.extend_from_slice(&extension.encode());
            }
            content.extend_from_slice(&der::implicit(9, true, &extensions));
        }
        der::sequence(&content)
    }

    /// The first extension with the given OID.
    pub fn extension(&self, arcs: &[u64]) -> Option<&Extension> {
        self.extensions.iter().find(|ext| ext.oid.matches(arcs))
    }
}

// ---------------------------------------------------------------------------
// CertRequest / CertReqMsg
// ---------------------------------------------------------------------------

/// `CertRequest ::= SEQUENCE { certReqId INTEGER, certTemplate CertTemplate,
/// controls SEQUENCE OF AttributeTypeAndValue OPTIONAL }`.
#[derive(Debug, Clone, PartialEq)]
pub struct CertRequest {
    /// `certReqId` magnitude.
    pub cert_req_id: Vec<u8>,
    /// Requested certificate template.
    pub cert_template: CertTemplate,
    /// Request controls.
    pub controls: Vec<AttributeTypeAndValue>,
}

impl CertRequest {
    /// Build a request with the given id and template.
    ///
    /// The id is stored as an unsigned magnitude; redundant leading zero
    /// octets are stripped so encode/parse round-trips compare equal.
    pub fn new(mut cert_req_id: Vec<u8>, cert_template: CertTemplate) -> Self {
        while cert_req_id.first() == Some(&0) {
            cert_req_id.remove(0);
        }
        CertRequest {
            cert_req_id,
            cert_template,
            controls: Vec::new(),
        }
    }

    /// Add a control.
    pub fn with_control(mut self, control: AttributeTypeAndValue) -> Self {
        self.controls.push(control);
        self
    }

    /// Parse a `CertRequest` from a DER SEQUENCE.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let request = Self::parse_reader(&mut reader)?;
        reader.expect_end()?;
        Ok(request)
    }

    fn parse_reader(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let cert_req_id = seq.read_integer()?.to_vec();
        let cert_template = CertTemplate::parse_reader(&mut seq)?;
        let controls = if seq.is_empty() {
            Vec::new()
        } else {
            parse_attributes(&mut seq)?
        };
        seq.expect_end()?;
        Ok(CertRequest {
            cert_req_id,
            cert_template,
            controls,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&self.cert_req_id);
        content.extend_from_slice(&self.cert_template.encode());
        if !self.controls.is_empty() {
            content.extend_from_slice(&encode_attributes(&self.controls));
        }
        der::sequence(&content)
    }

    /// The exact DER of the `certTemplate` field.
    pub fn cert_template_der(&self) -> Vec<u8> {
        self.cert_template.encode()
    }
}

/// `CertReqMsg ::= SEQUENCE { certReq CertRequest, popo ProofOfPossession
/// OPTIONAL, regInfo SEQUENCE OF AttributeTypeAndValue OPTIONAL }`.
#[derive(Debug, Clone, PartialEq)]
pub struct CertReqMsg {
    /// The certificate request.
    pub cert_req: CertRequest,
    /// Proof of possession of the requested private key.
    pub popo: Option<ProofOfPossession>,
    /// Registration info attributes.
    pub reg_info: Vec<AttributeTypeAndValue>,
}

impl CertReqMsg {
    /// Build a message from a request.
    pub fn new(cert_req: CertRequest) -> Self {
        CertReqMsg {
            cert_req,
            popo: None,
            reg_info: Vec::new(),
        }
    }

    /// A certificate request for `key`, optionally naming the issuer and
    /// asking for `subject`. This is the builder used for IR/CR bodies.
    pub fn for_key(
        public_key: &SubjectPublicKeyInfo,
        issuer: Option<Name>,
        subject: Name,
    ) -> CryptoResult<Self> {
        let template = CertTemplate {
            issuer,
            subject: Some(subject),
            public_key: Some(public_key.clone()),
            ..CertTemplate::default()
        };
        Ok(CertReqMsg::new(CertRequest::new(vec![0], template)))
    }

    /// [`Self::for_key`] from a decoded public key.
    pub fn for_key_identifier(
        key: &PublicKey,
        issuer: Option<Name>,
        subject: Name,
    ) -> CryptoResult<Self> {
        let spki = SubjectPublicKeyInfo::from_public_key(key)?;
        Self::for_key(&spki, issuer, subject)
    }

    /// Parse a `CertReqMsg` from a DER SEQUENCE.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let message = Self::parse_reader(&mut reader)?;
        reader.expect_end()?;
        Ok(message)
    }

    fn parse_reader(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let cert_req = CertRequest::parse_reader(&mut seq)?;
        let mut popo = None;
        let mut reg_info = Vec::new();
        if !seq.is_empty() {
            let tag = seq.peek_tag()?;
            if tag.class == der::Class::ContextSpecific && tag.number <= 3 {
                popo = Some(ProofOfPossession::parse(&mut seq)?);
            }
        }
        if !seq.is_empty() {
            reg_info = parse_attributes(&mut seq)?;
        }
        seq.expect_end()?;
        Ok(CertReqMsg {
            cert_req,
            popo,
            reg_info,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.cert_req.encode();
        if let Some(popo) = &self.popo {
            content.extend_from_slice(&popo.encode());
        }
        if !self.reg_info.is_empty() {
            content.extend_from_slice(&encode_attributes(&self.reg_info));
        }
        der::sequence(&content)
    }

    /// Sign a signature POP over the DER of the contained `CertRequest` and
    /// install it as the message's proof of possession.
    ///
    /// This is the RFC 4211 case where the certificate template carries both
    /// subject and public key, so no `POPOSigningKeyInput` is used.
    pub fn sign_popo(
        &mut self,
        key: &PrivateKey,
        algorithm: SignatureAlgorithm,
        rng: &mut impl Rng,
    ) -> CryptoResult<()> {
        let signed_data = self.cert_req.encode();
        self.popo = Some(ProofOfPossession::Signature(PopoSigningKey::sign(
            &signed_data,
            key,
            algorithm,
            rng,
        )?));
        Ok(())
    }

    /// Verify a signature POP over the DER of the contained `CertRequest`.
    ///
    /// Returns `Ok(None)` when the POP is absent or is not a signature POP.
    pub fn verify_popo(&self) -> CryptoResult<Option<bool>> {
        let Some(popo) = &self.popo else {
            return Ok(None);
        };
        let ProofOfPossession::Signature(key) = popo else {
            return Ok(None);
        };
        // RFC 4211 section 4.1: the signature covers the POPOSigningKeyInput
        // when present, otherwise the whole CertRequest.
        if let Some(input) = &key.poposk_input {
            let signed_data = input.encode();
            return Ok(Some(
                popo.verify_signature(&signed_data, &input.public_key.public_key)?,
            ));
        }
        let Some(public_key) = &self.cert_req.cert_template.public_key else {
            return Err(CryptoError::StrError("crmf: template has no public key"));
        };
        let signed_data = self.cert_req.encode();
        Ok(Some(
            popo.verify_signature(&signed_data, &public_key.public_key)?,
        ))
    }
}

/// `CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg`.
#[derive(Debug, Clone, PartialEq)]
pub struct CertReqMessages {
    /// The messages.
    pub messages: Vec<CertReqMsg>,
}

impl CertReqMessages {
    /// Build from a list of messages.
    pub fn new(messages: Vec<CertReqMsg>) -> Self {
        CertReqMessages { messages }
    }

    /// Parse a `CertReqMessages` from a DER SEQUENCE.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut messages = Vec::new();
        while !seq.is_empty() {
            messages.push(CertReqMsg::parse_reader(&mut seq)?);
        }
        reader.expect_end()?;
        if messages.is_empty() {
            return Err(CryptoError::StrError("crmf: empty CertReqMessages"));
        }
        Ok(CertReqMessages { messages })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for message in &self.messages {
            content.extend_from_slice(&message.encode());
        }
        der::sequence(&content)
    }
}

// ---------------------------------------------------------------------------
// ProofOfPossession
// ---------------------------------------------------------------------------

/// `ProofOfPossession`.
///
/// The variants mirror the wire choices directly; the signature variant is
/// naturally larger than the others.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum ProofOfPossession {
    /// `[0] raVerified` (POP was verified out of band).
    RaVerified,
    /// `[1] signature`.
    Signature(PopoSigningKey),
    /// `[2] keyEncipherment`.
    KeyEncipherment(PopoPrivKey),
    /// `[3] keyAgreement`.
    KeyAgreement(PopoPrivKey),
}

impl ProofOfPossession {
    /// Parse a `ProofOfPossession` choice.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let tag = reader.peek_tag()?;
        if tag.class != der::Class::ContextSpecific {
            return Err(CryptoError::StrError("crmf: invalid ProofOfPossession"));
        }
        match tag.number {
            0 => {
                let content = reader.read_implicit(0, false)?;
                if !content.is_empty() {
                    return Err(CryptoError::StrError("crmf: invalid raVerified"));
                }
                Ok(ProofOfPossession::RaVerified)
            }
            1 => {
                let mut inner = reader.read_implicit_constructed(1)?;
                Ok(ProofOfPossession::Signature(PopoSigningKey::parse_content(
                    &mut inner,
                )?))
            }
            2 => {
                let mut inner = reader.read_explicit(2)?;
                Ok(ProofOfPossession::KeyEncipherment(PopoPrivKey::parse(
                    &mut inner,
                )?))
            }
            3 => {
                let mut inner = reader.read_explicit(3)?;
                Ok(ProofOfPossession::KeyAgreement(PopoPrivKey::parse(
                    &mut inner,
                )?))
            }
            _ => Err(CryptoError::StrError("crmf: invalid ProofOfPossession")),
        }
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            ProofOfPossession::RaVerified => der::implicit(0, false, &[]),
            ProofOfPossession::Signature(key) => der::implicit(1, true, &key.encode_content()),
            ProofOfPossession::KeyEncipherment(priv_key) => der::explicit(2, &priv_key.encode()),
            ProofOfPossession::KeyAgreement(priv_key) => der::explicit(3, &priv_key.encode()),
        }
    }

    /// Verify the POP against a public key.
    ///
    /// `signed_data` is the DER of the `POPOSigningKeyInput` when the
    /// signature covers it, or the DER of the `CertRequest` when it does not
    /// (the usual OpenSSL case). Returns `Ok(false)` for non-signature POPs.
    pub fn verify_signature(
        &self,
        signed_data: &[u8],
        public_key: &PublicKey,
    ) -> CryptoResult<bool> {
        match self {
            ProofOfPossession::Signature(key) => key.verify(signed_data, public_key),
            _ => Ok(false),
        }
    }
}

/// `POPOSigningKey ::= SEQUENCE { poposkInput [0] OPTIONAL,
/// algorithmIdentifier AlgorithmIdentifier, signature BIT STRING }`.
#[derive(Debug, Clone, PartialEq)]
pub struct PopoSigningKey {
    /// The signed input, when the certificate template does not carry both
    /// subject and public key.
    pub poposk_input: Option<PopoSigningKeyInput>,
    /// Signature algorithm.
    pub algorithm_identifier: AlgorithmIdentifier,
    /// Raw signature.
    pub signature: Vec<u8>,
}

impl PopoSigningKey {
    fn parse_content(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let poposk_input =
            if !reader.is_empty() && reader.peek_tag()? == der::Tag::context_constructed(0) {
                let mut inner = reader.read_implicit_constructed(0)?;
                Some(PopoSigningKeyInput::parse_content(&mut inner)?)
            } else {
                None
            };
        let algorithm_identifier = AlgorithmIdentifier::parse(reader)?;
        let signature = reader.read_bit_string_bytes()?.to_vec();
        Ok(PopoSigningKey {
            poposk_input,
            algorithm_identifier,
            signature,
        })
    }

    /// Parse a standalone `POPOSigningKey` SEQUENCE.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let key = Self::parse_content(&mut seq)?;
        reader.expect_end()?;
        Ok(key)
    }

    fn encode_content(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if let Some(input) = &self.poposk_input {
            content.extend_from_slice(&der::implicit(0, true, &input.encode_content()));
        }
        content.extend_from_slice(&self.algorithm_identifier.encode());
        content.extend_from_slice(&der::bit_string(0, &self.signature));
        content
    }

    /// Encode as a DER SEQUENCE.
    pub fn encode(&self) -> Vec<u8> {
        der::sequence(&self.encode_content())
    }

    /// Sign `signed_data` and build a `POPOSigningKey` without
    /// `poposkInput`.
    pub fn sign(
        signed_data: &[u8],
        key: &PrivateKey,
        algorithm: SignatureAlgorithm,
        rng: &mut impl Rng,
    ) -> CryptoResult<Self> {
        // Signing with an algorithm that does not match the key is rejected
        // by PrivateKey::sign; the identifier is built from the algorithm.
        let identifier = algorithm.to_identifier();
        let signature = algorithm.sign(key, signed_data, rng)?;
        Ok(PopoSigningKey {
            poposk_input: None,
            algorithm_identifier: identifier,
            signature,
        })
    }

    /// Verify the signature over `signed_data` with `public_key`.
    pub fn verify(&self, signed_data: &[u8], public_key: &PublicKey) -> CryptoResult<bool> {
        let algorithm = SignatureAlgorithm::from_identifier(&self.algorithm_identifier)?;
        algorithm.verify(public_key, signed_data, &self.signature)
    }
}

/// `POPOSigningKeyInput ::= SEQUENCE { authInfo CHOICE { sender [0]
/// GeneralName, publicKeyMAC PKMACValue }, publicKey SubjectPublicKeyInfo }`.
#[derive(Debug, Clone)]
pub struct PopoSigningKeyInput {
    /// The authentication information.
    pub auth_info: PopoAuthInfo,
    /// The public key being proven.
    pub public_key: SubjectPublicKeyInfo,
}

impl PartialEq for PopoSigningKeyInput {
    fn eq(&self, other: &Self) -> bool {
        self.auth_info == other.auth_info && self.public_key.encode() == other.public_key.encode()
    }
}

/// The `authInfo` choice of [`PopoSigningKeyInput`].
#[derive(Debug, Clone, PartialEq)]
pub enum PopoAuthInfo {
    /// `[0] sender` (an explicitly tagged `GeneralName`).
    Sender(GeneralName),
    /// `publicKeyMAC` (a `PKMACValue` over the public key).
    PublicKeyMac(PKMACValue),
}

impl PopoSigningKeyInput {
    fn parse_content(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let tag = reader.peek_tag()?;
        let auth_info = if tag.class == der::Class::ContextSpecific && tag.number == 0 {
            let mut inner = reader.read_explicit(0)?;
            PopoAuthInfo::Sender(GeneralName::parse(&mut inner)?)
        } else {
            PopoAuthInfo::PublicKeyMac(PKMACValue::parse_content(reader)?)
        };
        let raw = reader.read_raw_tlv()?;
        let public_key = SubjectPublicKeyInfo::parse(raw)?;
        Ok(PopoSigningKeyInput {
            auth_info,
            public_key,
        })
    }

    fn encode_content(&self) -> Vec<u8> {
        let mut content = match &self.auth_info {
            PopoAuthInfo::Sender(name) => der::explicit(0, &name.encode()),
            PopoAuthInfo::PublicKeyMac(value) => value.encode(),
        };
        content.extend_from_slice(&self.public_key.encode());
        content
    }

    /// Parse a standalone `POPOSigningKeyInput` SEQUENCE.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let input = Self::parse_content(&mut seq)?;
        reader.expect_end()?;
        Ok(input)
    }

    /// Encode as a DER SEQUENCE.
    pub fn encode(&self) -> Vec<u8> {
        der::sequence(&self.encode_content())
    }
}

/// `POPOPrivKey` choices used by `keyEncipherment` and `keyAgreement`.
#[derive(Debug, Clone, PartialEq)]
pub enum PopoPrivKey {
    /// `[0] thisMessage` (deprecated): an encrypted private key.
    ThisMessage(Vec<u8>),
    /// `[1] subsequentMessage`: 0 = encrCert, 1 = challengeResp.
    SubsequentMessage(u8),
    /// `[2] dhMAC` (deprecated).
    DhMac(Vec<u8>),
    /// `[3] agreeMAC`.
    AgreeMac(PKMACValue),
    /// `[4] encryptedKey`: the DER of a CMS `EnvelopedData` SEQUENCE.
    EncryptedKey(Vec<u8>),
}

impl PopoPrivKey {
    /// Parse a `POPOPrivKey` choice.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let tag = reader.peek_tag()?;
        if tag.class != der::Class::ContextSpecific {
            return Err(CryptoError::StrError("crmf: invalid POPOPrivKey"));
        }
        match tag.number {
            0 => Ok(PopoPrivKey::ThisMessage(read_implicit_bit_string(
                reader, 0,
            )?)),
            1 => {
                let value = read_implicit_integer(reader, 1)?;
                if value.len() > 1 {
                    return Err(CryptoError::StrError("crmf: invalid subsequentMessage"));
                }
                Ok(PopoPrivKey::SubsequentMessage(
                    value.first().copied().unwrap_or(0),
                ))
            }
            2 => Ok(PopoPrivKey::DhMac(read_implicit_bit_string(reader, 2)?)),
            3 => {
                // `[3] IMPLICIT PKMACValue`: the tag replaces the SEQUENCE
                // tag, so the content is already the sequence content.
                let content = reader.read_implicit(3, true)?;
                let mut inner = Reader::new(content);
                Ok(PopoPrivKey::AgreeMac(PKMACValue::parse_content(
                    &mut inner,
                )?))
            }
            4 => {
                let content = reader.read_implicit(4, true)?;
                Ok(PopoPrivKey::EncryptedKey(der::sequence(content)))
            }
            _ => Err(CryptoError::StrError("crmf: invalid POPOPrivKey")),
        }
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PopoPrivKey::ThisMessage(data) => {
                der::implicit(0, false, &der::bit_string_payload(data))
            }
            PopoPrivKey::SubsequentMessage(value) => der::implicit(1, false, &[*value]),
            PopoPrivKey::DhMac(data) => der::implicit(2, false, &der::bit_string_payload(data)),
            PopoPrivKey::AgreeMac(value) => der::implicit(3, true, &value.encode_content()),
            PopoPrivKey::EncryptedKey(enveloped_data) => {
                der::implicit(4, true, tlv_content(enveloped_data))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Encrypted values and MAC structures
// ---------------------------------------------------------------------------

/// `PKMACValue ::= SEQUENCE { algId AlgorithmIdentifier, value BIT STRING }`.
#[derive(Debug, Clone, PartialEq)]
pub struct PKMACValue {
    /// The MAC algorithm (typically [`PbmParameter`] with
    /// [`OID_ID_PASSWORD_BASED_MAC`]).
    pub alg_id: AlgorithmIdentifier,
    /// The MAC value.
    pub value: Vec<u8>,
}

impl PKMACValue {
    /// Build a PKMAC value.
    pub fn new(alg_id: AlgorithmIdentifier, value: Vec<u8>) -> Self {
        PKMACValue { alg_id, value }
    }

    fn parse_content(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let alg_id = AlgorithmIdentifier::parse(reader)?;
        let value = reader.read_bit_string_bytes()?.to_vec();
        Ok(PKMACValue { alg_id, value })
    }

    /// Parse a standalone `PKMACValue` SEQUENCE.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let value = Self::parse_content(&mut seq)?;
        reader.expect_end()?;
        Ok(value)
    }

    fn encode_content(&self) -> Vec<u8> {
        let mut content = self.alg_id.encode();
        content.extend_from_slice(&der::bit_string(0, &self.value));
        content
    }

    /// Encode as a DER SEQUENCE.
    pub fn encode(&self) -> Vec<u8> {
        der::sequence(&self.encode_content())
    }
}

/// Map an HMAC algorithm OID to the digest it uses.
///
/// Both the PKCS#1 `hmacWithSHA*` OIDs and the `HMAC-MD5`/`HMAC-SHA1` OIDs
/// from RFC 3414 (`1.3.6.1.5.5.8.1.{1,2}`) are accepted; OpenSSL's `cmp`
/// app writes the latter for its SHA-1 default and the former for
/// `hmacWithSHA256`.
fn hmac_hash(oid: &ObjectIdentifier) -> Option<Hash> {
    let table: [(&[u64], Hash); 8] = [
        (&[1, 3, 6, 1, 5, 5, 8, 1, 1], Hash::Md5),
        (&[1, 3, 6, 1, 5, 5, 8, 1, 2], Hash::Sha1),
        (crate::asn1::oid::OID_HMAC_SHA1, Hash::Sha1),
        (crate::asn1::oid::OID_HMAC_SHA256, Hash::Sha256),
        (crate::asn1::oid::OID_HMAC_SHA384, Hash::Sha384),
        (crate::asn1::oid::OID_HMAC_SHA512, Hash::Sha512),
        (&[1, 2, 840, 113549, 2, 6], Hash::Md5),
        (&[1, 2, 840, 113549, 2, 8], Hash::Sha224),
    ];
    table
        .iter()
        .find(|(arcs, _)| oid.matches(arcs))
        .map(|(_, hash)| *hash)
}

/// `PBMParameter ::= SEQUENCE { salt OCTET STRING, owf AlgorithmIdentifier,
/// iterationCount INTEGER, mac AlgorithmIdentifier }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PbmParameter {
    /// Random salt.
    pub salt: Vec<u8>,
    /// One-way function used to derive the MAC key.
    pub owf: AlgorithmIdentifier,
    /// Number of hash iterations (RFC 4210 requires at least 100).
    pub iteration_count: u32,
    /// The MAC algorithm.
    pub mac: AlgorithmIdentifier,
}

impl PbmParameter {
    /// The HMAC algorithm OID for a digest, used for `PBMParameter.mac`.
    ///
    /// OpenSSL accepts the PKCS#1 `hmacWithSHA*` OIDs for all SHA-2 sizes.
    fn hmac_algorithm(hash: Hash) -> &'static [u64] {
        match hash {
            Hash::Md5 => &[1, 2, 840, 113549, 2, 6],
            Hash::Sha1 => crate::asn1::oid::OID_HMAC_SHA1,
            Hash::Sha224 => &[1, 2, 840, 113549, 2, 8],
            Hash::Sha384 => crate::asn1::oid::OID_HMAC_SHA384,
            Hash::Sha512 => crate::asn1::oid::OID_HMAC_SHA512,
            _ => crate::asn1::oid::OID_HMAC_SHA256,
        }
    }

    /// Build parameters from hashes for the OWF and MAC.
    pub fn new(salt: Vec<u8>, owf: Hash, iteration_count: u32, mac: Hash) -> Self {
        PbmParameter {
            salt,
            owf: AlgorithmIdentifier::new(
                ObjectIdentifier::new(owf.oid()).expect("static oid"),
                None,
            ),
            iteration_count,
            mac: AlgorithmIdentifier::new(
                ObjectIdentifier::new(Self::hmac_algorithm(mac)).expect("static oid"),
                None,
            ),
        }
    }

    /// Parse a `PBMParameter` from a DER SEQUENCE.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let salt = seq.read_octet_string()?.to_vec();
        let owf = AlgorithmIdentifier::parse(&mut seq)?;
        let iteration_count = seq.read_integer_i64()?;
        let mac = AlgorithmIdentifier::parse(&mut seq)?;
        seq.expect_end()?;
        let iteration_count = u32::try_from(iteration_count)
            .map_err(|_| CryptoError::StrError("crmf: invalid iteration count"))?;
        Ok(PbmParameter {
            salt,
            owf,
            iteration_count,
            mac,
        })
    }

    /// Encode as a DER SEQUENCE.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::octet_string(&self.salt);
        content.extend_from_slice(&self.owf.encode());
        content.extend_from_slice(&der::integer(&(self.iteration_count as u64).to_be_bytes()));
        content.extend_from_slice(&self.mac.encode());
        der::sequence(&content)
    }

    /// Derive the BASEKEY for this parameter set per RFC 4210 section 5.1.3.1
    /// (OWF applied `iterationCount` times to `password || salt`).
    ///
    /// The iteration count is limited to the range RFC 4210 requires
    /// (100..=100000, the same bound OpenSSL applies) so a hostile parameter
    /// set cannot force unbounded hashing.
    pub fn derive_key(&self, password: &[u8]) -> CryptoResult<Vec<u8>> {
        if !(100..=100_000).contains(&self.iteration_count) {
            return Err(CryptoError::StrError(
                "crmf: invalid PBMParameter iteration count",
            ));
        }
        let owf = Hash::from_oid(&self.owf.oid).ok_or(CryptoError::UnsupportedOperation(
            "crmf: unsupported OWF".into(),
        ))?;
        let mut input = Vec::with_capacity(password.len() + self.salt.len());
        input.extend_from_slice(password);
        input.extend_from_slice(&self.salt);
        let mut base = owf.digest(&input)?;
        for _ in 1..self.iteration_count {
            base = owf.digest(&base)?;
        }
        Ok(base)
    }

    /// Compute the password MAC over `message` per RFC 4210 section 5.1.3.1.
    ///
    /// Only HMAC MAC algorithms are supported.
    pub fn mac(&self, password: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
        let key = self.derive_key(password)?;
        let mac_hash = hmac_hash(&self.mac.oid).ok_or(CryptoError::UnsupportedOperation(
            "crmf: unsupported MAC".into(),
        ))?;
        mac_hash.hmac(&key, message)
    }
}

/// `EncryptedValue ::= SEQUENCE { ... encValue BIT STRING }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EncryptedValue {
    /// `[0] intendedAlg`.
    pub intended_alg: Option<AlgorithmIdentifier>,
    /// `[1] symmAlg`.
    pub symm_alg: Option<AlgorithmIdentifier>,
    /// `[2] encSymmKey` BIT STRING payload.
    pub enc_symm_key: Option<Vec<u8>>,
    /// `[3] keyAlg`.
    pub key_alg: Option<AlgorithmIdentifier>,
    /// `[4] valueHint`.
    pub value_hint: Option<Vec<u8>>,
    /// `encValue` BIT STRING payload.
    pub enc_value: Vec<u8>,
}

impl EncryptedValue {
    /// Parse an `EncryptedValue` from a DER SEQUENCE.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut value = EncryptedValue::default();
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            if tag.class == der::Class::ContextSpecific {
                match tag.number {
                    0 => {
                        let content = seq.read_implicit(0, true)?;
                        value.intended_alg = Some(parse_implicit_algorithm(content)?);
                        continue;
                    }
                    1 => {
                        let content = seq.read_implicit(1, true)?;
                        value.symm_alg = Some(parse_implicit_algorithm(content)?);
                        continue;
                    }
                    2 => {
                        value.enc_symm_key = Some(read_implicit_bit_string(&mut seq, 2)?);
                        continue;
                    }
                    3 => {
                        let content = seq.read_implicit(3, true)?;
                        value.key_alg = Some(parse_implicit_algorithm(content)?);
                        continue;
                    }
                    4 => {
                        value.value_hint = Some(seq.read_implicit(4, false)?.to_vec());
                        continue;
                    }
                    _ => return Err(CryptoError::StrError("crmf: invalid EncryptedValue")),
                }
            }
            value.enc_value = seq.read_bit_string_bytes()?.to_vec();
        }
        reader.expect_end()?;
        Ok(value)
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if let Some(alg) = &self.intended_alg {
            content.extend_from_slice(&der::implicit(0, true, tlv_content(&alg.encode())));
        }
        if let Some(alg) = &self.symm_alg {
            content.extend_from_slice(&der::implicit(1, true, tlv_content(&alg.encode())));
        }
        if let Some(key) = &self.enc_symm_key {
            content.extend_from_slice(&der::implicit(2, false, &der::bit_string_payload(key)));
        }
        if let Some(alg) = &self.key_alg {
            content.extend_from_slice(&der::implicit(3, true, tlv_content(&alg.encode())));
        }
        if let Some(hint) = &self.value_hint {
            content.extend_from_slice(&der::implicit(4, false, hint));
        }
        content.extend_from_slice(&der::bit_string(0, &self.enc_value));
        der::sequence(&content)
    }
}

/// `EncryptedKey ::= CHOICE { encryptedValue EncryptedValue, envelopedData
/// [0] EnvelopedData }` (RFC 4211 / RFC 9480).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptedKey {
    /// The deprecated `EncryptedValue` alternative.
    EncryptedValue(EncryptedValue),
    /// A CMS `EnvelopedData` SEQUENCE (stored as its full DER).
    EnvelopedData(Vec<u8>),
}

impl EncryptedKey {
    /// Parse an `EncryptedKey` choice.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let tag = reader.peek_tag()?;
        if tag.class == der::Class::ContextSpecific && tag.number == 0 {
            let content = reader.read_implicit(0, true)?;
            return Ok(EncryptedKey::EnvelopedData(der::sequence(content)));
        }
        let raw = reader.read_raw_tlv()?.to_vec();
        Ok(EncryptedKey::EncryptedValue(EncryptedValue::parse(&raw)?))
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            EncryptedKey::EncryptedValue(value) => value.encode(),
            EncryptedKey::EnvelopedData(enveloped_data) => {
                der::implicit(0, true, tlv_content(enveloped_data))
            }
        }
    }
}

#[cfg(test)]
mod tests;

//! X.509 attribute certificates (RFC 5755).
//!
//! Parsing, encoding, signing and signature verification for the attribute
//! certificates used to carry authorisation attributes (role, group,
//! clearance) independently of the identity certificate.

use alloc::string::String;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::ObjectIdentifier;
use crate::asn1::pem;
use crate::asn1::time::Asn1Time;
use crate::error::{CryptoError, CryptoResult};
use crate::rng::Rng;

use super::algorithm::{AlgorithmIdentifier, SignatureAlgorithm};
use super::attribute::Attribute;
use super::extensions::{Extension, GeneralName};
use super::keys::{PrivateKey, PublicKey};
use super::name::Name;

/// `AttCertVersion ::= INTEGER { v2(1) }`.
pub const VERSION_V2: u8 = 1;

/// `ObjectDigestInfo.digestedObjectType` values.
pub const DIGESTED_OBJECT_PUBLIC_KEY: u8 = 0;
/// `ObjectDigestInfo.digestedObjectType`: `publicKeyCert`.
pub const DIGESTED_OBJECT_PUBLIC_KEY_CERT: u8 = 1;
/// `ObjectDigestInfo.digestedObjectType`: `otherObjectTypes`.
pub const DIGESTED_OBJECT_OTHER: u8 = 2;

/// `IssuerSerial ::= SEQUENCE { issuer GeneralNames, serial
/// CertificateSerialNumber, issuerUID UniqueIdentifier OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerSerial {
    /// The issuer names.
    pub issuer: Vec<GeneralName>,
    /// The serial number magnitude.
    pub serial: Vec<u8>,
    /// `issuerUID` BIT STRING payload.
    pub issuer_uid: Option<Vec<u8>>,
}

impl IssuerSerial {
    /// Parse an `IssuerSerial`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let issuer_serial = Self::parse_fields(&mut seq)?;
        seq.expect_end()?;
        Ok(issuer_serial)
    }

    /// Parse the `IssuerSerial` fields (no surrounding `SEQUENCE`).
    pub fn parse_fields(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let issuer = parse_general_names_in(reader)?;
        let serial = reader.read_integer()?.to_vec();
        let issuer_uid = if !reader.is_empty() {
            Some(reader.read_bit_string_bytes()?.to_vec())
        } else {
            None
        };
        Ok(IssuerSerial {
            issuer,
            serial,
            issuer_uid,
        })
    }

    /// Encode the `IssuerSerial` fields (no surrounding `SEQUENCE`).
    pub fn encode_content(&self) -> Vec<u8> {
        let mut content = encoding::general_names(&self.issuer);
        content.extend_from_slice(&der::integer(&self.serial));
        if let Some(uid) = &self.issuer_uid {
            content.extend_from_slice(&der::bit_string(0, uid));
        }
        content
    }

    /// Encode an `IssuerSerial`.
    pub fn encode(&self) -> Vec<u8> {
        der::sequence(&self.encode_content())
    }

    /// Whether this identifier names `certificate`.
    pub fn matches(&self, certificate: &Certificate) -> bool {
        self.serial == certificate.serial_number()
            && self.issuer.iter().any(|name| match name {
                GeneralName::DirectoryName(issuer) => issuer == certificate.issuer(),
                _ => false,
            })
    }
}

/// `ObjectDigestInfo ::= SEQUENCE { digestedObjectType ENUMERATED,
/// otherObjectTypeID OID OPTIONAL, digestAlgorithm AlgorithmIdentifier,
/// objectDigest BIT STRING }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectDigestInfo {
    /// The digested object type.
    pub digested_object_type: u8,
    /// `otherObjectTypeID`, when the type is `otherObjectTypes`.
    pub other_object_type_id: Option<ObjectIdentifier>,
    /// The digest algorithm.
    pub digest_algorithm: AlgorithmIdentifier,
    /// The digest octets.
    pub object_digest: Vec<u8>,
}

impl ObjectDigestInfo {
    /// Parse an `ObjectDigestInfo`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let info = Self::parse_fields(&mut seq)?;
        seq.expect_end()?;
        Ok(info)
    }

    /// Parse the `ObjectDigestInfo` fields (no surrounding `SEQUENCE`).
    pub fn parse_fields(seq: &mut Reader<'_>) -> CryptoResult<Self> {
        let (tag, value) = seq.read_tlv()?;
        if tag != der::Tag::universal(0x0a) || value.len() != 1 {
            return Err(CryptoError::StrError("x509: invalid object digest info"));
        }
        let digested_object_type = value[0];
        let other_object_type_id = if seq.peek_tag()? == der::OBJECT_IDENTIFIER {
            Some(seq.read_oid()?)
        } else {
            None
        };
        let digest_algorithm = AlgorithmIdentifier::parse(seq)?;
        let object_digest = seq.read_bit_string_bytes()?.to_vec();
        Ok(ObjectDigestInfo {
            digested_object_type,
            other_object_type_id,
            digest_algorithm,
            object_digest,
        })
    }

    /// Encode the `ObjectDigestInfo` fields (no surrounding `SEQUENCE`).
    pub fn encode_content(&self) -> Vec<u8> {
        let mut content = der::tlv(der::Tag::universal(0x0a), &[self.digested_object_type]);
        if let Some(oid) = &self.other_object_type_id {
            content.extend_from_slice(&der::oid(oid));
        }
        content.extend_from_slice(&self.digest_algorithm.encode());
        content.extend_from_slice(&der::bit_string(0, &self.object_digest));
        content
    }

    /// Encode an `ObjectDigestInfo`.
    pub fn encode(&self) -> Vec<u8> {
        der::sequence(&self.encode_content())
    }
}

/// `Holder ::= SEQUENCE { baseCertificateID [0] IssuerSerial OPTIONAL,
/// entityName [1] GeneralNames OPTIONAL, objectDigestInfo [2]
/// ObjectDigestInfo OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Holder {
    /// The holder certificate identifier.
    pub base_certificate_id: Option<IssuerSerial>,
    /// The holder entity names.
    pub entity_name: Option<Vec<GeneralName>>,
    /// The holder object digest.
    pub object_digest_info: Option<ObjectDigestInfo>,
}

impl Holder {
    /// Parse a `Holder`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let mut holder = Holder::default();
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            match (tag.class, tag.number) {
                (der::Class::ContextSpecific, 0) => {
                    let mut inner = seq.read_implicit_constructed(0)?;
                    holder.base_certificate_id = Some(IssuerSerial::parse_fields(&mut inner)?);
                }
                (der::Class::ContextSpecific, 1) => {
                    let mut inner = seq.read_implicit_constructed(1)?;
                    let mut names = Vec::new();
                    while !inner.is_empty() {
                        names.push(GeneralName::parse(&mut inner)?);
                    }
                    holder.entity_name = Some(names);
                }
                (der::Class::ContextSpecific, 2) => {
                    let mut inner = seq.read_implicit_constructed(2)?;
                    holder.object_digest_info = Some(ObjectDigestInfo::parse_fields(&mut inner)?);
                }
                _ => return Err(CryptoError::StrError("x509: invalid holder")),
            }
        }
        Ok(holder)
    }

    /// Encode a `Holder`.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if let Some(id) = &self.base_certificate_id {
            content.extend_from_slice(&der::implicit(0, true, &id.encode_content()));
        }
        if let Some(names) = &self.entity_name {
            let mut names_content = Vec::new();
            for name in names {
                names_content.extend_from_slice(&name.encode());
            }
            content.extend_from_slice(&der::implicit(1, true, &names_content));
        }
        if let Some(info) = &self.object_digest_info {
            content.extend_from_slice(&der::implicit(2, true, &info.encode_content()));
        }
        der::sequence(&content)
    }

    /// Whether this holder names `certificate` (base certificate id or
    /// entity name).
    pub fn matches(&self, certificate: &Certificate) -> bool {
        if let Some(id) = &self.base_certificate_id {
            if id.matches(certificate) {
                return true;
            }
        }
        if let Some(names) = &self.entity_name {
            if names.iter().any(|name| match name {
                GeneralName::DirectoryName(subject) => subject == certificate.subject(),
                _ => false,
            }) {
                return true;
            }
        }
        false
    }
}

/// `V2Form ::= SEQUENCE { issuerName GeneralNames OPTIONAL,
/// baseCertificateID [0] IssuerSerial OPTIONAL, objectDigestInfo [1]
/// ObjectDigestInfo OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V2Form {
    /// The issuer names.
    pub issuer_name: Option<Vec<GeneralName>>,
    /// The issuer certificate identifier.
    pub base_certificate_id: Option<IssuerSerial>,
    /// The issuer object digest.
    pub object_digest_info: Option<ObjectDigestInfo>,
}

impl V2Form {
    /// Parse a `V2Form`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let seq = reader.read_sequence()?;
        Self::parse_fields(seq)
    }

    /// Parse the `V2Form` fields (no surrounding `SEQUENCE`).
    pub fn parse_fields(mut seq: Reader<'_>) -> CryptoResult<Self> {
        let mut form = V2Form::default();
        if seq.peek_tag()? == der::SEQUENCE {
            form.issuer_name = Some(parse_general_names_in(&mut seq)?);
        }
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            match (tag.class, tag.number) {
                (der::Class::ContextSpecific, 0) => {
                    let mut inner = seq.read_implicit_constructed(0)?;
                    form.base_certificate_id = Some(IssuerSerial::parse_fields(&mut inner)?);
                }
                (der::Class::ContextSpecific, 1) => {
                    let mut inner = seq.read_implicit_constructed(1)?;
                    form.object_digest_info = Some(ObjectDigestInfo::parse_fields(&mut inner)?);
                }
                _ => return Err(CryptoError::StrError("x509: invalid V2Form")),
            }
        }
        Ok(form)
    }

    /// Encode the `V2Form` fields (no surrounding `SEQUENCE`).
    pub fn encode_content(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if let Some(names) = &self.issuer_name {
            content.extend_from_slice(&encoding::general_names(names));
        }
        if let Some(id) = &self.base_certificate_id {
            content.extend_from_slice(&der::implicit(0, true, &id.encode_content()));
        }
        if let Some(info) = &self.object_digest_info {
            content.extend_from_slice(&der::implicit(1, true, &info.encode_content()));
        }
        content
    }

    /// Encode a `V2Form`.
    pub fn encode(&self) -> Vec<u8> {
        der::sequence(&self.encode_content())
    }
}

/// `AttCertIssuer ::= CHOICE { v1Form GeneralNames, v2Form [0] V2Form }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttCertIssuer {
    /// The RFC 3281 v1 form.
    V1(Vec<GeneralName>),
    /// The RFC 5755 v2 form.
    V2(V2Form),
}

impl AttCertIssuer {
    /// Parse an `AttCertIssuer`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let tag = reader.peek_tag()?;
        if tag.class == der::Class::ContextSpecific && tag.number == 0 {
            let inner = reader.read_implicit_constructed(0)?;
            Ok(AttCertIssuer::V2(V2Form::parse_fields(inner)?))
        } else {
            Ok(AttCertIssuer::V1(parse_general_names_in(reader)?))
        }
    }

    /// Encode an `AttCertIssuer`.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            AttCertIssuer::V1(names) => encoding::general_names(names),
            AttCertIssuer::V2(form) => der::implicit(0, true, &form.encode_content()),
        }
    }

    /// The issuer directory names.
    pub fn directory_names(&self) -> Vec<&Name> {
        let names: &[GeneralName] = match self {
            AttCertIssuer::V1(names) => names,
            AttCertIssuer::V2(form) => form.issuer_name.as_deref().unwrap_or(&[]),
        };
        names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DirectoryName(name) => Some(name),
                _ => None,
            })
            .collect()
    }
}

/// `AttCertValidityPeriod ::= SEQUENCE { notBeforeTime GeneralizedTime,
/// notAfterTime GeneralizedTime }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttCertValidityPeriod {
    /// `notBeforeTime`.
    pub not_before: Asn1Time,
    /// `notAfterTime`.
    pub not_after: Asn1Time,
}

impl AttCertValidityPeriod {
    /// Whether `now` (Unix seconds) falls inside the period.
    pub fn contains(&self, now: i64) -> bool {
        self.not_before.to_unix() <= now && now <= self.not_after.to_unix()
    }

    /// Parse an `AttCertValidityPeriod`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let not_before = seq.read_generalized_time()?;
        let not_after = seq.read_generalized_time()?;
        seq.expect_end()?;
        Ok(AttCertValidityPeriod {
            not_before,
            not_after,
        })
    }

    /// Encode an `AttCertValidityPeriod`.
    pub fn encode(&self) -> Vec<u8> {
        let mut not_before = self.not_before;
        not_before.utc = false;
        let mut not_after = self.not_after;
        not_after.utc = false;
        let mut content = der::generalized_time(&not_before);
        content.extend_from_slice(&der::generalized_time(&not_after));
        der::sequence(&content)
    }
}

/// `AttributeCertificateInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeCertificateInfo {
    /// Version: 1 = v2.
    pub version: u8,
    /// The certificate holder.
    pub holder: Holder,
    /// The issuing authority.
    pub issuer: AttCertIssuer,
    /// Signature algorithm (must match the outer one).
    pub signature: AlgorithmIdentifier,
    /// Serial number magnitude.
    pub serial_number: Vec<u8>,
    /// Validity period.
    pub validity: AttCertValidityPeriod,
    /// The attributes.
    pub attributes: Vec<Attribute>,
    /// `issuerUniqueID` BIT STRING payload.
    pub issuer_unique_id: Option<Vec<u8>>,
    /// v2 extensions.
    pub extensions: Vec<Extension>,
}

impl AttributeCertificateInfo {
    /// Parse an `AttributeCertificateInfo`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let version = u8::try_from(seq.read_integer_i64()?)
            .map_err(|_| CryptoError::StrError("x509: invalid AC version"))?;
        let holder = Holder::parse(&mut seq)?;
        let issuer = AttCertIssuer::parse(&mut seq)?;
        let signature = AlgorithmIdentifier::parse(&mut seq)?;
        let serial_number = seq.read_integer()?.to_vec();
        let validity = AttCertValidityPeriod::parse(&mut seq)?;
        let mut attributes_reader = seq.read_sequence()?;
        let mut attributes = Vec::new();
        while !attributes_reader.is_empty() {
            attributes.push(Attribute::parse(&mut attributes_reader)?);
        }
        let issuer_unique_id = if !seq.is_empty() && seq.peek_tag()? == der::BIT_STRING {
            Some(seq.read_bit_string_bytes()?.to_vec())
        } else {
            None
        };
        let mut extensions = Vec::new();
        if !seq.is_empty() {
            // RFC 5755 wraps the extensions in `[0] EXPLICIT`; RFC 3281
            // files (still produced by some toolkits) leave them untagged.
            let tag = seq.peek_tag()?;
            let mut ext_reader = if tag.class == der::Class::ContextSpecific && tag.number == 0 {
                seq.read_explicit(0)?.read_sequence()?
            } else {
                seq.read_sequence()?
            };
            while !ext_reader.is_empty() {
                extensions.push(Extension::parse(&mut ext_reader)?);
            }
        }
        seq.expect_end()?;
        reader.expect_end()?;
        Ok(AttributeCertificateInfo {
            version,
            holder,
            issuer,
            signature,
            serial_number,
            validity,
            attributes,
            issuer_unique_id,
            extensions,
        })
    }

    /// Encode an `AttributeCertificateInfo`.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.version]);
        content.extend_from_slice(&self.holder.encode());
        content.extend_from_slice(&self.issuer.encode());
        content.extend_from_slice(&self.signature.encode());
        content.extend_from_slice(&der::integer(&self.serial_number));
        content.extend_from_slice(&self.validity.encode());
        let mut attributes = Vec::new();
        for attribute in &self.attributes {
            attributes.extend_from_slice(&attribute.encode());
        }
        content.extend_from_slice(&der::sequence(&attributes));
        if let Some(uid) = &self.issuer_unique_id {
            content.extend_from_slice(&der::bit_string(0, uid));
        }
        if !self.extensions.is_empty() {
            let mut encoded = Vec::new();
            for extension in &self.extensions {
                encoded.extend_from_slice(&extension.encode());
            }
            content.extend_from_slice(&der::explicit(0, &der::sequence(&encoded)));
        }
        der::sequence(&content)
    }

    /// Build an info structure (v2) signed by the given algorithm.
    pub fn build(
        holder: Holder,
        issuer: AttCertIssuer,
        serial_number: Vec<u8>,
        validity: AttCertValidityPeriod,
        attributes: Vec<Attribute>,
        extensions: Vec<Extension>,
        signature_algorithm: SignatureAlgorithm,
    ) -> Self {
        AttributeCertificateInfo {
            version: VERSION_V2,
            holder,
            issuer,
            signature: signature_algorithm.to_identifier(),
            serial_number,
            validity,
            attributes,
            issuer_unique_id: None,
            extensions,
        }
    }

    /// Look up an attribute by OID.
    pub fn attribute(&self, arcs: &[u64]) -> Option<&Attribute> {
        self.attributes
            .iter()
            .find(|attribute| attribute.oid.matches(arcs))
    }
}

/// `AttributeCertificate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeCertificate {
    info: AttributeCertificateInfo,
    signature_algorithm: AlgorithmIdentifier,
    signature: Vec<u8>,
    info_raw: Vec<u8>,
}

impl AttributeCertificate {
    /// Parse a DER `AttributeCertificate`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let info_raw = seq.read_raw_tlv()?.to_vec();
        let info = AttributeCertificateInfo::parse(&info_raw)?;
        let signature_algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        let signature = seq.read_bit_string_bytes()?.to_vec();
        seq.expect_end()?;
        reader.expect_end()?;
        Ok(AttributeCertificate {
            info,
            signature_algorithm,
            signature,
            info_raw,
        })
    }

    /// Parse a PEM `ATTRIBUTE CERTIFICATE`.
    pub fn from_pem(pem_text: &str) -> CryptoResult<Self> {
        let block = pem::parse_first(pem_text)?;
        if block.label != "ATTRIBUTE CERTIFICATE" {
            return Err(CryptoError::StrError(
                "x509: not an attribute certificate PEM block",
            ));
        }
        Self::parse(&block.data)
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.info_raw.clone();
        content.extend_from_slice(&self.signature_algorithm.encode());
        content.extend_from_slice(&der::bit_string(0, &self.signature));
        der::sequence(&content)
    }

    /// Encode as PEM.
    pub fn to_pem(&self) -> String {
        pem::encode("ATTRIBUTE CERTIFICATE", &self.encode())
    }

    /// The parsed info structure.
    pub fn info(&self) -> &AttributeCertificateInfo {
        &self.info
    }

    /// The ACinfo DER (the signed part).
    pub fn info_der(&self) -> &[u8] {
        &self.info_raw
    }

    /// The signature algorithm identifier.
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// The raw signature.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The serial number magnitude.
    pub fn serial_number(&self) -> &[u8] {
        &self.info.serial_number
    }

    /// The validity period.
    pub fn validity(&self) -> AttCertValidityPeriod {
        self.info.validity
    }

    /// Whether the attribute certificate is valid at `now`.
    pub fn is_valid_at(&self, now: i64) -> bool {
        self.info.validity.contains(now)
    }

    /// Verify the signature with an issuer public key.
    pub fn verify_signature(&self, issuer: &PublicKey) -> CryptoResult<bool> {
        let algorithm = SignatureAlgorithm::from_identifier(&self.signature_algorithm)?;
        algorithm.verify(issuer, &self.info_raw, &self.signature)
    }

    /// Verify the signature and the issuer name against an issuer
    /// certificate.
    pub fn verify(&self, issuer: &Certificate, now: Option<i64>) -> CryptoResult<()> {
        if let Some(now) = now {
            if !self.is_valid_at(now) {
                return Err(CryptoError::StrError(
                    "x509: attribute certificate is not valid at this time",
                ));
            }
        }
        let names = self.info.issuer.directory_names();
        if !names.is_empty() && !names.iter().any(|name| *name == issuer.subject()) {
            return Err(CryptoError::StrError("x509: AC issuer name mismatch"));
        }
        if !self.verify_signature(issuer.public_key())? {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }

    /// Whether the AC holder is `certificate`.
    pub fn holder_matches(&self, certificate: &Certificate) -> bool {
        self.info.holder.matches(certificate)
    }

    /// Sign an info structure.
    pub fn sign(
        info: AttributeCertificateInfo,
        key: &PrivateKey,
        rng: &mut impl Rng,
    ) -> CryptoResult<Self> {
        let info_raw = info.encode();
        let signature_algorithm = info.signature.clone();
        let algorithm = SignatureAlgorithm::from_identifier(&signature_algorithm)?;
        let signature = algorithm.sign(key, &info_raw, rng)?;
        Ok(AttributeCertificate {
            info,
            signature_algorithm,
            signature,
            info_raw,
        })
    }
}

/// Helpers shared with the rest of the module.
mod encoding {
    use super::*;

    pub(super) fn general_names(names: &[GeneralName]) -> Vec<u8> {
        let mut content = Vec::new();
        for name in names {
            content.extend_from_slice(&name.encode());
        }
        der::sequence(&content)
    }
}

fn parse_general_names_in(reader: &mut Reader<'_>) -> CryptoResult<Vec<GeneralName>> {
    let mut seq = reader.read_sequence()?;
    let mut names = Vec::new();
    while !seq.is_empty() {
        names.push(GeneralName::parse(&mut seq)?);
    }
    Ok(names)
}

use super::cert::Certificate;

/// Build an `Attribute` from an OID and string values (used by tests and
/// callers of [`AttributeCertificateInfo::build`]).
pub fn attribute_from_text(oid: &[u64], values: &[&str]) -> Attribute {
    let oid = ObjectIdentifier::new(oid).expect("static oid");
    Attribute::new(
        oid,
        values.iter().map(|value| der::utf8_string(value)).collect(),
    )
}

/// The `id-aca-*` attribute OIDs from RFC 5755 Appendix A.
pub mod attr {
    /// `id-aca-authenticationInfo` (1.3.6.1.5.5.7.10.1).
    pub const AUTHENTICATION_INFO: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 10, 1];
    /// `id-aca-accessIdentity` (1.3.6.1.5.5.7.10.2).
    pub const ACCESS_IDENTITY: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 10, 2];
    /// `id-aca-chargingIdentity` (1.3.6.1.5.5.7.10.3).
    pub const CHARGING_IDENTITY: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 10, 3];
    /// `id-aca-group` (1.3.6.1.5.5.7.10.4).
    pub const GROUP: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 10, 4];
    /// `id-aca-role` (1.3.6.1.5.5.7.10.5).
    pub const ROLE: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 10, 5];
    /// `id-aca-clearance` (1.3.6.1.5.5.7.10.6).
    pub const CLEARANCE: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 10, 6];
}

/// The `id-pe-ac-proxying` extension OID (1.3.6.1.5.5.7.1.10).
pub const OID_PE_AC_PROXYING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 10];
/// The `id-ce-authorityAttributeIdentifier` extension OID (2.5.29.38).
pub const OID_CE_AUTHORITY_ATTRIBUTE_IDENTIFIER: &[u64] = &[2, 5, 29, 38];
/// The `id-ce-roleSpecCertIdentifier` extension OID (2.5.29.39).
pub const OID_CE_ROLE_SPEC_CERT_IDENTIFIER: &[u64] = &[2, 5, 29, 39];

/// Re-export for callers that only need the string form of an attribute
/// value.
pub fn attribute_text(attribute: &Attribute) -> Option<String> {
    attribute.first_text()
}

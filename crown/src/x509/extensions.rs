//! X.509 v3 extensions.

use alloc::string::String;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::{self, ObjectIdentifier};
use crate::error::{CryptoError, CryptoResult};

use super::attribute::Attribute;
use super::name::Name;

/// A raw extension: `SEQUENCE { extnID, critical DEFAULT FALSE, extnValue }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// Extension OID.
    pub oid: ObjectIdentifier,
    /// Criticality flag.
    pub critical: bool,
    /// The DER contents of the `extnValue` OCTET STRING (the extension's own
    /// ASN.1 encoding).
    pub value: Vec<u8>,
}

impl Extension {
    /// Build an extension.
    pub fn new(oid: ObjectIdentifier, critical: bool, value: Vec<u8>) -> Self {
        Extension {
            oid,
            critical,
            value,
        }
    }

    /// Parse one extension.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let oid = seq.read_oid()?;
        let critical = if !seq.is_empty() && seq.peek_tag()? == der::BOOLEAN {
            seq.read_boolean()?
        } else {
            false
        };
        let value = seq.read_octet_string()?.to_vec();
        seq.expect_end()?;
        Ok(Extension {
            oid,
            critical,
            value,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::oid(&self.oid);
        if self.critical {
            content.extend_from_slice(&der::boolean(true));
        }
        content.extend_from_slice(&der::octet_string(&self.value));
        der::sequence(&content)
    }

    /// Parse the extension value as a typed extension, when supported.
    pub fn parsed(&self) -> CryptoResult<ParsedExtension> {
        if self.oid.matches(oid::OID_BASIC_CONSTRAINTS) {
            return Ok(ParsedExtension::BasicConstraints(BasicConstraints::parse(
                &self.value,
            )?));
        }
        if self.oid.matches(oid::OID_KEY_USAGE) {
            return Ok(ParsedExtension::KeyUsage(KeyUsage::parse(&self.value)?));
        }
        if self.oid.matches(oid::OID_EXTENDED_KEY_USAGE) {
            return Ok(ParsedExtension::ExtendedKeyUsage(ExtendedKeyUsage::parse(
                &self.value,
            )?));
        }
        if self.oid.matches(oid::OID_SUBJECT_ALT_NAME) {
            return Ok(ParsedExtension::SubjectAltName(parse_general_names(
                &self.value,
            )?));
        }
        if self.oid.matches(oid::OID_ISSUER_ALT_NAME) {
            return Ok(ParsedExtension::IssuerAltName(parse_general_names(
                &self.value,
            )?));
        }
        if self.oid.matches(oid::OID_SUBJECT_KEY_IDENTIFIER) {
            let mut reader = Reader::new(&self.value);
            let key = reader.read_octet_string()?.to_vec();
            reader.expect_end()?;
            return Ok(ParsedExtension::SubjectKeyIdentifier(key));
        }
        if self.oid.matches(oid::OID_AUTHORITY_KEY_IDENTIFIER) {
            return Ok(ParsedExtension::AuthorityKeyIdentifier(
                AuthorityKeyIdentifier::parse(&self.value)?,
            ));
        }
        if self.oid.matches(oid::OID_CRL_DISTRIBUTION_POINTS) {
            return Ok(ParsedExtension::CrlDistributionPoints(
                CrlDistributionPoints::parse(&self.value)?,
            ));
        }
        if self.oid.matches(oid::OID_AUTHORITY_INFO_ACCESS) {
            return Ok(ParsedExtension::AuthorityInfoAccess(
                AuthorityInfoAccess::parse(&self.value)?,
            ));
        }
        if self.oid.matches(oid::OID_CERTIFICATE_POLICIES) {
            return Ok(ParsedExtension::CertificatePolicies(
                CertificatePolicies::parse(&self.value)?,
            ));
        }
        if self.oid.matches(oid::OID_NAME_CONSTRAINTS) {
            return Ok(ParsedExtension::NameConstraints(NameConstraints::parse(
                &self.value,
            )?));
        }
        if self.oid.matches(oid::OID_POLICY_CONSTRAINTS) {
            return Ok(ParsedExtension::PolicyConstraints(
                PolicyConstraints::parse(&self.value)?,
            ));
        }
        if self.oid.matches(oid::OID_INHIBIT_ANY_POLICY) {
            return Ok(ParsedExtension::InhibitAnyPolicy(InhibitAnyPolicy::parse(
                &self.value,
            )?));
        }
        if self.oid.matches(oid::OID_POLICY_MAPPINGS) {
            return Ok(ParsedExtension::PolicyMappings(PolicyMappings::parse(
                &self.value,
            )?));
        }
        if self.oid.matches(oid::OID_SUBJECT_INFO_ACCESS) {
            return Ok(ParsedExtension::SubjectInfoAccess(
                SubjectInfoAccess::parse(&self.value)?,
            ));
        }
        if self.oid.matches(oid::OID_CRL_NUMBER) {
            return Ok(ParsedExtension::CrlNumber(CrlNumber::parse(&self.value)?));
        }
        if self.oid.matches(oid::OID_DELTA_CRL_INDICATOR) {
            return Ok(ParsedExtension::DeltaCrlIndicator(
                DeltaCrlIndicator::parse(&self.value)?,
            ));
        }
        if self.oid.matches(oid::OID_ISSUING_DISTRIBUTION_POINT) {
            return Ok(ParsedExtension::IssuingDistributionPoint(
                IssuingDistributionPoint::parse(&self.value)?,
            ));
        }
        if self.oid.matches(oid::OID_REASON_CODE) {
            return Ok(ParsedExtension::CrlReason(CrlReason::parse(&self.value)?));
        }
        if self.oid.matches(oid::OID_INVALIDITY_DATE) {
            return Ok(ParsedExtension::InvalidityDate(InvalidityDate::parse(
                &self.value,
            )?));
        }
        if self.oid.matches(oid::OID_CERTIFICATE_ISSUER) {
            return Ok(ParsedExtension::CertificateIssuer(
                CertificateIssuer::parse(&self.value)?,
            ));
        }
        if self.oid.matches(oid::OID_FRESHEST_CRL) {
            return Ok(ParsedExtension::FreshestCrl(CrlDistributionPoints::parse(
                &self.value,
            )?));
        }
        if self.oid.matches(oid::OID_TLS_FEATURE) {
            return Ok(ParsedExtension::TlsFeature(TlsFeature::parse(&self.value)?));
        }
        if self.oid.matches(oid::OID_OCSP_NOCHECK) {
            return Ok(ParsedExtension::OcspNoCheck);
        }
        if self.oid.matches(oid::OID_NO_REV_AVAIL) {
            return Ok(ParsedExtension::NoRevAvail);
        }
        if self.oid.matches(oid::OID_SUBJECT_DIRECTORY_ATTRIBUTES) {
            return Ok(ParsedExtension::SubjectDirectoryAttributes(
                SubjectDirectoryAttributes::parse(&self.value)?,
            ));
        }
        Ok(ParsedExtension::Other)
    }
}

/// A typed extension value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedExtension {
    /// `basicConstraints`.
    BasicConstraints(BasicConstraints),
    /// `keyUsage`.
    KeyUsage(KeyUsage),
    /// `extKeyUsage`.
    ExtendedKeyUsage(ExtendedKeyUsage),
    /// `subjectAltName`.
    SubjectAltName(Vec<GeneralName>),
    /// `issuerAltName`.
    IssuerAltName(Vec<GeneralName>),
    /// `subjectKeyIdentifier`.
    SubjectKeyIdentifier(Vec<u8>),
    /// `authorityKeyIdentifier`.
    AuthorityKeyIdentifier(AuthorityKeyIdentifier),
    /// `crlDistributionPoints`.
    CrlDistributionPoints(CrlDistributionPoints),
    /// `authorityInfoAccess`.
    AuthorityInfoAccess(AuthorityInfoAccess),
    /// `certificatePolicies`.
    CertificatePolicies(CertificatePolicies),
    /// `nameConstraints`.
    NameConstraints(NameConstraints),
    /// `policyConstraints`.
    PolicyConstraints(PolicyConstraints),
    /// `inhibitAnyPolicy`.
    InhibitAnyPolicy(InhibitAnyPolicy),
    /// `policyMappings`.
    PolicyMappings(PolicyMappings),
    /// `subjectInfoAccess`.
    SubjectInfoAccess(SubjectInfoAccess),
    /// `cRLNumber`.
    CrlNumber(CrlNumber),
    /// `deltaCRLIndicator`.
    DeltaCrlIndicator(DeltaCrlIndicator),
    /// `issuingDistributionPoint`.
    IssuingDistributionPoint(IssuingDistributionPoint),
    /// `reasonCode` (CRL entries).
    CrlReason(CrlReason),
    /// `invalidityDate` (CRL entries).
    InvalidityDate(InvalidityDate),
    /// `certificateIssuer` (CRL entries).
    CertificateIssuer(CertificateIssuer),
    /// `freshestCRL`.
    FreshestCrl(CrlDistributionPoints),
    /// `tlsfeature`.
    TlsFeature(TlsFeature),
    /// `OCSP no-check`.
    OcspNoCheck,
    /// `noRevAvail`.
    NoRevAvail,
    /// `subjectDirectoryAttributes`.
    SubjectDirectoryAttributes(SubjectDirectoryAttributes),
    /// A recognized-but-untyped extension.
    Other,
}

/// `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
/// pathLenConstraint INTEGER OPTIONAL }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BasicConstraints {
    /// Whether the certificate is a CA certificate.
    pub ca: bool,
    /// Maximum path length below this certificate.
    pub path_len: Option<u32>,
}

impl BasicConstraints {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let ca = if !seq.is_empty() && seq.peek_tag()? == der::BOOLEAN {
            seq.read_boolean()?
        } else {
            false
        };
        let path_len = if !seq.is_empty() {
            let value = seq.read_integer_i64()?;
            Some(
                u32::try_from(value)
                    .map_err(|_| CryptoError::StrError("x509: invalid path length"))?,
            )
        } else {
            None
        };
        seq.expect_end()?;
        reader.expect_end()?;
        Ok(BasicConstraints { ca, path_len })
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if self.ca {
            content.extend_from_slice(&der::boolean(true));
        }
        if let Some(path_len) = self.path_len {
            content.extend_from_slice(&der::integer(&path_len.to_be_bytes()));
        }
        der::sequence(&content)
    }
}

/// `KeyUsage ::= BIT STRING` with the RFC 5280 bit order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyUsage {
    /// Bit 0: digitalSignature.
    pub digital_signature: bool,
    /// Bit 1: nonRepudiation / contentCommitment.
    pub content_commitment: bool,
    /// Bit 2: keyEncipherment.
    pub key_encipherment: bool,
    /// Bit 3: dataEncipherment.
    pub data_encipherment: bool,
    /// Bit 4: keyAgreement.
    pub key_agreement: bool,
    /// Bit 5: keyCertSign.
    pub key_cert_sign: bool,
    /// Bit 6: cRLSign.
    pub crl_sign: bool,
    /// Bit 7: encipherOnly.
    pub encipher_only: bool,
    /// Bit 8: decipherOnly.
    pub decipher_only: bool,
}

impl KeyUsage {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let (unused, data) = reader.read_bit_string()?;
        reader.expect_end()?;
        let bit_len = data
            .len()
            .checked_mul(8)
            .and_then(|len| len.checked_sub(unused as usize))
            .ok_or(CryptoError::StrError("x509: invalid key usage"))?;
        let get = |index: usize| -> bool {
            if index >= bit_len {
                return false;
            }
            let byte = data[index / 8];
            // BIT STRING bit 0 is the most significant bit of the first
            // octet.
            byte & (0x80 >> (index % 8)) != 0
        };
        Ok(KeyUsage {
            digital_signature: get(0),
            content_commitment: get(1),
            key_encipherment: get(2),
            data_encipherment: get(3),
            key_agreement: get(4),
            key_cert_sign: get(5),
            crl_sign: get(6),
            encipher_only: get(7),
            decipher_only: get(8),
        })
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let bits = [
            self.digital_signature,
            self.content_commitment,
            self.key_encipherment,
            self.data_encipherment,
            self.key_agreement,
            self.key_cert_sign,
            self.crl_sign,
            self.encipher_only,
            self.decipher_only,
        ];
        let last = bits
            .iter()
            .rposition(|&bit| bit)
            .map(|i| i + 1)
            .unwrap_or(0);
        let mut data = Vec::new();
        let mut byte = 0u8;
        for (i, &bit) in bits.iter().enumerate() {
            if i >= last {
                break;
            }
            if bit {
                byte |= 0x80 >> (i % 8);
            }
            if i % 8 == 7 {
                data.push(byte);
                byte = 0;
            }
        }
        if last % 8 != 0 {
            data.push(byte);
        }
        der::bit_string(((8 - (last % 8)) % 8) as u8, &data)
    }
}

/// `ExtKeyUsageSyntax ::= SEQUENCE OF KeyPurposeId`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExtendedKeyUsage {
    /// The key purpose OIDs.
    pub purposes: Vec<ObjectIdentifier>,
}

impl ExtendedKeyUsage {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut purposes = Vec::new();
        while !seq.is_empty() {
            purposes.push(seq.read_oid()?);
        }
        Ok(ExtendedKeyUsage { purposes })
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for purpose in &self.purposes {
            content.extend_from_slice(&der::oid(purpose));
        }
        der::sequence(&content)
    }

    /// Whether `arcs` is present, treating `anyExtendedKeyUsage` as a match.
    pub fn contains(&self, arcs: &[u64]) -> bool {
        self.purposes
            .iter()
            .any(|oid| oid.matches(arcs) || oid.matches(oid::OID_ANY_EXTENDED_KEY_USAGE))
    }
}

/// A `GeneralName`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneralName {
    /// `[0] otherName` (OID plus raw value).
    OtherName {
        /// The type-id OID.
        oid: ObjectIdentifier,
        /// Raw DER of the value.
        value: Vec<u8>,
    },
    /// `[1] rfc822Name`.
    Rfc822Name(String),
    /// `[2] dNSName`.
    DnsName(String),
    /// `[3] x400Address` (raw).
    X400Address(Vec<u8>),
    /// `[4] directoryName`.
    DirectoryName(Name),
    /// `[5] ediPartyName` (raw).
    EdiPartyName(Vec<u8>),
    /// `[6] uniformResourceIdentifier`.
    Uri(String),
    /// `[7] iPAddress`.
    IpAddress(Vec<u8>),
    /// `[8] registeredID`.
    RegisteredId(ObjectIdentifier),
    /// Any other tag.
    Unknown {
        /// Context-specific tag number.
        tag: u32,
        /// Raw contents.
        value: Vec<u8>,
    },
}

impl GeneralName {
    /// Parse one `GeneralName`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let (tag, content) = reader.read_tlv()?;
        if tag.class != der::Class::ContextSpecific {
            return Err(CryptoError::StrError("x509: invalid general name"));
        }
        let text = |content: &[u8]| -> CryptoResult<String> {
            core::str::from_utf8(content)
                .map(String::from)
                .map_err(|_| CryptoError::StrError("x509: invalid general name string"))
        };
        Ok(match (tag.number, tag.constructed) {
            (0, true) => {
                let mut inner = Reader::new(content);
                let mut seq = inner.read_sequence()?;
                let oid = seq.read_oid()?;
                let (_, value) = seq.read_tlv()?;
                GeneralName::OtherName {
                    oid,
                    value: value.to_vec(),
                }
            }
            (1, false) => GeneralName::Rfc822Name(text(content)?),
            (2, false) => GeneralName::DnsName(text(content)?),
            (3, true) => GeneralName::X400Address(content.to_vec()),
            (4, true) => {
                let mut inner = Reader::new(content);
                GeneralName::DirectoryName(Name::parse(&mut inner)?)
            }
            (5, true) => GeneralName::EdiPartyName(content.to_vec()),
            (6, false) => GeneralName::Uri(text(content)?),
            (7, false) => GeneralName::IpAddress(content.to_vec()),
            (8, false) => GeneralName::RegisteredId(ObjectIdentifier::from_der_content(content)?),
            (number, _) => GeneralName::Unknown {
                tag: number,
                value: content.to_vec(),
            },
        })
    }

    /// Encode this name.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            GeneralName::OtherName { oid, value } => {
                let mut content = der::oid(oid);
                content.extend_from_slice(value);
                der::implicit(0, true, &der::sequence(&content))
            }
            GeneralName::Rfc822Name(name) => der::implicit(1, false, name.as_bytes()),
            GeneralName::DnsName(name) => der::implicit(2, false, name.as_bytes()),
            GeneralName::X400Address(value) => der::implicit(3, true, value),
            GeneralName::DirectoryName(name) => der::implicit(4, true, &name.encode()),
            GeneralName::EdiPartyName(value) => der::implicit(5, true, value),
            GeneralName::Uri(uri) => der::implicit(6, false, uri.as_bytes()),
            GeneralName::IpAddress(value) => der::implicit(7, false, value),
            GeneralName::RegisteredId(oid) => der::implicit(8, false, &oid.to_der_content()),
            GeneralName::Unknown { tag, value } => der::implicit(*tag, false, value),
        }
    }

    /// A printable rendering (the string form for the common types).
    pub fn to_text(&self) -> Option<&str> {
        match self {
            GeneralName::Rfc822Name(name) | GeneralName::DnsName(name) | GeneralName::Uri(name) => {
                Some(name)
            }
            _ => None,
        }
    }
}

/// Parse `GeneralNames ::= SEQUENCE OF GeneralName`.
pub fn parse_general_names(der: &[u8]) -> CryptoResult<Vec<GeneralName>> {
    let mut reader = Reader::new(der);
    let mut seq = reader.read_sequence()?;
    let mut names = Vec::new();
    while !seq.is_empty() {
        names.push(GeneralName::parse(&mut seq)?);
    }
    Ok(names)
}

/// Encode `GeneralNames`.
pub fn encode_general_names(names: &[GeneralName]) -> Vec<u8> {
    let mut content = Vec::new();
    for name in names {
        content.extend_from_slice(&name.encode());
    }
    der::sequence(&content)
}

/// `AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OPTIONAL,
/// authorityCertIssuer [1] OPTIONAL, authorityCertSerialNumber [2]
/// OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthorityKeyIdentifier {
    /// The key identifier octets.
    pub key_identifier: Option<Vec<u8>>,
    /// Issuer names (raw `GeneralNames` content).
    pub authority_cert_issuer: Option<Vec<u8>>,
    /// Issuer serial number.
    pub authority_cert_serial: Option<Vec<u8>>,
}

impl AuthorityKeyIdentifier {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut out = AuthorityKeyIdentifier::default();
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            match tag.number {
                0 => out.key_identifier = Some(seq.read_implicit(0, false)?.to_vec()),
                1 => out.authority_cert_issuer = Some(seq.read_implicit(1, true)?.to_vec()),
                2 => {
                    let content = seq.read_implicit(2, false)?;
                    let mut inner = Reader::new(content);
                    out.authority_cert_serial = Some(inner.read_integer()?.to_vec());
                }
                _ => return Err(CryptoError::StrError("x509: invalid authority key id")),
            }
        }
        Ok(out)
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if let Some(key_id) = &self.key_identifier {
            content.extend_from_slice(&der::implicit(0, false, key_id));
        }
        if let Some(issuer) = &self.authority_cert_issuer {
            content.extend_from_slice(&der::implicit(1, true, issuer));
        }
        if let Some(serial) = &self.authority_cert_serial {
            content.extend_from_slice(&der::implicit(2, false, &der::integer(serial)));
        }
        der::sequence(&content)
    }
}

/// One `DistributionPoint` of a `CRLDistributionPoints` or `freshestCRL`
/// extension.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DistributionPoint {
    /// The distribution point name, when present.
    pub distribution_point: Option<DistributionPointName>,
    /// `reasons` as RFC 5280 `ReasonFlags` bits (bit 1 = `keyCompromise`, bit
    /// 9 = `removeFromCRL`); `None` means all reasons.
    pub reasons: Option<u16>,
    /// `cRLIssuer` general names, when present.
    pub crl_issuer: Vec<GeneralName>,
}

impl DistributionPoint {
    /// A distribution point that only carries `fullName` URIs.
    pub fn from_uris(uris: &[String]) -> Self {
        DistributionPoint {
            distribution_point: Some(DistributionPointName {
                full_name: Some(uris.iter().cloned().map(GeneralName::Uri).collect()),
                relative_name: None,
            }),
            reasons: None,
            crl_issuer: Vec::new(),
        }
    }

    /// The `fullName` URIs of this distribution point.
    pub fn uris(&self) -> Vec<&str> {
        match &self.distribution_point {
            Some(DistributionPointName {
                full_name: Some(names),
                ..
            }) => names.iter().filter_map(GeneralName::to_text).collect(),
            _ => Vec::new(),
        }
    }

    /// Whether the given RFC 5280 reason bit is set (or no reasons are
    /// restricted).
    pub fn has_reason(&self, bit: u16) -> bool {
        self.reasons.is_none_or(|reasons| reasons & (1 << bit) != 0)
    }
}

/// `CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint`.
///
/// `freshestCRL` reuses the same syntax.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CrlDistributionPoints {
    /// The distribution points.
    pub points: Vec<DistributionPoint>,
}

impl CrlDistributionPoints {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut points = Vec::new();
        while !seq.is_empty() {
            // DistributionPoint ::= SEQUENCE { distributionPoint [0] OPTIONAL,
            // reasons [1] OPTIONAL, cRLIssuer [2] OPTIONAL }.
            let mut point = seq.read_sequence()?;
            let mut parsed = DistributionPoint::default();
            while !point.is_empty() {
                let tag = point.peek_tag()?;
                match (tag.class, tag.number) {
                    (der::Class::ContextSpecific, 0) => {
                        let mut inner = point.read_implicit_constructed(0)?;
                        parsed.distribution_point =
                            Some(parse_distribution_point_name(&mut inner)?);
                    }
                    (der::Class::ContextSpecific, 1) => {
                        let content = point.read_implicit(1, false)?;
                        let (unused, data) = content
                            .split_first()
                            .ok_or(CryptoError::StrError("x509: invalid reason flags"))?;
                        parsed.reasons = Some(bit_string_bits(*unused, data));
                    }
                    (der::Class::ContextSpecific, 2) => {
                        let mut inner = point.read_implicit_constructed(2)?;
                        while !inner.is_empty() {
                            parsed.crl_issuer.push(GeneralName::parse(&mut inner)?);
                        }
                    }
                    _ => return Err(CryptoError::StrError("x509: invalid crlDistributionPoints")),
                }
            }
            points.push(parsed);
        }
        Ok(CrlDistributionPoints { points })
    }

    /// The `fullName` URIs of every distribution point.
    pub fn uris(&self) -> Vec<&str> {
        self.points
            .iter()
            .flat_map(DistributionPoint::uris)
            .collect()
    }

    /// Build the extension contents from URIs only.
    pub fn from_uris(uris: &[String]) -> Self {
        CrlDistributionPoints {
            points: alloc::vec![DistributionPoint::from_uris(uris)],
        }
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for point in &self.points {
            let mut point_content = Vec::new();
            if let Some(name) = &point.distribution_point {
                let mut name_content = Vec::new();
                if let Some(names) = &name.full_name {
                    let mut names_content = Vec::new();
                    for name in names {
                        names_content.extend_from_slice(&name.encode());
                    }
                    name_content.extend_from_slice(&der::implicit(0, true, &names_content));
                }
                if let Some(relative) = &name.relative_name {
                    let mut rdn_content = Vec::new();
                    for attribute in &relative.attributes {
                        rdn_content.extend_from_slice(&attribute.encode());
                    }
                    name_content.extend_from_slice(&der::implicit(1, true, &rdn_content));
                }
                point_content.extend_from_slice(&der::implicit(0, true, &name_content));
            }
            if let Some(bits) = point.reasons {
                point_content.extend_from_slice(&der::implicit(1, false, &bit_string_bytes(bits)));
            }
            if !point.crl_issuer.is_empty() {
                let mut names_content = Vec::new();
                for name in &point.crl_issuer {
                    names_content.extend_from_slice(&name.encode());
                }
                point_content.extend_from_slice(&der::implicit(2, true, &names_content));
            }
            content.extend_from_slice(&der::sequence(&point_content));
        }
        der::sequence(&content)
    }
}

/// `AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthorityInfoAccess {
    /// The access descriptions, in order.
    pub descriptions: Vec<AccessDescription>,
}

impl AuthorityInfoAccess {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut descriptions = Vec::new();
        while !seq.is_empty() {
            descriptions.push(AccessDescription::parse(&mut seq)?);
        }
        Ok(AuthorityInfoAccess { descriptions })
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for description in &self.descriptions {
            content.extend_from_slice(&description.encode());
        }
        der::sequence(&content)
    }

    /// Every location for `method`.
    pub fn locations(&self, method: &[u64]) -> Vec<&GeneralName> {
        self.descriptions
            .iter()
            .filter(|description| description.method.matches(method))
            .map(|description| &description.location)
            .collect()
    }

    /// The `ocsp` responder URIs.
    pub fn ocsp_uris(&self) -> Vec<&str> {
        self.uris_for(oid::OID_AD_OCSP)
    }

    /// The `caIssuers` URIs.
    pub fn ca_issuers_uris(&self) -> Vec<&str> {
        self.uris_for(oid::OID_AD_CA_ISSUERS)
    }

    fn uris_for(&self, method: &[u64]) -> Vec<&str> {
        self.locations(method)
            .into_iter()
            .filter_map(GeneralName::to_text)
            .collect()
    }
}

/// One `PolicyInformation` of a `certificatePolicies` extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyInformation {
    /// The policy OID.
    pub policy_identifier: ObjectIdentifier,
    /// Optional policy qualifiers.
    pub qualifiers: Vec<PolicyQualifier>,
}

/// A policy qualifier of a `PolicyInformation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyQualifier {
    /// `id-qt-cps`: a certification practice statement URI.
    CpsUri(String),
    /// `id-qt-unotice`: a user notice.
    UserNotice(UserNotice),
    /// Any other qualifier (raw value preserved).
    Other {
        /// The qualifier OID.
        oid: ObjectIdentifier,
        /// The raw qualifier value.
        value: Vec<u8>,
    },
}

/// A `DisplayText` value (`IA5String|VisibleString|BMPString|UTF8String`).
///
/// The original string tag is preserved so re-encoding a parsed value is
/// byte-exact, matching [`AttributeTypeAndValue`](super::name::AttributeTypeAndValue).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayText {
    /// The string type's universal tag.
    pub tag: der::Tag,
    /// Raw string content octets.
    pub value: Vec<u8>,
}

impl Default for DisplayText {
    fn default() -> Self {
        DisplayText {
            tag: der::UTF8_STRING,
            value: Vec::new(),
        }
    }
}

impl DisplayText {
    /// A UTF8String-valued text.
    pub fn from_utf8(text: &str) -> Self {
        DisplayText {
            tag: der::UTF8_STRING,
            value: text.as_bytes().to_vec(),
        }
    }

    /// Parse one `DisplayText`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let (tag, content) = reader.read_tlv()?;
        if tag.class != der::Class::Universal || tag.constructed {
            return Err(CryptoError::StrError("x509: invalid display text"));
        }
        Ok(DisplayText {
            tag,
            value: content.to_vec(),
        })
    }

    /// Encode the `DisplayText`.
    pub fn encode(&self) -> Vec<u8> {
        der::string_with_tag(self.tag, &self.value)
    }

    /// The text decoded according to its string type.
    pub fn text(&self) -> CryptoResult<String> {
        der::decode_string(self.tag, &self.value)
    }
}

/// `UserNotice ::= SEQUENCE { noticeRef NoticeReference OPTIONAL,
/// explicitText DisplayText OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserNotice {
    /// The notice reference, when present.
    pub notice_ref: Option<NoticeReference>,
    /// The explicit text, when present.
    pub explicit_text: Option<DisplayText>,
}

/// `NoticeReference ::= SEQUENCE { organization DisplayText,
/// noticeNumbers SEQUENCE OF INTEGER }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NoticeReference {
    /// The organization maintaining the notice file.
    pub organization: DisplayText,
    /// The notice numbers.
    pub notice_numbers: Vec<u64>,
}

impl PolicyQualifier {
    /// Parse one `PolicyQualifierInfo`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let oid = seq.read_oid()?;
        let tag = seq.peek_tag()?;
        if oid.matches(oid::OID_QT_UNOTICE) && tag.number == der::SEQUENCE.number && tag.constructed
        {
            return Ok(PolicyQualifier::UserNotice(UserNotice::parse(&mut seq)?));
        }
        let (tag, content) = seq.read_tlv()?;
        if tag.class != der::Class::Universal {
            return Err(CryptoError::StrError("x509: invalid policy qualifier"));
        }
        if oid.matches(oid::OID_QT_CPS) && tag.number == der::IA5_STRING.number {
            let text = core::str::from_utf8(content)
                .map_err(|_| CryptoError::StrError("x509: invalid CPS URI"))?;
            return Ok(PolicyQualifier::CpsUri(String::from(text)));
        }
        Ok(PolicyQualifier::Other {
            oid,
            value: der::tlv(tag, content),
        })
    }

    /// Encode the qualifier.
    pub fn encode(&self) -> Vec<u8> {
        let (qualifier_oid, value) = match self {
            PolicyQualifier::CpsUri(uri) => (oid::OID_QT_CPS, der::ia5_string(uri)),
            PolicyQualifier::UserNotice(notice) => (oid::OID_QT_UNOTICE, notice.encode()),
            PolicyQualifier::Other { oid, value } => {
                let mut content = der::oid(oid);
                content.extend_from_slice(value);
                return der::sequence(&content);
            }
        };
        let mut content = der::oid(&ObjectIdentifier::new(qualifier_oid).expect("static oid"));
        content.extend_from_slice(&value);
        der::sequence(&content)
    }
}

impl UserNotice {
    /// Parse a `UserNotice`.
    fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let mut notice = UserNotice::default();
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            if tag.number == der::SEQUENCE.number && tag.constructed {
                notice.notice_ref = Some(NoticeReference::parse(&mut seq)?);
            } else {
                notice.explicit_text = Some(DisplayText::parse(&mut seq)?);
            }
        }
        Ok(notice)
    }

    /// Encode the `UserNotice`.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if let Some(notice_ref) = &self.notice_ref {
            let mut reference = notice_ref.organization.encode();
            let mut numbers = Vec::new();
            for number in &notice_ref.notice_numbers {
                numbers.extend_from_slice(&der::integer_i64(*number as i64));
            }
            reference.extend_from_slice(&der::sequence(&numbers));
            content.extend_from_slice(&der::sequence(&reference));
        }
        if let Some(text) = &self.explicit_text {
            content.extend_from_slice(&text.encode());
        }
        der::sequence(&content)
    }
}

impl NoticeReference {
    /// Parse a `NoticeReference`.
    fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let organization = DisplayText::parse(&mut seq)?;
        let mut numbers = seq.read_sequence()?;
        let mut notice_numbers = Vec::new();
        while !numbers.is_empty() {
            notice_numbers.push(
                u64::try_from(numbers.read_integer_i64()?)
                    .map_err(|_| CryptoError::StrError("x509: invalid notice number"))?,
            );
        }
        seq.expect_end()?;
        Ok(NoticeReference {
            organization,
            notice_numbers,
        })
    }
}

/// `CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertificatePolicies {
    /// The policy information entries.
    pub policies: Vec<PolicyInformation>,
}

impl CertificatePolicies {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut policies = Vec::new();
        while !seq.is_empty() {
            // PolicyInformation ::= SEQUENCE { policyIdentifier OID,
            // policyQualifiers SEQUENCE OF PolicyQualifierInfo OPTIONAL }.
            let mut info = seq.read_sequence()?;
            let policy_identifier = info.read_oid()?;
            let mut qualifiers = Vec::new();
            if !info.is_empty() {
                let mut list = info.read_sequence()?;
                while !list.is_empty() {
                    qualifiers.push(PolicyQualifier::parse(&mut list)?);
                }
            }
            info.expect_end()?;
            policies.push(PolicyInformation {
                policy_identifier,
                qualifiers,
            });
        }
        Ok(CertificatePolicies { policies })
    }

    /// The policy OIDs in order.
    pub fn policy_identifiers(&self) -> Vec<ObjectIdentifier> {
        self.policies
            .iter()
            .map(|policy| policy.policy_identifier.clone())
            .collect()
    }

    /// Whether `arcs` is one of the policy OIDs.
    pub fn contains(&self, arcs: &[u64]) -> bool {
        self.policies
            .iter()
            .any(|policy| policy.policy_identifier.matches(arcs))
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for policy in &self.policies {
            let mut policy_content = der::oid(&policy.policy_identifier);
            if !policy.qualifiers.is_empty() {
                let mut qualifiers = Vec::new();
                for qualifier in &policy.qualifiers {
                    qualifiers.extend_from_slice(&qualifier.encode());
                }
                policy_content.extend_from_slice(&der::sequence(&qualifiers));
            }
            content.extend_from_slice(&der::sequence(&policy_content));
        }
        der::sequence(&content)
    }
}

/// Build a `certificatePolicies` extension.
pub fn certificate_policies(policies: &[PolicyInformation]) -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_CERTIFICATE_POLICIES).expect("static oid"),
        false,
        CertificatePolicies {
            policies: policies.to_vec(),
        }
        .encode(),
    )
}

/// Build a `subjectAltName` extension from DNS names and IP addresses.
pub fn subject_alt_name(dns_names: &[String], ip_addresses: &[[u8; 4]]) -> Extension {
    let mut names: Vec<GeneralName> = dns_names
        .iter()
        .cloned()
        .map(GeneralName::DnsName)
        .collect();
    for ip in ip_addresses {
        names.push(GeneralName::IpAddress(ip.to_vec()));
    }
    Extension::new(
        ObjectIdentifier::new(oid::OID_SUBJECT_ALT_NAME).expect("static oid"),
        false,
        encode_general_names(&names),
    )
}

/// Build a `basicConstraints` extension.
pub fn basic_constraints(ca: bool, path_len: Option<u32>) -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_BASIC_CONSTRAINTS).expect("static oid"),
        true,
        BasicConstraints { ca, path_len }.encode(),
    )
}

/// Build a `keyUsage` extension.
pub fn key_usage(usage: KeyUsage) -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_KEY_USAGE).expect("static oid"),
        true,
        usage.encode(),
    )
}

/// Build an `extKeyUsage` extension.
pub fn extended_key_usage(purposes: &[&[u64]]) -> Extension {
    let purposes = purposes
        .iter()
        .map(|arcs| ObjectIdentifier::new(arcs).expect("static oid"))
        .collect();
    Extension::new(
        ObjectIdentifier::new(oid::OID_EXTENDED_KEY_USAGE).expect("static oid"),
        false,
        ExtendedKeyUsage { purposes }.encode(),
    )
}

/// Build a `subjectKeyIdentifier` extension.
pub fn subject_key_identifier(key_id: &[u8]) -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_SUBJECT_KEY_IDENTIFIER).expect("static oid"),
        false,
        der::octet_string(key_id),
    )
}

/// Build an `authorityKeyIdentifier` extension from a key identifier.
pub fn authority_key_identifier(key_id: &[u8]) -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_AUTHORITY_KEY_IDENTIFIER).expect("static oid"),
        false,
        AuthorityKeyIdentifier {
            key_identifier: Some(key_id.to_vec()),
            ..Default::default()
        }
        .encode(),
    )
}

// ---------------------------------------------------------------------------
// Access descriptions and subjectInfoAccess
// ---------------------------------------------------------------------------

/// One `AccessDescription`: `SEQUENCE { accessMethod OID, accessLocation GeneralName }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDescription {
    /// Access method OID.
    pub method: ObjectIdentifier,
    /// The location of the data.
    pub location: GeneralName,
}

impl AccessDescription {
    /// Parse one `AccessDescription`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let method = seq.read_oid()?;
        let location = GeneralName::parse(&mut seq)?;
        seq.expect_end()?;
        Ok(AccessDescription { method, location })
    }

    /// Encode one `AccessDescription`.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::oid(&self.method);
        content.extend_from_slice(&self.location.encode());
        der::sequence(&content)
    }
}

/// `SubjectInfoAccessSyntax ::= SEQUENCE OF AccessDescription` (RFC 5280
/// 4.2.2.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SubjectInfoAccess {
    /// The access descriptions.
    pub descriptions: Vec<AccessDescription>,
}

impl SubjectInfoAccess {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut descriptions = Vec::new();
        while !seq.is_empty() {
            descriptions.push(AccessDescription::parse(&mut seq)?);
        }
        Ok(SubjectInfoAccess { descriptions })
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for description in &self.descriptions {
            content.extend_from_slice(&description.encode());
        }
        der::sequence(&content)
    }

    /// Every access location for `method`.
    pub fn locations(&self, method: &[u64]) -> Vec<&GeneralName> {
        self.descriptions
            .iter()
            .filter(|description| description.method.matches(method))
            .map(|description| &description.location)
            .collect()
    }

    /// `caRepository` URIs.
    pub fn ca_repository(&self) -> Vec<&str> {
        self.locations(oid::OID_AD_CA_REPOSITORY)
            .into_iter()
            .filter_map(GeneralName::to_text)
            .collect()
    }

    /// `timeStamping` URIs.
    pub fn time_stamping(&self) -> Vec<&str> {
        self.locations(oid::OID_AD_TIME_STAMPING)
            .into_iter()
            .filter_map(GeneralName::to_text)
            .collect()
    }
}

/// `SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF AttributeSet`,
/// with `AttributeSet ::= SET SIZE (1..MAX) OF Attribute` (RFC 5280 4.2.1.8).
///
/// Each entry keeps its `SET OF` grouping; values are generic `Attribute`s
/// because the types are application-defined.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SubjectDirectoryAttributes {
    /// The attribute sets, in order.
    pub attributes: Vec<Vec<Attribute>>,
}

impl SubjectDirectoryAttributes {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut attributes = Vec::new();
        while !seq.is_empty() {
            attributes.push(super::attribute::parse_attributes(&mut seq)?);
        }
        Ok(SubjectDirectoryAttributes { attributes })
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for set in &self.attributes {
            content.extend_from_slice(&super::attribute::encode_attributes(set));
        }
        der::sequence(&content)
    }
}

// ---------------------------------------------------------------------------
// Name constraints
// ---------------------------------------------------------------------------

/// `GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0] BaseDistance
/// DEFAULT 0, maximum [1] BaseDistance OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralSubtree {
    /// The constraint's base name.
    pub base: GeneralName,
    /// Minimum distance (always 0 in RFC 5280 deployments).
    pub minimum: u32,
    /// Maximum distance, when present.
    pub maximum: Option<u32>,
}

impl GeneralSubtree {
    /// Whether the subtree uses only the RFC 5280 mandatory zero minimum and
    /// no maximum.
    pub fn is_supported(&self) -> bool {
        self.minimum == 0 && self.maximum.is_none()
    }

    /// Parse one `GeneralSubtree`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let base = GeneralName::parse(&mut seq)?;
        let mut minimum = 0;
        let mut maximum = None;
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            match (tag.class, tag.number) {
                (der::Class::ContextSpecific, 0) => {
                    minimum = implicit_u32(&mut seq, 0)?;
                }
                (der::Class::ContextSpecific, 1) => {
                    maximum = Some(implicit_u32(&mut seq, 1)?);
                }
                _ => return Err(CryptoError::StrError("x509: invalid general subtree")),
            }
        }
        Ok(GeneralSubtree {
            base,
            minimum,
            maximum,
        })
    }

    /// Encode one `GeneralSubtree`.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.base.encode();
        if self.minimum != 0 {
            content.extend_from_slice(&der::implicit(0, false, &integer_content(self.minimum)));
        }
        if let Some(maximum) = self.maximum {
            content.extend_from_slice(&der::implicit(1, false, &integer_content(maximum)));
        }
        der::sequence(&content)
    }

    /// Whether `name` falls inside this subtree (RFC 5280 4.2.1.10 matching
    /// rules for DNS, email, IP, URI and directory names).
    pub fn matches(&self, name: &GeneralName) -> bool {
        match (&self.base, name) {
            (GeneralName::DnsName(constraint), GeneralName::DnsName(name)) => {
                dns_matches(constraint, name)
            }
            (GeneralName::Rfc822Name(constraint), GeneralName::Rfc822Name(name)) => {
                email_matches(constraint, name)
            }
            (GeneralName::IpAddress(constraint), GeneralName::IpAddress(name)) => {
                ip_matches(constraint, name)
            }
            (GeneralName::Uri(constraint), GeneralName::Uri(name)) => uri_matches(constraint, name),
            (GeneralName::DirectoryName(constraint), GeneralName::DirectoryName(name)) => {
                directory_matches(constraint, name)
            }
            (GeneralName::RegisteredId(constraint), GeneralName::RegisteredId(name)) => {
                constraint == name
            }
            (
                GeneralName::OtherName {
                    oid: constraint_oid,
                    value: constraint_value,
                },
                GeneralName::OtherName { oid, value },
            ) => constraint_oid == oid && constraint_value == value,
            _ => false,
        }
    }

    fn same_type(&self, name: &GeneralName) -> bool {
        general_name_tag(&self.base) == general_name_tag(name)
    }
}

/// The context tag of a `GeneralName` (the matching "type").
fn general_name_tag(name: &GeneralName) -> u32 {
    match name {
        GeneralName::OtherName { .. } => 0,
        GeneralName::Rfc822Name(_) => 1,
        GeneralName::DnsName(_) => 2,
        GeneralName::X400Address(_) => 3,
        GeneralName::DirectoryName(_) => 4,
        GeneralName::EdiPartyName(_) => 5,
        GeneralName::Uri(_) => 6,
        GeneralName::IpAddress(_) => 7,
        GeneralName::RegisteredId(_) => 8,
        GeneralName::Unknown { tag, .. } => *tag,
    }
}

fn dns_matches(constraint: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let constraint = constraint.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();
    match constraint.strip_prefix('.') {
        // A leading dot constrains subdomains only.
        Some(suffix) => name.len() > suffix.len() + 1 && name.ends_with(&constraint),
        None => {
            name == constraint
                || (name.len() > constraint.len()
                    && name.ends_with(&constraint)
                    && name.as_bytes()[name.len() - constraint.len() - 1] == b'.')
        }
    }
}

fn email_matches(constraint: &str, name: &str) -> bool {
    let constraint = constraint.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();
    if constraint.contains('@') {
        return name == constraint;
    }
    let Some((_, host)) = name.rsplit_once('@') else {
        return false;
    };
    match constraint.strip_prefix('.') {
        Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(&constraint),
        None => host == constraint,
    }
}

fn ip_matches(constraint: &[u8], name: &[u8]) -> bool {
    if constraint.len() != name.len() * 2 || name.is_empty() {
        return false;
    }
    let (address, mask) = constraint.split_at(name.len());
    address
        .iter()
        .zip(name.iter())
        .zip(mask.iter())
        .all(|((address, name), mask)| address & mask == name & mask)
}

fn uri_host(uri: &str) -> Option<&str> {
    let rest = uri.split_once("://").map(|(_, rest)| rest)?;
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit('@').next().unwrap_or(host);
    if let Some(bracketed) = host.strip_prefix('[') {
        return bracketed.split(']').next();
    }
    Some(host.split(':').next().unwrap_or(host))
}

fn uri_matches(constraint: &str, name: &str) -> bool {
    let Some(host) = uri_host(name) else {
        return false;
    };
    dns_matches(constraint, host)
}

fn directory_matches(constraint: &Name, name: &Name) -> bool {
    if constraint.rdns.len() > name.rdns.len() {
        return false;
    }
    constraint
        .rdns
        .iter()
        .zip(name.rdns.iter())
        .all(|(constraint, name)| constraint == name)
}

/// `NameConstraints ::= SEQUENCE { permittedSubtrees [0] OPTIONAL, excludedSubtrees [1] OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NameConstraints {
    /// Permitted subtrees.
    pub permitted: Option<Vec<GeneralSubtree>>,
    /// Excluded subtrees.
    pub excluded: Option<Vec<GeneralSubtree>>,
}

impl NameConstraints {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut constraints = NameConstraints::default();
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            let mut subtrees = Vec::new();
            match (tag.class, tag.number) {
                (der::Class::ContextSpecific, 0) => {
                    let mut inner = seq.read_implicit_constructed(0)?;
                    while !inner.is_empty() {
                        subtrees.push(GeneralSubtree::parse(&mut inner)?);
                    }
                    constraints.permitted = Some(subtrees);
                }
                (der::Class::ContextSpecific, 1) => {
                    let mut inner = seq.read_implicit_constructed(1)?;
                    while !inner.is_empty() {
                        subtrees.push(GeneralSubtree::parse(&mut inner)?);
                    }
                    constraints.excluded = Some(subtrees);
                }
                _ => return Err(CryptoError::StrError("x509: invalid name constraints")),
            }
        }
        Ok(constraints)
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if let Some(permitted) = &self.permitted {
            let mut inner = Vec::new();
            for subtree in permitted {
                inner.extend_from_slice(&subtree.encode());
            }
            content.extend_from_slice(&der::implicit(0, true, &inner));
        }
        if let Some(excluded) = &self.excluded {
            let mut inner = Vec::new();
            for subtree in excluded {
                inner.extend_from_slice(&subtree.encode());
            }
            content.extend_from_slice(&der::implicit(1, true, &inner));
        }
        der::sequence(&content)
    }

    /// Whether `name` is permitted by these constraints.
    ///
    /// A name of a type with permitted subtrees must match at least one of
    /// them; excluded subtrees reject on any match. Names of a type that is
    /// not constrained are permitted.
    pub fn permits(&self, name: &GeneralName) -> bool {
        if let Some(excluded) = &self.excluded {
            if excluded
                .iter()
                .any(|subtree| subtree.same_type(name) && subtree.matches(name))
            {
                return false;
            }
        }
        if let Some(permitted) = &self.permitted {
            let mut any_of_type = false;
            let mut matches = false;
            for subtree in permitted {
                if !subtree.same_type(name) {
                    continue;
                }
                any_of_type = true;
                if subtree.matches(name) {
                    matches = true;
                    break;
                }
            }
            if any_of_type && !matches {
                return false;
            }
        }
        true
    }

    /// Whether every subtree uses only the supported zero minimum and no
    /// maximum.
    pub fn is_supported(&self) -> bool {
        let supported = |subtrees: &Option<Vec<GeneralSubtree>>| {
            subtrees
                .as_ref()
                .is_none_or(|subtrees| subtrees.iter().all(GeneralSubtree::is_supported))
        };
        supported(&self.permitted) && supported(&self.excluded)
    }
}

// ---------------------------------------------------------------------------
// Policy constraints, inhibitAnyPolicy and policyMappings
// ---------------------------------------------------------------------------

fn integer_content(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&byte| byte != 0).unwrap_or(3);
    bytes[start..].to_vec()
}

/// `PolicyConstraints ::= SEQUENCE { requireExplicitPolicy [0] OPTIONAL,
/// inhibitPolicyMapping [1] OPTIONAL }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolicyConstraints {
    /// `requireExplicitPolicy` skipCerts.
    pub require_explicit_policy: Option<u32>,
    /// `inhibitPolicyMapping` skipCerts.
    pub inhibit_policy_mapping: Option<u32>,
}

impl PolicyConstraints {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut constraints = PolicyConstraints::default();
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            match (tag.class, tag.number) {
                (der::Class::ContextSpecific, 0) => {
                    constraints.require_explicit_policy = Some(implicit_u32(&mut seq, 0)?);
                }
                (der::Class::ContextSpecific, 1) => {
                    constraints.inhibit_policy_mapping = Some(implicit_u32(&mut seq, 1)?);
                }
                _ => return Err(CryptoError::StrError("x509: invalid policy constraint")),
            }
        }
        Ok(constraints)
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if let Some(value) = self.require_explicit_policy {
            content.extend_from_slice(&der::implicit(0, false, &integer_content(value)));
        }
        if let Some(value) = self.inhibit_policy_mapping {
            content.extend_from_slice(&der::implicit(1, false, &integer_content(value)));
        }
        der::sequence(&content)
    }
}

/// `InhibitAnyPolicy ::= SkipCerts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InhibitAnyPolicy {
    /// Number of certificates that may follow before anyPolicy stops being
    /// acceptable.
    pub skip_certs: u32,
}

impl InhibitAnyPolicy {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let value = reader.read_integer_i64()?;
        reader.expect_end()?;
        Ok(InhibitAnyPolicy {
            skip_certs: u32::try_from(value)
                .map_err(|_| CryptoError::StrError("x509: invalid inhibitAnyPolicy"))?,
        })
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        der::integer(&integer_content(self.skip_certs))
    }
}

/// One `PolicyMapping`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyMapping {
    /// `issuerDomainPolicy`.
    pub issuer_domain_policy: ObjectIdentifier,
    /// `subjectDomainPolicy`.
    pub subject_domain_policy: ObjectIdentifier,
}

/// `PolicyMappings ::= SEQUENCE OF SEQUENCE { issuerDomainPolicy, subjectDomainPolicy }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyMappings {
    /// The mappings.
    pub mappings: Vec<PolicyMapping>,
}

impl PolicyMappings {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut mappings = Vec::new();
        while !seq.is_empty() {
            let mut mapping = seq.read_sequence()?;
            mappings.push(PolicyMapping {
                issuer_domain_policy: mapping.read_oid()?,
                subject_domain_policy: mapping.read_oid()?,
            });
        }
        Ok(PolicyMappings { mappings })
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for mapping in &self.mappings {
            content.extend_from_slice(&der::sequence(
                &[
                    der::oid(&mapping.issuer_domain_policy),
                    der::oid(&mapping.subject_domain_policy),
                ]
                .concat(),
            ));
        }
        der::sequence(&content)
    }
}

// ---------------------------------------------------------------------------
// CRL extensions
// ---------------------------------------------------------------------------

/// `CRLNumber ::= INTEGER`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CrlNumber {
    /// The number as a big-endian magnitude.
    pub number: Vec<u8>,
}

impl CrlNumber {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let number = reader.read_integer()?.to_vec();
        reader.expect_end()?;
        Ok(CrlNumber { number })
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        der::integer(&self.number)
    }

    /// The number as a `u64`, when it fits.
    pub fn to_u64(&self) -> Option<u64> {
        if self.number.len() > 8 {
            return None;
        }
        Some(
            self.number
                .iter()
                .fold(0u64, |value, &byte| (value << 8) | byte as u64),
        )
    }
}

/// `BaseCRLNumber ::= CRLNumber` (the `deltaCRLIndicator` extension).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeltaCrlIndicator {
    /// The base CRL number.
    pub base_crl_number: Vec<u8>,
}

impl DeltaCrlIndicator {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        Ok(DeltaCrlIndicator {
            base_crl_number: CrlNumber::parse(der)?.number,
        })
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        CrlNumber {
            number: self.base_crl_number.clone(),
        }
        .encode()
    }
}

/// The RFC 5280 `CRLReason` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlReason {
    /// `unspecified` (0).
    Unspecified,
    /// `keyCompromise` (1).
    KeyCompromise,
    /// `cACompromise` (2).
    CaCompromise,
    /// `affiliationChanged` (3).
    AffiliationChanged,
    /// `superseded` (4).
    Superseded,
    /// `cessationOfOperation` (5).
    CessationOfOperation,
    /// `certificateHold` (6).
    CertificateHold,
    /// `removeFromCRL` (8).
    RemoveFromCrl,
    /// `privilegeWithdrawn` (9).
    PrivilegeWithdrawn,
    /// `aACompromise` (10).
    AaCompromise,
}

impl CrlReason {
    /// Decode an ENUMERATED value.
    pub fn from_u8(value: u8) -> CryptoResult<Self> {
        Ok(match value {
            0 => CrlReason::Unspecified,
            1 => CrlReason::KeyCompromise,
            2 => CrlReason::CaCompromise,
            3 => CrlReason::AffiliationChanged,
            4 => CrlReason::Superseded,
            5 => CrlReason::CessationOfOperation,
            6 => CrlReason::CertificateHold,
            8 => CrlReason::RemoveFromCrl,
            9 => CrlReason::PrivilegeWithdrawn,
            10 => CrlReason::AaCompromise,
            _ => return Err(CryptoError::StrError("x509: unknown CRL reason value")),
        })
    }

    /// The wire value.
    pub fn as_u8(self) -> u8 {
        match self {
            CrlReason::Unspecified => 0,
            CrlReason::KeyCompromise => 1,
            CrlReason::CaCompromise => 2,
            CrlReason::AffiliationChanged => 3,
            CrlReason::Superseded => 4,
            CrlReason::CessationOfOperation => 5,
            CrlReason::CertificateHold => 6,
            CrlReason::RemoveFromCrl => 8,
            CrlReason::PrivilegeWithdrawn => 9,
            CrlReason::AaCompromise => 10,
        }
    }

    /// The RFC 5280 name.
    pub fn name(self) -> &'static str {
        match self {
            CrlReason::Unspecified => "unspecified",
            CrlReason::KeyCompromise => "keyCompromise",
            CrlReason::CaCompromise => "cACompromise",
            CrlReason::AffiliationChanged => "affiliationChanged",
            CrlReason::Superseded => "superseded",
            CrlReason::CessationOfOperation => "cessationOfOperation",
            CrlReason::CertificateHold => "certificateHold",
            CrlReason::RemoveFromCrl => "removeFromCRL",
            CrlReason::PrivilegeWithdrawn => "privilegeWithdrawn",
            CrlReason::AaCompromise => "aACompromise",
        }
    }

    /// Parse a `reasonCode` value: the CRL entry extension uses a plain
    /// `ENUMERATED`, OCSP's `RevokedInfo` wraps the same value in `[0]`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let (tag, content) = reader.read_tlv()?;
        let enumerated = tag.class == der::Class::Universal && tag.number == 0x0a;
        let context = tag.class == der::Class::ContextSpecific && tag.number == 0;
        if !(enumerated || context) || tag.constructed || content.len() != 1 {
            return Err(CryptoError::StrError("x509: invalid crl reason code"));
        }
        reader.expect_end()?;
        CrlReason::from_u8(content[0])
    }

    /// Encode the `reasonCode` extension contents (`ENUMERATED`).
    pub fn encode(self) -> Vec<u8> {
        der::tlv(der::Tag::universal(0x0a), &[self.as_u8()])
    }
}

impl core::fmt::Display for CrlReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// `InvalidityDate ::= GeneralizedTime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidityDate {
    /// The invalidity date.
    pub date: crate::asn1::time::Asn1Time,
}

impl InvalidityDate {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let date = reader.read_generalized_time()?;
        reader.expect_end()?;
        Ok(InvalidityDate { date })
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let mut date = self.date;
        date.utc = false;
        der::generalized_time(&date)
    }
}

/// `CertificateIssuer ::= GeneralNames` (a CRL entry indirection).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertificateIssuer {
    /// The issuer names.
    pub names: Vec<GeneralName>,
}

impl CertificateIssuer {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        Ok(CertificateIssuer {
            names: parse_general_names(der)?,
        })
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        encode_general_names(&self.names)
    }
}

/// The distribution point name of an `IssuingDistributionPoint`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DistributionPointName {
    /// `fullName` general names.
    pub full_name: Option<Vec<GeneralName>>,
    /// `nameRelativeToCRLIssuer`.
    pub relative_name: Option<super::name::Rdn>,
}

/// `IssuingDistributionPoint ::= SEQUENCE { distributionPoint [0] OPTIONAL,
/// onlyContainsUserCerts [1] DEFAULT FALSE, onlyContainsCACerts [2] DEFAULT
/// FALSE, onlySomeReasons [3] OPTIONAL, indirectCRL [4] DEFAULT FALSE,
/// onlyContainsAttributeCerts [5] DEFAULT FALSE }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IssuingDistributionPoint {
    /// The distribution point name.
    pub distribution_point: Option<DistributionPointName>,
    /// `onlyContainsUserCerts`.
    pub only_contains_user_certs: bool,
    /// `onlyContainsCACerts`.
    pub only_contains_ca_certs: bool,
    /// `onlySomeReasons` bits (RFC 5280 bit numbers 0..=8).
    pub only_some_reasons: Option<u16>,
    /// `indirectCRL`.
    pub indirect_crl: bool,
    /// `onlyContainsAttributeCerts`.
    pub only_contains_attribute_certs: bool,
}

impl IssuingDistributionPoint {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut point = IssuingDistributionPoint::default();
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            match (tag.class, tag.number) {
                (der::Class::ContextSpecific, 0) => {
                    let mut inner = seq.read_implicit_constructed(0)?;
                    point.distribution_point = Some(parse_distribution_point_name(&mut inner)?);
                }
                (der::Class::ContextSpecific, 1) => {
                    point.only_contains_user_certs = implicit_boolean(&mut seq, 1)?;
                }
                (der::Class::ContextSpecific, 2) => {
                    point.only_contains_ca_certs = implicit_boolean(&mut seq, 2)?;
                }
                (der::Class::ContextSpecific, 3) => {
                    let content = seq.read_implicit(3, false)?;
                    let (unused, data) = content.split_first().ok_or(CryptoError::StrError(
                        "x509: invalid issuingDistributionPoint reasons",
                    ))?;
                    point.only_some_reasons = Some(bit_string_bits(*unused, data));
                }
                (der::Class::ContextSpecific, 4) => {
                    point.indirect_crl = implicit_boolean(&mut seq, 4)?;
                }
                (der::Class::ContextSpecific, 5) => {
                    point.only_contains_attribute_certs = implicit_boolean(&mut seq, 5)?;
                }
                _ => {
                    return Err(CryptoError::StrError(
                        "x509: invalid issuingDistributionPoint",
                    ));
                }
            }
        }
        Ok(point)
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if let Some(point) = &self.distribution_point {
            let mut inner = Vec::new();
            if let Some(names) = &point.full_name {
                let mut names_content = Vec::new();
                for name in names {
                    names_content.extend_from_slice(&name.encode());
                }
                inner.extend_from_slice(&der::implicit(0, true, &names_content));
            }
            if let Some(relative) = &point.relative_name {
                let mut rdn_content = Vec::new();
                for attribute in &relative.attributes {
                    rdn_content.extend_from_slice(&attribute.encode());
                }
                inner.extend_from_slice(&der::implicit(1, true, &rdn_content));
            }
            content.extend_from_slice(&der::implicit(0, true, &inner));
        }
        if self.only_contains_user_certs {
            content.extend_from_slice(&der::implicit(1, false, &[0xff]));
        }
        if self.only_contains_ca_certs {
            content.extend_from_slice(&der::implicit(2, false, &[0xff]));
        }
        if let Some(bits) = self.only_some_reasons {
            content.extend_from_slice(&der::implicit(3, false, &bit_string_bytes(bits)));
        }
        if self.indirect_crl {
            content.extend_from_slice(&der::implicit(4, false, &[0xff]));
        }
        if self.only_contains_attribute_certs {
            content.extend_from_slice(&der::implicit(5, false, &[0xff]));
        }
        der::sequence(&content)
    }

    /// Whether the given RFC 5280 reason bit is set.
    pub fn has_reason(&self, bit: u16) -> bool {
        self.only_some_reasons
            .is_some_and(|reasons| reasons & (1 << bit) != 0)
    }
}

fn parse_distribution_point_name(reader: &mut Reader<'_>) -> CryptoResult<DistributionPointName> {
    let tag = reader.peek_tag()?;
    match (tag.class, tag.number) {
        (der::Class::ContextSpecific, 0) => {
            let mut inner = reader.read_implicit_constructed(0)?;
            let mut names = Vec::new();
            while !inner.is_empty() {
                names.push(GeneralName::parse(&mut inner)?);
            }
            Ok(DistributionPointName {
                full_name: Some(names),
                relative_name: None,
            })
        }
        (der::Class::ContextSpecific, 1) => {
            let mut inner = reader.read_implicit_constructed(1)?;
            let mut attributes = Vec::new();
            while !inner.is_empty() {
                attributes.push(super::name::AttributeTypeAndValue::parse(&mut inner)?);
            }
            Ok(DistributionPointName {
                full_name: None,
                relative_name: Some(super::name::Rdn { attributes }),
            })
        }
        _ => Err(CryptoError::StrError(
            "x509: invalid distribution point name",
        )),
    }
}

fn bit_string_bits(unused: u8, data: &[u8]) -> u16 {
    let mut bits = 0u16;
    for (index, &byte) in data.iter().enumerate() {
        for bit in 0..8 {
            let position = index * 8 + bit;
            if position >= 16 {
                return bits;
            }
            if byte & (0x80 >> bit) != 0 {
                bits |= 1 << position;
            }
        }
    }
    let _ = unused;
    bits
}

/// The content of an IMPLICIT BIT STRING for `bits` (unused count then
/// octets). `bits` uses RFC 5280 bit numbering: bit 0 is the most significant
/// bit of the first octet.
fn bit_string_bytes(bits: u16) -> Vec<u8> {
    let encode = |group: u16| -> u8 {
        let mut byte = 0u8;
        for bit in 0..8 {
            if group & (1 << bit) != 0 {
                byte |= 0x80 >> bit;
            }
        }
        byte
    };
    // DER uses the smallest number of octets with a matching unused-bit
    // count; OpenSSL emits the same for ReasonFlags.
    let Some(highest) = (0..16).rev().find(|bit| bits & (1 << bit) != 0) else {
        return alloc::vec![0];
    };
    let octets = highest / 8 + 1;
    let unused = (octets * 8 - (highest + 1)) as u8;
    let mut out = alloc::vec![unused];
    for octet in (0..octets).rev() {
        out.push(encode((bits >> (octet * 8)) & 0xff));
    }
    out
}

/// Read an IMPLICIT INTEGER of at most four octets.
fn implicit_u32(reader: &mut Reader<'_>, number: u32) -> CryptoResult<u32> {
    let content = reader.read_implicit(number, false)?;
    if content.is_empty() || content.len() > 4 {
        return Err(CryptoError::StrError("x509: invalid implicit integer"));
    }
    Ok(content
        .iter()
        .fold(0u32, |value, &byte| (value << 8) | byte as u32))
}

/// Read an IMPLICIT BOOLEAN.
fn implicit_boolean(reader: &mut Reader<'_>, number: u32) -> CryptoResult<bool> {
    let content = reader.read_implicit(number, false)?;
    content
        .first()
        .map(|&byte| byte != 0)
        .ok_or(CryptoError::StrError("x509: invalid implicit boolean"))
}

/// `TLSFeature ::= SEQUENCE OF INTEGER`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsFeature {
    /// The feature values (`status_request` = 5, `status_request_v2` = 17).
    pub features: Vec<u64>,
}

impl TlsFeature {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut features = Vec::new();
        while !seq.is_empty() {
            features.push(
                u64::try_from(seq.read_integer_i64()?)
                    .map_err(|_| CryptoError::StrError("x509: invalid TLS feature value"))?,
            );
        }
        Ok(TlsFeature { features })
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for feature in &self.features {
            content.extend_from_slice(&der::integer_i64(*feature as i64));
        }
        der::sequence(&content)
    }
}

/// Build a `subjectInfoAccess` extension.
pub fn subject_info_access(descriptions: &[AccessDescription]) -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_SUBJECT_INFO_ACCESS).expect("static oid"),
        false,
        SubjectInfoAccess {
            descriptions: descriptions.to_vec(),
        }
        .encode(),
    )
}

/// Build a `nameConstraints` extension.
pub fn name_constraints(permitted: &[GeneralSubtree], excluded: &[GeneralSubtree]) -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_NAME_CONSTRAINTS).expect("static oid"),
        true,
        NameConstraints {
            permitted: (!permitted.is_empty()).then(|| permitted.to_vec()),
            excluded: (!excluded.is_empty()).then(|| excluded.to_vec()),
        }
        .encode(),
    )
}

/// Build a `policyConstraints` extension.
pub fn policy_constraints(
    require_explicit_policy: Option<u32>,
    inhibit_policy_mapping: Option<u32>,
) -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_POLICY_CONSTRAINTS).expect("static oid"),
        true,
        PolicyConstraints {
            require_explicit_policy,
            inhibit_policy_mapping,
        }
        .encode(),
    )
}

/// Build an `inhibitAnyPolicy` extension.
pub fn inhibit_any_policy(skip_certs: u32) -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_INHIBIT_ANY_POLICY).expect("static oid"),
        true,
        InhibitAnyPolicy { skip_certs }.encode(),
    )
}

/// Build a `policyMappings` extension.
pub fn policy_mappings(mappings: &[PolicyMapping]) -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_POLICY_MAPPINGS).expect("static oid"),
        true,
        PolicyMappings {
            mappings: mappings.to_vec(),
        }
        .encode(),
    )
}

/// Build a `cRLNumber` extension.
pub fn crl_number(number: &[u8]) -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_CRL_NUMBER).expect("static oid"),
        false,
        CrlNumber {
            number: number.to_vec(),
        }
        .encode(),
    )
}

/// Build a `reasonCode` CRL entry extension.
pub fn reason_code(reason: CrlReason) -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_REASON_CODE).expect("static oid"),
        false,
        reason.encode(),
    )
}

/// Build an `invalidityDate` CRL entry extension.
pub fn invalidity_date(date: crate::asn1::time::Asn1Time) -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_INVALIDITY_DATE).expect("static oid"),
        false,
        InvalidityDate { date }.encode(),
    )
}

/// Build a `certificateIssuer` CRL entry extension.
pub fn certificate_issuer(names: &[GeneralName]) -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_CERTIFICATE_ISSUER).expect("static oid"),
        true,
        encode_general_names(names),
    )
}

/// Build a `deltaCRLIndicator` extension.
pub fn delta_crl_indicator(base_crl_number: &[u8]) -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_DELTA_CRL_INDICATOR).expect("static oid"),
        true,
        DeltaCrlIndicator {
            base_crl_number: base_crl_number.to_vec(),
        }
        .encode(),
    )
}

/// Build a `tlsfeature` extension.
pub fn tls_feature(features: &[u64]) -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_TLS_FEATURE).expect("static oid"),
        false,
        TlsFeature {
            features: features.to_vec(),
        }
        .encode(),
    )
}

/// Build an `OCSP no-check` extension.
pub fn ocsp_no_check() -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_OCSP_NOCHECK).expect("static oid"),
        false,
        der::null(),
    )
}

/// Build a `noRevAvail` extension.
pub fn no_rev_avail() -> Extension {
    Extension::new(
        ObjectIdentifier::new(oid::OID_NO_REV_AVAIL).expect("static oid"),
        false,
        der::null(),
    )
}

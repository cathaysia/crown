//! X.509 v3 extensions.

use alloc::string::String;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::{self, ObjectIdentifier};
use crate::error::{CryptoError, CryptoResult};

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
        if self.oid.matches(oid::OID_SUBJECT_DIRECTORY_ATTRIBUTES) {
            return Ok(ParsedExtension::SubjectDirectoryAttributes);
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
    /// `crlDistributionPoints` (URIs only).
    CrlDistributionPoints(CrlDistributionPoints),
    /// `authorityInfoAccess` (OCSP and caIssuers URIs only).
    AuthorityInfoAccess(AuthorityInfoAccess),
    /// `certificatePolicies` (policy OIDs only).
    CertificatePolicies(CertificatePolicies),
    /// `subjectDirectoryAttributes` (not decoded further).
    SubjectDirectoryAttributes,
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

/// `CRLDistributionPoints`, reduced to the distribution point URIs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CrlDistributionPoints {
    /// The `uniformResourceIdentifier` general names found in the
    /// distribution points.
    pub uris: Vec<String>,
}

impl CrlDistributionPoints {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut uris = Vec::new();
        while !seq.is_empty() {
            // DistributionPoint ::= SEQUENCE { distributionPoint [0] OPTIONAL,
            // reasons [1], cRLIssuer [2] }
            let mut point = seq.read_sequence()?;
            while !point.is_empty() {
                let tag = point.peek_tag()?;
                let content = point.read_implicit(tag.number, tag.constructed)?;
                if tag.number == 0 {
                    let mut inner = Reader::new(content);
                    // distributionPoint CHOICE: [0] fullName, [1] nameRelative.
                    while !inner.is_empty() {
                        let (inner_tag, inner_content) = inner.read_tlv()?;
                        if inner_tag.number == 0 {
                            let mut names = Reader::new(inner_content);
                            while !names.is_empty() {
                                if let GeneralName::Uri(uri) = GeneralName::parse(&mut names)? {
                                    uris.push(uri);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(CrlDistributionPoints { uris })
    }

    /// Encode the extension contents from URIs.
    pub fn from_uris(uris: &[String]) -> Self {
        CrlDistributionPoints {
            uris: uris.to_vec(),
        }
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let mut names_content = Vec::new();
        for uri in &self.uris {
            names_content.extend_from_slice(&GeneralName::Uri(uri.clone()).encode());
        }
        // DistributionPointName's fullName is [0] IMPLICIT GeneralNames.
        let full_name = der::implicit(0, true, &names_content);
        // DistributionPoint is SEQUENCE { distributionPoint [0] ... }.
        let point = der::implicit(0, true, &full_name);
        let distribution_point = der::sequence(&point);
        der::sequence(&distribution_point)
    }
}

/// `AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthorityInfoAccess {
    /// OCSP responder URIs.
    pub ocsp: Vec<String>,
    /// CA issuers URIs.
    pub ca_issuers: Vec<String>,
}

impl AuthorityInfoAccess {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut out = AuthorityInfoAccess::default();
        while !seq.is_empty() {
            let mut desc = seq.read_sequence()?;
            let method = desc.read_oid()?;
            let mut location = Reader::new(desc.read_raw_tlv()?);
            let name = GeneralName::parse(&mut location)?;
            if let GeneralName::Uri(uri) = name {
                if method.matches(oid::OID_AD_OCSP) {
                    out.ocsp.push(uri);
                } else if method.matches(oid::OID_AD_CA_ISSUERS) {
                    out.ca_issuers.push(uri);
                }
            }
        }
        Ok(out)
    }

    /// Encode the extension contents.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        let mut push = |method: &[u64], uri: &str| {
            let mut desc = der::oid(&ObjectIdentifier::new(method).expect("static oid"));
            desc.extend_from_slice(&GeneralName::Uri(String::from(uri)).encode());
            content.extend_from_slice(&der::sequence(&desc));
        };
        for uri in &self.ocsp {
            push(oid::OID_AD_OCSP, uri);
        }
        for uri in &self.ca_issuers {
            push(oid::OID_AD_CA_ISSUERS, uri);
        }
        der::sequence(&content)
    }
}

/// `CertificatePolicies`, reduced to the policy OIDs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertificatePolicies {
    /// Policy OIDs.
    pub policies: Vec<ObjectIdentifier>,
}

impl CertificatePolicies {
    /// Parse the extension contents.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut policies = Vec::new();
        while !seq.is_empty() {
            let mut info = seq.read_sequence()?;
            policies.push(info.read_oid()?);
        }
        Ok(CertificatePolicies { policies })
    }
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

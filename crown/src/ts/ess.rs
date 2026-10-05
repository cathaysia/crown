//! ESS signing-certificate attributes (RFC 2634, RFC 5035).
//!
//! `SigningCertificateV2` binds a CMS signature to the DER encoding of an
//! X.509 certificate through a hash over the whole certificate, optionally
//! together with the issuer name and serial number. It is carried as the
//! `id-aa-signingCertificateV2` signed attribute in RFC 3161 timestamp
//! tokens, but is equally valid for any CMS signature.

use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::error::{CryptoError, CryptoResult};
use crate::utils::subtle::constant_time_eq;
use crate::x509::algorithm::{AlgorithmIdentifier, Hash};
use crate::x509::attribute::Attribute;
use crate::x509::cert::Certificate;
use crate::x509::extensions::{encode_general_names, parse_general_names, GeneralName};

use super::{
    oid_of, GeneralNames, OID_ID_AA_SIGNING_CERTIFICATE, OID_ID_AA_SIGNING_CERTIFICATE_V2,
};

/// `IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber INTEGER }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerSerial {
    /// The certificate issuer, as general names.
    pub issuer: GeneralNames,
    /// The certificate serial number magnitude.
    pub serial: Vec<u8>,
}

impl IssuerSerial {
    /// Build the issuer/serial pair identifying `certificate`.
    pub fn from_certificate(certificate: &Certificate) -> Self {
        IssuerSerial {
            issuer: alloc::vec![GeneralName::DirectoryName(certificate.issuer().clone())],
            serial: certificate.serial_number().to_vec(),
        }
    }

    /// Parse an `IssuerSerial`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let issuer = parse_general_names(seq.read_raw_tlv()?)?;
        let serial = seq.read_integer()?.to_vec();
        seq.expect_end()?;
        Ok(IssuerSerial { issuer, serial })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = encode_general_names(&self.issuer);
        content.extend_from_slice(&der::integer(&self.serial));
        der::sequence(&content)
    }

    /// Whether this pair matches `certificate`.
    pub fn matches_certificate(&self, certificate: &Certificate) -> bool {
        if self.serial != certificate.serial_number() {
            return false;
        }
        self.issuer.iter().any(|name| match name {
            GeneralName::DirectoryName(issuer) => issuer == certificate.issuer(),
            _ => false,
        })
    }
}

/// `ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier DEFAULT
/// {algorithm id-sha256}, certHash OCTET STRING, issuerSerial IssuerSerial
/// OPTIONAL }` (RFC 5035).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsCertIdV2 {
    /// Hash algorithm; `None` is the RFC 5035 default of SHA-256 (the field
    /// is omitted from the DER in that case).
    pub hash_algorithm: Option<AlgorithmIdentifier>,
    /// The certificate hash.
    pub cert_hash: Vec<u8>,
    /// Optional issuer/serial identification.
    pub issuer_serial: Option<IssuerSerial>,
}

impl EsCertIdV2 {
    /// The effective hash algorithm (`SHA-256` when the field is absent).
    pub fn hash(&self) -> CryptoResult<Hash> {
        match &self.hash_algorithm {
            None => Ok(Hash::Sha256),
            Some(algorithm) => Hash::from_oid(&algorithm.oid).ok_or_else(|| {
                CryptoError::UnsupportedOperation(alloc::format!(
                    "ts: unsupported ESSCertIDv2 hash algorithm {}",
                    algorithm.oid
                ))
            }),
        }
    }

    /// Hash `certificate` with SHA-256, including its issuer and serial.
    pub fn from_certificate(certificate: &Certificate) -> CryptoResult<Self> {
        Ok(EsCertIdV2 {
            hash_algorithm: None,
            cert_hash: Hash::Sha256.digest(&certificate.encode())?,
            issuer_serial: Some(IssuerSerial::from_certificate(certificate)),
        })
    }

    /// Parse an `ESSCertIDv2`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let hash_algorithm = if !seq.is_empty() && seq.peek_tag()? == der::SEQUENCE {
            Some(AlgorithmIdentifier::parse(&mut seq)?)
        } else {
            None
        };
        let cert_hash = seq.read_octet_string()?.to_vec();
        let issuer_serial = if seq.is_empty() {
            None
        } else {
            Some(IssuerSerial::parse(&mut seq)?)
        };
        seq.expect_end()?;
        Ok(EsCertIdV2 {
            hash_algorithm,
            cert_hash,
            issuer_serial,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if let Some(algorithm) = &self.hash_algorithm {
            content.extend_from_slice(&algorithm.encode());
        }
        content.extend_from_slice(&der::octet_string(&self.cert_hash));
        if let Some(issuer_serial) = &self.issuer_serial {
            content.extend_from_slice(&issuer_serial.encode());
        }
        der::sequence(&content)
    }

    /// Whether the certificate hash (and issuer/serial, when present) match
    /// `certificate`.
    pub fn matches_certificate(&self, certificate: &Certificate) -> CryptoResult<bool> {
        let digest = self.hash()?.digest(&certificate.encode())?;
        if !constant_time_eq(&digest, &self.cert_hash) {
            return Ok(false);
        }
        if let Some(issuer_serial) = &self.issuer_serial {
            if !issuer_serial.matches_certificate(certificate) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// `ESSCertID ::= SEQUENCE { certHash OCTET STRING, issuerSerial IssuerSerial
/// OPTIONAL }` (RFC 2634); the hash is SHA-1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsCertId {
    /// The SHA-1 certificate hash.
    pub cert_hash: Vec<u8>,
    /// Optional issuer/serial identification.
    pub issuer_serial: Option<IssuerSerial>,
}

impl EsCertId {
    /// Build from a certificate using SHA-1.
    pub fn from_certificate(certificate: &Certificate) -> CryptoResult<Self> {
        Ok(EsCertId {
            cert_hash: Hash::Sha1.digest(&certificate.encode())?,
            issuer_serial: Some(IssuerSerial::from_certificate(certificate)),
        })
    }

    /// Parse an `ESSCertID`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let cert_hash = seq.read_octet_string()?.to_vec();
        let issuer_serial = if seq.is_empty() {
            None
        } else {
            Some(IssuerSerial::parse(&mut seq)?)
        };
        seq.expect_end()?;
        Ok(EsCertId {
            cert_hash,
            issuer_serial,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::octet_string(&self.cert_hash);
        if let Some(issuer_serial) = &self.issuer_serial {
            content.extend_from_slice(&issuer_serial.encode());
        }
        der::sequence(&content)
    }

    /// Whether the SHA-1 hash (and issuer/serial, when present) match
    /// `certificate`.
    pub fn matches_certificate(&self, certificate: &Certificate) -> CryptoResult<bool> {
        let digest = Hash::Sha1.digest(&certificate.encode())?;
        if !constant_time_eq(&digest, &self.cert_hash) {
            return Ok(false);
        }
        if let Some(issuer_serial) = &self.issuer_serial {
            if !issuer_serial.matches_certificate(certificate) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// `SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2,
/// policies SEQUENCE OF PolicyInformation OPTIONAL }` (RFC 5035).
///
/// The optional policies are not interpreted but are preserved on re-encode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningCertificateV2 {
    /// The certificate identifiers.
    pub certs: Vec<EsCertIdV2>,
    /// Raw DER of the optional `policies` element (a complete TLV).
    pub policies: Option<Vec<u8>>,
}

impl SigningCertificateV2 {
    /// Build a single-entry attribute body for `certificate` (SHA-256).
    pub fn from_certificate(certificate: &Certificate) -> CryptoResult<Self> {
        Ok(SigningCertificateV2 {
            certs: alloc::vec![EsCertIdV2::from_certificate(certificate)?],
            policies: None,
        })
    }

    /// Parse the DER of a `SigningCertificateV2`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut certs_reader = seq.read_sequence()?;
        let mut certs = Vec::new();
        while !certs_reader.is_empty() {
            certs.push(EsCertIdV2::parse(&mut certs_reader)?);
        }
        let policies = if seq.is_empty() {
            None
        } else {
            Some(seq.read_raw_tlv()?.to_vec())
        };
        seq.expect_end()?;
        reader.expect_end()?;
        Ok(SigningCertificateV2 { certs, policies })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut certs = Vec::new();
        for cert in &self.certs {
            certs.extend_from_slice(&cert.encode());
        }
        let mut content = der::sequence(&certs);
        if let Some(policies) = &self.policies {
            content.extend_from_slice(policies);
        }
        der::sequence(&content)
    }

    /// Convert to the `id-aa-signingCertificateV2` signed attribute.
    pub fn to_attribute(&self) -> Attribute {
        Attribute::new(
            oid_of(OID_ID_AA_SIGNING_CERTIFICATE_V2),
            alloc::vec![self.encode()],
        )
    }

    /// Parse an `id-aa-signingCertificateV2` attribute.
    pub fn from_attribute(attribute: &Attribute) -> CryptoResult<Self> {
        if !attribute.oid.matches(OID_ID_AA_SIGNING_CERTIFICATE_V2) {
            return Err(CryptoError::StrError(
                "ts: not a signingCertificateV2 attribute",
            ));
        }
        let value = attribute.values.first().ok_or(CryptoError::StrError(
            "ts: empty signingCertificateV2 attribute",
        ))?;
        Self::parse(value)
    }

    /// Whether any entry matches `certificate`.
    pub fn matches_certificate(&self, certificate: &Certificate) -> CryptoResult<bool> {
        for cert in &self.certs {
            if cert.matches_certificate(certificate)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// `SigningCertificate ::= SEQUENCE { certs SEQUENCE OF ESSCertID, policies
/// SEQUENCE OF PolicyInformation OPTIONAL }` (RFC 2634).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningCertificate {
    /// The certificate identifiers (SHA-1).
    pub certs: Vec<EsCertId>,
    /// Raw DER of the optional `policies` element (a complete TLV).
    pub policies: Option<Vec<u8>>,
}

impl SigningCertificate {
    /// Build a single-entry attribute body for `certificate` (SHA-1).
    pub fn from_certificate(certificate: &Certificate) -> CryptoResult<Self> {
        Ok(SigningCertificate {
            certs: alloc::vec![EsCertId::from_certificate(certificate)?],
            policies: None,
        })
    }

    /// Parse the DER of a `SigningCertificate`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let mut certs_reader = seq.read_sequence()?;
        let mut certs = Vec::new();
        while !certs_reader.is_empty() {
            certs.push(EsCertId::parse(&mut certs_reader)?);
        }
        let policies = if seq.is_empty() {
            None
        } else {
            Some(seq.read_raw_tlv()?.to_vec())
        };
        seq.expect_end()?;
        reader.expect_end()?;
        Ok(SigningCertificate { certs, policies })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut certs = Vec::new();
        for cert in &self.certs {
            certs.extend_from_slice(&cert.encode());
        }
        let mut content = der::sequence(&certs);
        if let Some(policies) = &self.policies {
            content.extend_from_slice(policies);
        }
        der::sequence(&content)
    }

    /// Convert to the `id-aa-signingCertificate` signed attribute.
    pub fn to_attribute(&self) -> Attribute {
        Attribute::new(
            oid_of(OID_ID_AA_SIGNING_CERTIFICATE),
            alloc::vec![self.encode()],
        )
    }

    /// Parse an `id-aa-signingCertificate` attribute.
    pub fn from_attribute(attribute: &Attribute) -> CryptoResult<Self> {
        if !attribute.oid.matches(OID_ID_AA_SIGNING_CERTIFICATE) {
            return Err(CryptoError::StrError(
                "ts: not a signingCertificate attribute",
            ));
        }
        let value = attribute.values.first().ok_or(CryptoError::StrError(
            "ts: empty signingCertificate attribute",
        ))?;
        Self::parse(value)
    }

    /// Whether any entry matches `certificate`.
    pub fn matches_certificate(&self, certificate: &Certificate) -> CryptoResult<bool> {
        for cert in &self.certs {
            if cert.matches_certificate(certificate)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

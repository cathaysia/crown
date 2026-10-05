//! X.509 certificate revocation lists.

use alloc::string::String;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::pem;
use crate::asn1::time::Asn1Time;
use crate::error::{CryptoError, CryptoResult};

use super::algorithm::{AlgorithmIdentifier, SignatureAlgorithm};
use super::extensions::{invalidity_date, reason_code, CrlReason, Extension};
use super::keys::PublicKey;
use super::name::Name;

/// One `RevokedCertificate` entry.
#[derive(Debug, Clone)]
pub struct RevokedCertificate {
    /// The revoked certificate's serial number magnitude.
    pub serial_number: Vec<u8>,
    /// Revocation date.
    pub revocation_date: Asn1Time,
    /// CRL entry extensions.
    pub extensions: Vec<Extension>,
}

impl RevokedCertificate {
    /// A revoked entry at `revocation_date` with no reason code.
    pub fn new(serial_number: Vec<u8>, revocation_date: Asn1Time) -> Self {
        RevokedCertificate {
            serial_number,
            revocation_date,
            extensions: Vec::new(),
        }
    }

    /// Attach a `reasonCode` extension.
    pub fn reason(mut self, reason: CrlReason) -> Self {
        self.extensions.push(reason_code(reason));
        self
    }

    /// Attach an `invalidityDate` extension.
    pub fn invalidity_date(mut self, date: Asn1Time) -> Self {
        self.extensions.push(invalidity_date(date));
        self
    }
}

/// The signed part of a CRL.
#[derive(Debug, Clone)]
pub struct TbsCertList {
    /// Version: `None` = v1, `Some(0)` = v2, `Some(1)` = v3.
    pub version: Option<u8>,
    /// Signature algorithm.
    pub signature: AlgorithmIdentifier,
    /// Issuer name.
    pub issuer: Name,
    /// `thisUpdate`.
    pub this_update: Asn1Time,
    /// `nextUpdate`, when present.
    pub next_update: Option<Asn1Time>,
    /// Revoked certificate entries.
    pub revoked_certificates: Vec<RevokedCertificate>,
    /// CRL extensions.
    pub extensions: Vec<Extension>,
}

impl TbsCertList {
    /// Parse a `TBSCertList`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let version = if seq.peek_tag()? == der::INTEGER {
            let value = seq.read_integer_i64()?;
            Some(
                u8::try_from(value)
                    .map_err(|_| CryptoError::StrError("x509: invalid CRL version"))?,
            )
        } else {
            None
        };
        let signature = AlgorithmIdentifier::parse(&mut seq)?;
        let issuer = Name::parse(&mut seq)?;
        let this_update = seq.read_time()?;
        let next_update = match seq.peek_tag()? {
            tag if tag == der::UTC_TIME || tag == der::GENERALIZED_TIME => Some(seq.read_time()?),
            _ => None,
        };
        let mut revoked_certificates = Vec::new();
        let mut extensions = Vec::new();
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            if tag == der::SEQUENCE {
                let mut entries = seq.read_sequence()?;
                while !entries.is_empty() {
                    let mut entry = entries.read_sequence()?;
                    let serial_number = entry.read_integer()?.to_vec();
                    let revocation_date = entry.read_time()?;
                    let mut entry_extensions = Vec::new();
                    if !entry.is_empty() {
                        let mut ext_reader = entry.read_sequence()?;
                        while !ext_reader.is_empty() {
                            entry_extensions.push(Extension::parse(&mut ext_reader)?);
                        }
                    }
                    entry.expect_end()?;
                    revoked_certificates.push(RevokedCertificate {
                        serial_number,
                        revocation_date,
                        extensions: entry_extensions,
                    });
                }
            } else if tag == der::Tag::context_constructed(0) {
                let mut inner = seq.read_explicit(0)?;
                let mut ext_reader = inner.read_sequence()?;
                while !ext_reader.is_empty() {
                    extensions.push(Extension::parse(&mut ext_reader)?);
                }
            } else {
                return Err(CryptoError::StrError("x509: invalid CRL"));
            }
        }
        Ok(TbsCertList {
            version,
            signature,
            issuer,
            this_update,
            next_update,
            revoked_certificates,
            extensions,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if let Some(version) = self.version {
            content.extend_from_slice(&der::integer(&[version]));
        }
        content.extend_from_slice(&self.signature.encode());
        content.extend_from_slice(&self.issuer.encode());
        content.extend_from_slice(&der::time(&self.this_update));
        if let Some(next_update) = &self.next_update {
            content.extend_from_slice(&der::time(next_update));
        }
        if !self.revoked_certificates.is_empty() {
            let mut entries = Vec::new();
            for entry in &self.revoked_certificates {
                let mut entry_content = der::integer(&entry.serial_number);
                entry_content.extend_from_slice(&der::time(&entry.revocation_date));
                if !entry.extensions.is_empty() {
                    let mut exts = Vec::new();
                    for extension in &entry.extensions {
                        exts.extend_from_slice(&extension.encode());
                    }
                    entry_content.extend_from_slice(&der::sequence(&exts));
                }
                entries.extend_from_slice(&der::sequence(&entry_content));
            }
            content.extend_from_slice(&der::sequence(&entries));
        }
        if !self.extensions.is_empty() {
            let mut exts = Vec::new();
            for extension in &self.extensions {
                exts.extend_from_slice(&extension.encode());
            }
            content.extend_from_slice(&der::explicit(0, &der::sequence(&exts)));
        }
        der::sequence(&content)
    }
}

/// `CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm,
/// signatureValue }`.
#[derive(Debug, Clone)]
pub struct CertificateList {
    tbs: TbsCertList,
    signature_algorithm: AlgorithmIdentifier,
    signature: Vec<u8>,
    tbs_raw: Vec<u8>,
}

impl CertificateList {
    /// Parse a DER CRL.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let tbs_raw = seq.read_raw_tlv()?.to_vec();
        let tbs = TbsCertList::parse(&tbs_raw)?;
        let signature_algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        let signature = seq.read_bit_string_bytes()?.to_vec();
        seq.expect_end()?;
        reader.expect_end()?;
        Ok(CertificateList {
            tbs,
            signature_algorithm,
            signature,
            tbs_raw,
        })
    }

    /// Parse a PEM CRL.
    pub fn from_pem(pem_text: &str) -> CryptoResult<Self> {
        let block = pem::parse_first(pem_text)?;
        if block.label != "X509 CRL" && block.label != "CRL" {
            return Err(CryptoError::StrError("x509: not a CRL PEM block"));
        }
        Self::parse(&block.data)
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.tbs_raw.clone();
        content.extend_from_slice(&self.signature_algorithm.encode());
        content.extend_from_slice(&der::bit_string(0, &self.signature));
        der::sequence(&content)
    }

    /// Encode as PEM.
    pub fn to_pem(&self) -> String {
        pem::encode("X509 CRL", &self.encode())
    }

    /// The parsed `TBSCertList`.
    pub fn tbs(&self) -> &TbsCertList {
        &self.tbs
    }

    /// Verify the CRL signature with the issuer public key.
    ///
    /// SM2 signatures use the GM/T default identity; see
    /// [`Self::verify_signature_with_sm2_id`] to override it.
    pub fn verify_signature(&self, issuer: &PublicKey) -> CryptoResult<bool> {
        self.verify_signature_with_sm2_id(issuer, crate::sm2::DEFAULT_ID)
    }

    /// Verify the CRL signature with an explicit SM2 identity.
    pub fn verify_signature_with_sm2_id(
        &self,
        issuer: &PublicKey,
        sm2_id: &[u8],
    ) -> CryptoResult<bool> {
        if self.tbs.signature != self.signature_algorithm {
            return Ok(false);
        }
        let algorithm = SignatureAlgorithm::from_identifier(&self.tbs.signature)?;
        algorithm.verify_with_sm2_id(issuer, &self.tbs_raw, &self.signature, sm2_id)
    }

    /// Find a revoked entry by serial number magnitude.
    pub fn is_revoked(&self, serial_number: &[u8]) -> Option<&RevokedCertificate> {
        self.tbs
            .revoked_certificates
            .iter()
            .find(|entry| entry.serial_number == serial_number)
    }

    /// Build and sign a CRL.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        issuer: Name,
        this_update: Asn1Time,
        next_update: Option<Asn1Time>,
        revoked_certificates: Vec<RevokedCertificate>,
        extensions: Vec<Extension>,
        signature_algorithm: SignatureAlgorithm,
        key: &crate::x509::keys::PrivateKey,
        rng: &mut impl crate::rng::Rng,
    ) -> CryptoResult<Self> {
        let signature = signature_algorithm.to_identifier();
        let tbs = TbsCertList {
            version: Some(1),
            signature: signature.clone(),
            issuer,
            this_update,
            next_update,
            revoked_certificates,
            extensions,
        };
        let tbs_raw = tbs.encode();
        let signature_value = signature_algorithm.sign(key, &tbs_raw, rng)?;
        Ok(CertificateList {
            tbs,
            signature_algorithm: signature,
            signature: signature_value,
            tbs_raw,
        })
    }
}

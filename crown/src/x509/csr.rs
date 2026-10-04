//! PKCS#10 certification requests.

use alloc::string::String;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::pem;
use crate::error::{CryptoError, CryptoResult};
use crate::rng::Rng;

use super::algorithm::{AlgorithmIdentifier, SignatureAlgorithm};
use super::attribute::Attribute;
use super::keys::{PrivateKey, SubjectPublicKeyInfo};
use super::name::Name;

/// The signed part of a certification request.
#[derive(Debug, Clone)]
pub struct CertificationRequestInfo {
    /// Request version (0).
    pub version: u8,
    /// Subject name.
    pub subject: Name,
    /// Subject public key.
    pub subject_public_key_info: SubjectPublicKeyInfo,
    /// Request attributes (challengePassword, extensions, ...).
    pub attributes: Vec<Attribute>,
}

impl CertificationRequestInfo {
    /// Parse a `CertificationRequestInfo`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let version = seq.read_integer_i64()? as u8;
        let subject = Name::parse(&mut seq)?;
        let spki_raw = seq.read_raw_tlv()?;
        let subject_public_key_info = SubjectPublicKeyInfo::parse(spki_raw)?;
        let mut attributes = Vec::new();
        if !seq.is_empty() {
            let tag = seq.peek_tag()?;
            if tag.class != der::Class::ContextSpecific || tag.number != 0 {
                return Err(CryptoError::StrError("x509: invalid CSR attributes"));
            }
            let mut attrs = seq.read_implicit_constructed(0)?;
            while !attrs.is_empty() {
                attributes.push(Attribute::parse(&mut attrs)?);
            }
        }
        seq.expect_end()?;
        reader.expect_end()?;
        Ok(CertificationRequestInfo {
            version,
            subject,
            subject_public_key_info,
            attributes,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.version]);
        content.extend_from_slice(&self.subject.encode());
        content.extend_from_slice(&self.subject_public_key_info.encode());
        let mut attrs_content = Vec::new();
        for attribute in &self.attributes {
            attrs_content.extend_from_slice(&attribute.encode());
        }
        content.extend_from_slice(&der::implicit(0, true, &attrs_content));
        der::sequence(&content)
    }
}

/// A PKCS#10 certification request.
#[derive(Debug, Clone)]
pub struct CertificationRequest {
    info: CertificationRequestInfo,
    signature_algorithm: AlgorithmIdentifier,
    signature: Vec<u8>,
    info_raw: Vec<u8>,
}

impl CertificationRequest {
    /// Parse a DER certification request.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let info_raw = seq.read_raw_tlv()?.to_vec();
        let info = CertificationRequestInfo::parse(&info_raw)?;
        let signature_algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        let signature = seq.read_bit_string_bytes()?.to_vec();
        seq.expect_end()?;
        reader.expect_end()?;
        Ok(CertificationRequest {
            info,
            signature_algorithm,
            signature,
            info_raw,
        })
    }

    /// Parse a PEM certification request.
    pub fn from_pem(pem_text: &str) -> CryptoResult<Self> {
        let block = pem::parse_first(pem_text)?;
        if block.label != "CERTIFICATE REQUEST" && block.label != "NEW CERTIFICATE REQUEST" {
            return Err(CryptoError::StrError("x509: not a request PEM block"));
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
        pem::encode("CERTIFICATE REQUEST", &self.encode())
    }

    /// The request information.
    pub fn info(&self) -> &CertificationRequestInfo {
        &self.info
    }

    /// The exact DER of the signed request information.
    pub fn info_der(&self) -> &[u8] {
        &self.info_raw
    }

    /// The outer signature algorithm.
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// The raw signature.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Verify the self-signature (proof of possession).
    ///
    /// SM2 requests use the GM/T default identity; see
    /// [`Self::verify_signature_with_sm2_id`] to override it.
    pub fn verify_signature(&self) -> CryptoResult<bool> {
        self.verify_signature_with_sm2_id(crate::sm2::DEFAULT_ID)
    }

    /// Verify the self-signature with an explicit SM2 identity.
    pub fn verify_signature_with_sm2_id(&self, sm2_id: &[u8]) -> CryptoResult<bool> {
        let algorithm = SignatureAlgorithm::from_identifier(&self.signature_algorithm)?;
        algorithm.verify_with_sm2_id(
            &self.info.subject_public_key_info.public_key,
            &self.info_raw,
            &self.signature,
            sm2_id,
        )
    }

    /// Build and sign a request.
    pub fn build(
        subject: Name,
        subject_public_key_info: SubjectPublicKeyInfo,
        attributes: Vec<Attribute>,
        signature_algorithm: SignatureAlgorithm,
        key: &PrivateKey,
        rng: &mut impl Rng,
    ) -> CryptoResult<Self> {
        let info = CertificationRequestInfo {
            version: 0,
            subject,
            subject_public_key_info,
            attributes,
        };
        let info_raw = info.encode();
        let signature_algorithm = signature_algorithm.to_identifier();
        let algorithm = SignatureAlgorithm::from_identifier(&signature_algorithm)?;
        let signature = algorithm.sign(key, &info_raw, rng)?;
        Ok(CertificationRequest {
            info,
            signature_algorithm,
            signature,
            info_raw,
        })
    }
}

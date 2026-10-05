//! `DigestedData` (RFC 5652 section 7).

use alloc::string::String;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::{self, OID_PKCS7_DIGESTED_DATA};
use crate::asn1::pem;
use crate::error::{CryptoError, CryptoResult};
use crate::pkcs7::EncapsulatedContentInfo;
use crate::utils::subtle::constant_time_eq;
use crate::x509::algorithm::{AlgorithmIdentifier, Hash};

use super::{oid_of, ContentInfo};

/// `DigestedData ::= SEQUENCE { version, digestAlgorithm,
/// encapContentInfo, digest }`.
#[derive(Debug, Clone)]
pub struct DigestedData {
    /// CMS version (0).
    pub version: u8,
    /// The digest algorithm.
    pub digest_algorithm: AlgorithmIdentifier,
    /// The digested content.
    pub encap_content_info: EncapsulatedContentInfo,
    /// The message digest.
    pub digest: Vec<u8>,
}

impl DigestedData {
    /// Parse a DER `DigestedData`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let data = Self::parse_reader(&mut reader)?;
        reader.expect_end()?;
        Ok(data)
    }

    /// Parse a `DigestedData` from a reader.
    pub fn parse_reader(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let version = u8::try_from(seq.read_integer_i64()?)
            .map_err(|_| CryptoError::StrError("cms: invalid digested data version"))?;
        let digest_algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        let encap_content_info = EncapsulatedContentInfo::parse(&mut seq)?;
        let digest = seq.read_octet_string()?.to_vec();
        seq.expect_end()?;
        Ok(DigestedData {
            version,
            digest_algorithm,
            encap_content_info,
            digest,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.version]);
        content.extend_from_slice(&self.digest_algorithm.encode());
        content.extend_from_slice(&self.encap_content_info.encode());
        content.extend_from_slice(&der::octet_string(&self.digest));
        der::sequence(&content)
    }

    /// Parse the content of an `id-digestedData` `ContentInfo`.
    pub fn from_content_info(info: &ContentInfo) -> CryptoResult<Self> {
        super::check_content_type(info, OID_PKCS7_DIGESTED_DATA, "digested data")?;
        Self::parse(&info.content)
    }

    /// Wrap in an `id-digestedData` `ContentInfo`.
    pub fn to_content_info(&self) -> ContentInfo {
        ContentInfo {
            content_type: oid_of(OID_PKCS7_DIGESTED_DATA),
            content: self.encode(),
        }
    }

    /// Encode as PEM with the `CMS` label.
    pub fn to_pem(&self) -> String {
        pem::encode("CMS", &self.to_content_info().encode())
    }

    /// Parse a PEM `CMS` block.
    pub fn from_pem(text: &str) -> CryptoResult<Self> {
        let block = pem::parse_first(text)?;
        if block.label != "CMS" {
            return Err(CryptoError::StrError("cms: unexpected PEM label"));
        }
        Self::from_content_info(&ContentInfo::parse(&block.data)?)
    }

    /// Create an `id-data` `DigestedData` over `content`.
    pub fn create(content: &[u8], hash: Hash) -> CryptoResult<Self> {
        let digest = hash.digest(content)?;
        Ok(DigestedData {
            version: 0,
            digest_algorithm: AlgorithmIdentifier::new(oid_of(hash.oid()), None),
            encap_content_info: EncapsulatedContentInfo {
                content_type: oid_of(oid::OID_PKCS7_DATA),
                content: Some(content.to_vec()),
            },
            digest,
        })
    }

    /// The digested content.
    pub fn content(&self) -> CryptoResult<&[u8]> {
        self.encap_content_info
            .content
            .as_deref()
            .ok_or(CryptoError::StrError("cms: content missing"))
    }

    /// Verify the digest over the encapsulated content.
    pub fn verify(&self) -> CryptoResult<()> {
        let hash = Hash::from_oid(&self.digest_algorithm.oid).ok_or_else(|| {
            CryptoError::UnsupportedOperation(alloc::format!(
                "cms: unsupported digest {}",
                self.digest_algorithm.oid
            ))
        })?;
        let expected = hash.digest(self.content()?)?;
        if !constant_time_eq(&expected, &self.digest) {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }
}

//! RFC 3161 `TimeStampReq` and `MessageImprint`.

use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::ObjectIdentifier;
use crate::asn1::pem;
use crate::error::{CryptoError, CryptoResult};
use crate::utils::subtle::constant_time_eq;
use crate::x509::algorithm::{AlgorithmIdentifier, Hash};
use crate::x509::extensions::Extension;

/// `MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier,
/// hashedMessage OCTET STRING }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageImprint {
    /// The digest algorithm.
    pub hash_algorithm: AlgorithmIdentifier,
    /// The digest value.
    pub hashed_message: Vec<u8>,
}

impl MessageImprint {
    /// Hash `data` with `hash`.
    pub fn for_data(data: &[u8], hash: Hash) -> CryptoResult<Self> {
        Ok(MessageImprint {
            hash_algorithm: AlgorithmIdentifier::new(
                ObjectIdentifier::new(hash.oid()).expect("static oid"),
                None,
            ),
            hashed_message: hash.digest(data)?,
        })
    }

    /// The digest algorithm, when crown supports it.
    pub fn hash(&self) -> CryptoResult<Hash> {
        Hash::from_oid(&self.hash_algorithm.oid).ok_or_else(|| {
            CryptoError::UnsupportedOperation(alloc::format!(
                "ts: unsupported message imprint hash algorithm {}",
                self.hash_algorithm.oid
            ))
        })
    }

    /// Whether `data` hashes to [`Self::hashed_message`] under
    /// [`Self::hash_algorithm`].
    pub fn matches(&self, data: &[u8]) -> CryptoResult<bool> {
        let digest = self.hash()?.digest(data)?;
        Ok(constant_time_eq(&digest, &self.hashed_message))
    }

    /// Parse a `MessageImprint`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let hash_algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        let hashed_message = seq.read_octet_string()?.to_vec();
        seq.expect_end()?;
        Ok(MessageImprint {
            hash_algorithm,
            hashed_message,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.hash_algorithm.encode();
        content.extend_from_slice(&der::octet_string(&self.hashed_message));
        der::sequence(&content)
    }
}

/// `TimeStampReq ::= SEQUENCE { version INTEGER { v1(1) }, messageImprint
/// MessageImprint, reqPolicy TSAPolicyId OPTIONAL, nonce INTEGER OPTIONAL,
/// certReq BOOLEAN DEFAULT FALSE, extensions [0] IMPLICIT Extensions
/// OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeStampReq {
    /// Protocol version, always 1.
    pub version: u8,
    /// The hash of the data to be timestamped.
    pub message_imprint: MessageImprint,
    /// The requested TSA policy.
    pub req_policy: Option<ObjectIdentifier>,
    /// The nonce magnitude (a positive INTEGER).
    pub nonce: Option<Vec<u8>>,
    /// Whether the TSA certificate should be included in the response.
    pub cert_req: bool,
    /// Request extensions.
    pub extensions: Option<Vec<Extension>>,
}

impl TimeStampReq {
    /// Build a version 1 request for `data` hashed with `hash`.
    pub fn for_data(data: &[u8], hash: Hash, cert_req: bool) -> CryptoResult<Self> {
        Ok(TimeStampReq {
            version: 1,
            message_imprint: MessageImprint::for_data(data, hash)?,
            req_policy: None,
            nonce: None,
            cert_req,
            extensions: None,
        })
    }

    /// Parse a DER `TimeStampReq`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let request = Self::parse_reader(&mut reader)?;
        reader.expect_end()?;
        Ok(request)
    }

    /// Parse a `TimeStampReq` from a reader.
    pub fn parse_reader(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let version = u8::try_from(seq.read_integer_i64()?)
            .map_err(|_| CryptoError::StrError("ts: invalid request version"))?;
        if version != 1 {
            return Err(CryptoError::StrError("ts: unsupported request version"));
        }
        let message_imprint = MessageImprint::parse(&mut seq)?;
        let req_policy = if !seq.is_empty() && seq.peek_tag()? == der::OBJECT_IDENTIFIER {
            Some(seq.read_oid()?)
        } else {
            None
        };
        let nonce = if !seq.is_empty() && seq.peek_tag()? == der::INTEGER {
            Some(seq.read_integer()?.to_vec())
        } else {
            None
        };
        let cert_req = if !seq.is_empty() && seq.peek_tag()? == der::BOOLEAN {
            seq.read_boolean()?
        } else {
            false
        };
        let extensions = if !seq.is_empty() {
            Some(super::tst_info::parse_extensions_implicit(&mut seq, 0)?)
        } else {
            None
        };
        seq.expect_end()?;
        Ok(TimeStampReq {
            version,
            message_imprint,
            req_policy,
            nonce,
            cert_req,
            extensions,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.version]);
        content.extend_from_slice(&self.message_imprint.encode());
        if let Some(policy) = &self.req_policy {
            content.extend_from_slice(&der::oid(policy));
        }
        if let Some(nonce) = &self.nonce {
            content.extend_from_slice(&der::integer(nonce));
        }
        if self.cert_req {
            content.extend_from_slice(&der::boolean(true));
        }
        if let Some(extensions) = &self.extensions {
            content.extend_from_slice(&super::tst_info::encode_extensions_implicit(extensions, 0));
        }
        der::sequence(&content)
    }

    /// Parse the first PEM block, which must be a `TIME STAMP REQUEST`.
    pub fn from_pem(pem_text: &str) -> CryptoResult<Self> {
        let block = pem::parse_first(pem_text)?;
        if block.label != "TIME STAMP REQUEST" {
            return Err(CryptoError::StrError(
                "ts: not a timestamp request PEM block",
            ));
        }
        Self::parse(&block.data)
    }

    /// Encode as PEM with the `TIME STAMP REQUEST` label.
    pub fn to_pem(&self) -> alloc::string::String {
        pem::encode("TIME STAMP REQUEST", &self.encode())
    }

    /// Whether `data` matches the request's message imprint.
    pub fn verify_message_imprint(&self, data: &[u8]) -> CryptoResult<bool> {
        self.message_imprint.matches(data)
    }
}

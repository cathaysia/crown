//! `EncryptedData` (RFC 5652 section 8).
//!
//! Supports the raw-key form OpenSSL's `cms -EncryptedData_encrypt` produces
//! and a PBES2 (PBKDF2 + AES-CBC) password form.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::{self, OID_PKCS7_ENCRYPTED_DATA};
use crate::asn1::pem;
use crate::error::{CryptoError, CryptoResult};
use crate::rng::Rng;
use crate::x509::algorithm::Hash;
use crate::x509::attribute::Attribute;
use crate::x509::pbe::{Pbes2, Pbes2Cipher};

use super::cipher::{Cipher, ContentCipher};
use super::enveloped::EncryptedContentInfo;
use super::{oid_of, ContentInfo};

/// `EncryptedData ::= SEQUENCE { version, encryptedContentInfo,
/// unprotectedAttrs [1] IMPLICIT OPTIONAL }`.
#[derive(Debug, Clone)]
pub struct EncryptedData {
    /// CMS version (0, or 2 when unprotected attributes are present).
    pub version: u8,
    /// The encrypted content.
    pub encrypted_content_info: EncryptedContentInfo,
    /// Optional unprotected attributes.
    pub unprotected_attrs: Vec<Attribute>,
}

impl EncryptedData {
    /// Parse a DER `EncryptedData`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let data = Self::parse_reader(&mut reader)?;
        reader.expect_end()?;
        Ok(data)
    }

    /// Parse an `EncryptedData` from a reader.
    pub fn parse_reader(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let version = u8::try_from(seq.read_integer_i64()?)
            .map_err(|_| CryptoError::StrError("cms: invalid encrypted data version"))?;
        let encrypted_content_info = EncryptedContentInfo::parse(&mut seq)?;
        let mut unprotected_attrs = Vec::new();
        if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(1) {
            let mut attrs = seq.read_implicit_constructed(1)?;
            while !attrs.is_empty() {
                unprotected_attrs.push(Attribute::parse(&mut attrs)?);
            }
        }
        seq.expect_end()?;
        Ok(EncryptedData {
            version,
            encrypted_content_info,
            unprotected_attrs,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.version]);
        content.extend_from_slice(&self.encrypted_content_info.encode());
        if !self.unprotected_attrs.is_empty() {
            let mut attrs = Vec::new();
            for attribute in &self.unprotected_attrs {
                attrs.extend_from_slice(&attribute.encode());
            }
            content.extend_from_slice(&der::implicit(1, true, &attrs));
        }
        der::sequence(&content)
    }

    /// Parse the content of an `id-encryptedData` `ContentInfo`.
    pub fn from_content_info(info: &ContentInfo) -> CryptoResult<Self> {
        super::check_content_type(info, OID_PKCS7_ENCRYPTED_DATA, "encrypted data")?;
        Self::parse(&info.content)
    }

    /// Wrap in an `id-encryptedData` `ContentInfo`.
    pub fn to_content_info(&self) -> ContentInfo {
        ContentInfo {
            content_type: oid_of(OID_PKCS7_ENCRYPTED_DATA),
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

    /// Encrypt `content` with a raw content-encryption `key`.
    pub fn encrypt(
        content: &[u8],
        cipher: Cipher,
        key: &[u8],
        rng: &mut impl Rng,
    ) -> CryptoResult<Self> {
        let content_cipher = cipher.new_content_cipher(rng);
        let encrypted_content = content_cipher.encrypt(key, content)?;
        Ok(EncryptedData {
            version: 0,
            encrypted_content_info: EncryptedContentInfo {
                content_type: oid_of(oid::OID_PKCS7_DATA),
                content_encryption_algorithm: content_cipher.to_algorithm(),
                encrypted_content: Some(encrypted_content),
            },
            unprotected_attrs: Vec::new(),
        })
    }

    /// Decrypt with a raw content-encryption key.
    pub fn decrypt_with_key(&self, key: &[u8]) -> CryptoResult<Vec<u8>> {
        let cipher =
            ContentCipher::parse(&self.encrypted_content_info.content_encryption_algorithm)?;
        let encrypted = self
            .encrypted_content_info
            .encrypted_content
            .as_deref()
            .ok_or(CryptoError::StrError("cms: encrypted content missing"))?;
        cipher.decrypt(key, encrypted)
    }

    /// Encrypt `content` with a password (PBES2: PBKDF2-SHA-256 + AES-CBC).
    pub fn encrypt_with_password(
        content: &[u8],
        password: &[u8],
        cipher: Cipher,
        iterations: u32,
        rng: &mut impl Rng,
    ) -> CryptoResult<Self> {
        let pbe_cipher = pbes2_cipher(cipher, rng)?;
        let mut salt = vec![0u8; 16];
        rng.fill_bytes(&mut salt);
        let pbes2 = Pbes2 {
            salt,
            iterations,
            key_length: None,
            prf: Hash::Sha256,
            cipher: pbe_cipher,
        };
        let encrypted = pbes2.encrypt(content, password)?;
        Ok(EncryptedData {
            version: 0,
            encrypted_content_info: EncryptedContentInfo {
                content_type: oid_of(oid::OID_PKCS7_DATA),
                content_encryption_algorithm: pbes2.to_algorithm(),
                encrypted_content: Some(encrypted),
            },
            unprotected_attrs: Vec::new(),
        })
    }

    /// Decrypt a password-encrypted (`PBES2`) `EncryptedData`.
    pub fn decrypt_with_password(&self, password: &[u8]) -> CryptoResult<Vec<u8>> {
        let pbes2 = Pbes2::parse(&self.encrypted_content_info.content_encryption_algorithm)?;
        let encrypted = self
            .encrypted_content_info
            .encrypted_content
            .as_deref()
            .ok_or(CryptoError::StrError("cms: encrypted content missing"))?;
        pbes2.decrypt(encrypted, password)
    }
}

/// Map a CBC content cipher onto the PBES2 schemes (GCM has no PBES2 form).
fn pbes2_cipher(cipher: Cipher, rng: &mut impl Rng) -> CryptoResult<Pbes2Cipher> {
    match cipher {
        Cipher::Aes128Cbc | Cipher::Aes192Cbc | Cipher::Aes256Cbc => {
            let mut iv = vec![0u8; 16];
            rng.fill_bytes(&mut iv);
            Ok(match cipher {
                Cipher::Aes128Cbc => Pbes2Cipher::Aes128Cbc { iv },
                Cipher::Aes192Cbc => Pbes2Cipher::Aes192Cbc { iv },
                _ => Pbes2Cipher::Aes256Cbc { iv },
            })
        }
        Cipher::DesEde3Cbc => {
            let mut iv = vec![0u8; 8];
            rng.fill_bytes(&mut iv);
            Ok(Pbes2Cipher::DesEde3Cbc { iv })
        }
        _ => Err(CryptoError::UnsupportedOperation(
            "cms: password encryption requires a CBC cipher".to_string(),
        )),
    }
}

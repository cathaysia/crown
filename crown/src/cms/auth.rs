//! `AuthEnvelopedData` (RFC 5083): enveloped content with an AEAD cipher,
//! where the authentication tag travels in the `mac` field instead of being
//! appended to the ciphertext.
//!
//! OpenSSL emits this structure for `cms -encrypt -aes-256-gcm`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::pem;
use crate::error::{CryptoError, CryptoResult};
use crate::x509::attribute::Attribute;
use crate::x509::cert::Certificate;
use crate::x509::keys::PrivateKey;

use super::cipher::ContentCipher;
use super::enveloped::{EncryptedContentInfo, EnvelopedData, OriginatorInfo};
use super::recipient::RecipientInfo;
use super::{oid_of, ContentInfo, OID_AUTH_ENVELOPED_DATA};

/// `AuthEnvelopedData ::= SEQUENCE { version, originatorInfo [0] IMPLICIT
/// OPTIONAL, recipientInfos, authEncryptedContentInfo, authAttrs [1] IMPLICIT
/// OPTIONAL, mac OCTET STRING, unauthAttrs [2] IMPLICIT OPTIONAL }`.
#[derive(Debug, Clone)]
pub struct AuthEnvelopedData {
    /// CMS version.
    pub version: u8,
    /// Optional originator certificates and CRLs.
    pub originator_info: Option<OriginatorInfo>,
    /// One entry per recipient.
    pub recipient_infos: Vec<RecipientInfo>,
    /// The encrypted content (without the tag).
    pub auth_encrypted_content_info: EncryptedContentInfo,
    /// Authenticated attributes, used as AEAD associated data.
    pub auth_attrs: Vec<Attribute>,
    /// The AEAD authentication tag.
    pub mac: Vec<u8>,
    /// Unauthenticated attributes.
    pub unauth_attrs: Vec<Attribute>,
}

impl AuthEnvelopedData {
    /// Parse a DER `AuthEnvelopedData`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let data = Self::parse_reader(&mut reader)?;
        reader.expect_end()?;
        Ok(data)
    }

    /// Parse an `AuthEnvelopedData` from a reader.
    pub fn parse_reader(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let version = u8::try_from(seq.read_integer_i64()?)
            .map_err(|_| CryptoError::StrError("cms: invalid auth enveloped data version"))?;
        let originator_info =
            if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(0) {
                let mut inner = seq.read_implicit_constructed(0)?;
                let info = OriginatorInfo::parse_body(&mut inner)?;
                inner.expect_end()?;
                Some(info)
            } else {
                None
            };
        let mut recipients = seq.read_set()?;
        let mut recipient_infos = Vec::new();
        while !recipients.is_empty() {
            recipient_infos.push(RecipientInfo::parse(&mut recipients)?);
        }
        let auth_encrypted_content_info = EncryptedContentInfo::parse(&mut seq)?;
        let auth_attrs = parse_attribute_set(&mut seq, 1)?;
        let mac = seq.read_octet_string()?.to_vec();
        let unauth_attrs = parse_attribute_set(&mut seq, 2)?;
        seq.expect_end()?;
        Ok(AuthEnvelopedData {
            version,
            originator_info,
            recipient_infos,
            auth_encrypted_content_info,
            auth_attrs,
            mac,
            unauth_attrs,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.version]);
        if let Some(info) = &self.originator_info {
            content.extend_from_slice(&der::implicit(0, true, &info.encode_body()));
        }
        let mut recipients: Vec<Vec<u8>> = self
            .recipient_infos
            .iter()
            .map(RecipientInfo::encode)
            .collect();
        recipients.sort();
        content.extend_from_slice(&der::set(&recipients.concat()));
        content.extend_from_slice(&self.auth_encrypted_content_info.encode());
        if !self.auth_attrs.is_empty() {
            content.extend_from_slice(&der::implicit(
                1,
                true,
                &encode_attributes(&self.auth_attrs),
            ));
        }
        content.extend_from_slice(&der::octet_string(&self.mac));
        if !self.unauth_attrs.is_empty() {
            content.extend_from_slice(&der::implicit(
                2,
                true,
                &encode_attributes(&self.unauth_attrs),
            ));
        }
        der::sequence(&content)
    }

    /// Parse the content of an `id-smime-ct-authEnvelopedData` `ContentInfo`.
    pub fn from_content_info(info: &ContentInfo) -> CryptoResult<Self> {
        super::check_content_type(info, OID_AUTH_ENVELOPED_DATA, "auth enveloped data")?;
        Self::parse(&info.content)
    }

    /// Wrap in an `id-smime-ct-authEnvelopedData` `ContentInfo`.
    pub fn to_content_info(&self) -> ContentInfo {
        ContentInfo {
            content_type: oid_of(OID_AUTH_ENVELOPED_DATA),
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

    /// Convert an AEAD `EnvelopedData` (tag appended to the ciphertext) into
    /// the equivalent `AuthEnvelopedData` (tag in `mac`).
    pub fn from_enveloped_data(data: EnvelopedData) -> CryptoResult<Self> {
        let cipher =
            ContentCipher::parse(&data.encrypted_content_info.content_encryption_algorithm)?;
        let tag_len = cipher.tag_len().ok_or_else(|| {
            CryptoError::UnsupportedOperation(
                "cms: AuthEnvelopedData requires an AEAD content cipher".to_string(),
            )
        })?;
        let encrypted = data
            .encrypted_content_info
            .encrypted_content
            .ok_or(CryptoError::StrError("cms: encrypted content missing"))?;
        if encrypted.len() < tag_len {
            return Err(CryptoError::StrError("cms: truncated AEAD ciphertext"));
        }
        let (content, mac) = encrypted.split_at(encrypted.len() - tag_len);
        Ok(AuthEnvelopedData {
            version: data.version,
            originator_info: data.originator_info,
            recipient_infos: data.recipient_infos,
            auth_encrypted_content_info: EncryptedContentInfo {
                content_type: data.encrypted_content_info.content_type,
                content_encryption_algorithm: data
                    .encrypted_content_info
                    .content_encryption_algorithm,
                encrypted_content: Some(content.to_vec()),
            },
            auth_attrs: Vec::new(),
            mac: mac.to_vec(),
            unauth_attrs: data.unprotected_attrs,
        })
    }

    /// Decrypt using an RSA key-transport or ECDH key-agreement recipient
    /// matching `certificate`.
    pub fn decrypt_with_key(
        &self,
        key: &PrivateKey,
        certificate: &Certificate,
    ) -> CryptoResult<Vec<u8>> {
        for recipient in &self.recipient_infos {
            match recipient {
                RecipientInfo::KeyTrans(info) => {
                    if info.rid.matches(certificate) {
                        let cek = info.decrypt(key)?;
                        return self.decrypt_content(&cek);
                    }
                }
                RecipientInfo::KeyAgree(info) => {
                    if let Some(cek) = info.decrypt(key, certificate)? {
                        return self.decrypt_content(&cek);
                    }
                }
                _ => {}
            }
        }
        Err(CryptoError::StrError("cms: no matching recipient"))
    }

    /// Decrypt a password-based (`pwri`) recipient with PBKDF2.
    pub fn decrypt_with_password(&self, password: &[u8]) -> CryptoResult<Vec<u8>> {
        for recipient in &self.recipient_infos {
            if let RecipientInfo::Password(info) = recipient {
                let cek = info.decrypt(password)?;
                return self.decrypt_content(&cek);
            }
        }
        Err(CryptoError::StrError("cms: no password recipient"))
    }

    /// Decrypt a `kekri` recipient whose `keyIdentifier` equals `key_id`.
    pub fn decrypt_with_kek(&self, kek: &[u8], key_id: &[u8]) -> CryptoResult<Vec<u8>> {
        for recipient in &self.recipient_infos {
            if let RecipientInfo::Kek(info) = recipient {
                if info.kekid.key_id == key_id {
                    let cek = info.decrypt(kek)?;
                    return self.decrypt_content(&cek);
                }
            }
        }
        Err(CryptoError::StrError("cms: no matching KEK recipient"))
    }

    /// The AEAD associated data: the DER `SET OF` encoding of `authAttrs`,
    /// or empty when there are none.
    pub fn associated_data(&self) -> Vec<u8> {
        if self.auth_attrs.is_empty() {
            Vec::new()
        } else {
            der::set(&encode_attributes(&self.auth_attrs))
        }
    }

    /// Verify the tag and decrypt the content with a recovered CEK.
    pub fn decrypt_content(&self, cek: &[u8]) -> CryptoResult<Vec<u8>> {
        let info = &self.auth_encrypted_content_info;
        let cipher = ContentCipher::parse(&info.content_encryption_algorithm)?;
        let encrypted = info
            .encrypted_content
            .as_deref()
            .ok_or(CryptoError::StrError("cms: encrypted content missing"))?;
        let aad = self.associated_data();
        cipher.decrypt_with_tag(cek, encrypted, &self.mac, &aad)
    }
}

/// Parse an `[n] IMPLICIT SET OF Attribute` field when present.
fn parse_attribute_set(reader: &mut Reader<'_>, number: u32) -> CryptoResult<Vec<Attribute>> {
    let mut attrs = Vec::new();
    if !reader.is_empty() && reader.peek_tag()? == der::Tag::context_constructed(number) {
        let mut content = reader.read_implicit_constructed(number)?;
        while !content.is_empty() {
            attrs.push(Attribute::parse(&mut content)?);
        }
    }
    Ok(attrs)
}

/// Encode attribute values as the SET OF content octets.
fn encode_attributes(attrs: &[Attribute]) -> Vec<u8> {
    let mut content = Vec::new();
    for attribute in attrs {
        content.extend_from_slice(&attribute.encode());
    }
    content
}

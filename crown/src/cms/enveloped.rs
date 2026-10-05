//! `EnvelopedData` (RFC 5652 section 6), its builder and decryption.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::{self, ObjectIdentifier, OID_PKCS7_ENVELOPED_DATA};
use crate::asn1::pem;
use crate::error::{CryptoError, CryptoResult};
use crate::rng::Rng;
use crate::x509::algorithm::AlgorithmIdentifier;
use crate::x509::attribute::Attribute;
use crate::x509::cert::Certificate;
use crate::x509::crl::CertificateList;
use crate::x509::keys::PrivateKey;

use super::cipher::{Cipher, ContentCipher};
use super::recipient::{
    KekRecipientInfo, KeyAgreeRecipientInfo, KeyTransRecipientInfo, PasswordRecipientInfo,
    RecipientInfo,
};
use super::{oid_of, ContentInfo};

/// `OriginatorInfo ::= SEQUENCE { certs [0] IMPLICIT CertificateSet
/// OPTIONAL, crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }`.
#[derive(Debug, Clone, Default)]
pub struct OriginatorInfo {
    /// Originator certificates.
    pub certificates: Vec<Certificate>,
    /// Originator CRLs.
    pub crls: Vec<CertificateList>,
}

impl OriginatorInfo {
    /// Parse an `OriginatorInfo` `SEQUENCE`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let info = Self::parse_body(&mut seq)?;
        seq.expect_end()?;
        Ok(info)
    }

    /// Parse the fields of an `OriginatorInfo` (used for the IMPLICIT `[0]`
    /// form inside `EnvelopedData`).
    pub fn parse_body(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut certificates = Vec::new();
        let mut crls = Vec::new();
        if !reader.is_empty() && reader.peek_tag()? == der::Tag::context_constructed(0) {
            let mut inner = reader.read_implicit_constructed(0)?;
            while !inner.is_empty() {
                let raw = inner.read_raw_tlv()?;
                // CertificateChoices also allows attribute certificates; only
                // X.509 certificates are decoded.
                if Reader::new(raw).peek_tag()? == der::SEQUENCE {
                    certificates.push(Certificate::parse(raw)?);
                }
            }
        }
        if !reader.is_empty() && reader.peek_tag()? == der::Tag::context_constructed(1) {
            let mut inner = reader.read_implicit_constructed(1)?;
            while !inner.is_empty() {
                let raw = inner.read_raw_tlv()?;
                // RevocationInfoChoices also allows other revocation info.
                if Reader::new(raw).peek_tag()? == der::SEQUENCE {
                    crls.push(CertificateList::parse(raw)?);
                }
            }
        }
        Ok(OriginatorInfo { certificates, crls })
    }

    /// Encode as a DER `SEQUENCE`.
    pub fn encode(&self) -> Vec<u8> {
        der::sequence(&self.encode_body())
    }

    /// The `SEQUENCE` content octets (for IMPLICIT tagging).
    pub fn encode_body(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if !self.certificates.is_empty() {
            let mut certs = Vec::new();
            for certificate in &self.certificates {
                certs.extend_from_slice(&certificate.encode());
            }
            content.extend_from_slice(&der::implicit(0, true, &certs));
        }
        if !self.crls.is_empty() {
            let mut crls = Vec::new();
            for crl in &self.crls {
                crls.extend_from_slice(&crl.encode());
            }
            content.extend_from_slice(&der::implicit(1, true, &crls));
        }
        content
    }
}

/// `EncryptedContentInfo ::= SEQUENCE { contentType, contentEncryptionAlgorithm,
/// encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedContentInfo {
    /// The content type (normally `id-data`).
    pub content_type: ObjectIdentifier,
    /// The content-encryption algorithm and its parameters.
    pub content_encryption_algorithm: AlgorithmIdentifier,
    /// The ciphertext (with the GCM tag appended for AEAD ciphers), absent
    /// for detached content.
    pub encrypted_content: Option<Vec<u8>>,
}

impl EncryptedContentInfo {
    /// Parse an `EncryptedContentInfo`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let content_type = seq.read_oid()?;
        let content_encryption_algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        let encrypted_content = if seq.is_empty() {
            None
        } else {
            Some(seq.read_implicit(0, false)?.to_vec())
        };
        seq.expect_end()?;
        Ok(EncryptedContentInfo {
            content_type,
            content_encryption_algorithm,
            encrypted_content,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::oid(&self.content_type);
        content.extend_from_slice(&self.content_encryption_algorithm.encode());
        if let Some(encrypted) = &self.encrypted_content {
            content.extend_from_slice(&der::implicit(0, false, encrypted));
        }
        der::sequence(&content)
    }
}

/// `EnvelopedData ::= SEQUENCE { version, originatorInfo [0] IMPLICIT
/// OPTIONAL, recipientInfos, encryptedContentInfo, unprotectedAttrs [1]
/// IMPLICIT OPTIONAL }`.
#[derive(Debug, Clone)]
pub struct EnvelopedData {
    /// CMS version (0, 2 or 3).
    pub version: u8,
    /// Optional originator certificates and CRLs.
    pub originator_info: Option<OriginatorInfo>,
    /// One entry per recipient.
    pub recipient_infos: Vec<RecipientInfo>,
    /// The encrypted content.
    pub encrypted_content_info: EncryptedContentInfo,
    /// Optional unprotected attributes.
    pub unprotected_attrs: Vec<Attribute>,
}

impl EnvelopedData {
    /// Parse a DER `EnvelopedData` (the inner element of an
    /// `id-envelopedData` `ContentInfo`).
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let data = Self::parse_reader(&mut reader)?;
        reader.expect_end()?;
        Ok(data)
    }

    /// Parse an `EnvelopedData` from a reader.
    pub fn parse_reader(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let version = u8::try_from(seq.read_integer_i64()?)
            .map_err(|_| CryptoError::StrError("cms: invalid enveloped data version"))?;
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
        let encrypted_content_info = EncryptedContentInfo::parse(&mut seq)?;
        let mut unprotected_attrs = Vec::new();
        if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(1) {
            let mut attrs = seq.read_implicit_constructed(1)?;
            while !attrs.is_empty() {
                unprotected_attrs.push(Attribute::parse(&mut attrs)?);
            }
        }
        seq.expect_end()?;
        Ok(EnvelopedData {
            version,
            originator_info,
            recipient_infos,
            encrypted_content_info,
            unprotected_attrs,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.version]);
        if let Some(info) = &self.originator_info {
            content.extend_from_slice(&der::implicit(0, true, &info.encode_body()));
        }
        // RecipientInfos is a DER SET OF: sort the encodings.
        let mut recipients: Vec<Vec<u8>> = self
            .recipient_infos
            .iter()
            .map(RecipientInfo::encode)
            .collect();
        recipients.sort();
        content.extend_from_slice(&der::set(&recipients.concat()));
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

    /// Parse the content of an `id-envelopedData` `ContentInfo`.
    pub fn from_content_info(info: &ContentInfo) -> CryptoResult<Self> {
        super::check_content_type(info, OID_PKCS7_ENVELOPED_DATA, "enveloped data")?;
        Self::parse(&info.content)
    }

    /// Wrap in an `id-envelopedData` `ContentInfo`.
    pub fn to_content_info(&self) -> ContentInfo {
        ContentInfo {
            content_type: oid_of(OID_PKCS7_ENVELOPED_DATA),
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

    /// Decrypt the content with a recovered content-encryption key.
    pub fn decrypt_content(&self, cek: &[u8]) -> CryptoResult<Vec<u8>> {
        let info = &self.encrypted_content_info;
        let cipher = ContentCipher::parse(&info.content_encryption_algorithm)?;
        let encrypted = info
            .encrypted_content
            .as_deref()
            .ok_or(CryptoError::StrError("cms: encrypted content missing"))?;
        cipher.decrypt(cek, encrypted)
    }
}

/// Builder for `EnvelopedData` with one content-encryption key shared by
/// every recipient.
///
/// Add the recipients first, then call [`Self::build`] to generate the CEK
/// and content IV and encrypt the content.
#[derive(Debug, Clone, Default)]
pub struct EnvelopedDataBuilder {
    content: Vec<u8>,
    cipher: Option<Cipher>,
    cek: Option<Vec<u8>>,
    recipients: Vec<RecipientInfo>,
    pending_password: Vec<(Vec<u8>, u32)>,
    pending_kek: Vec<(Vec<u8>, Vec<u8>)>,
    originator_info: Option<OriginatorInfo>,
    unprotected_attrs: Vec<Attribute>,
    error: Option<String>,
}

impl EnvelopedDataBuilder {
    /// An `id-data` builder over `content`.
    pub fn new(content: Vec<u8>) -> Self {
        EnvelopedDataBuilder {
            content,
            ..Default::default()
        }
    }

    /// Include an `originatorInfo` field.
    pub fn originator_info(mut self, info: OriginatorInfo) -> Self {
        self.originator_info = Some(info);
        self
    }

    /// Include unprotected attributes.
    pub fn unprotected_attrs(mut self, attrs: Vec<Attribute>) -> Self {
        self.unprotected_attrs = attrs;
        self
    }

    /// Add an RSA PKCS#1 v1.5 key-transport recipient.
    pub fn add_rsa_recipient(
        mut self,
        certificate: &Certificate,
        cipher: Cipher,
        rng: &mut impl Rng,
    ) -> Self {
        self.prepare(cipher, rng);
        if self.error.is_some() {
            return self;
        }
        let cek = self.cek.clone().unwrap_or_default();
        match KeyTransRecipientInfo::wrap(certificate, &cek, rng) {
            Ok(info) => self.recipients.push(RecipientInfo::KeyTrans(info)),
            Err(err) => self.fail(err),
        }
        self
    }

    /// Add an RSA OAEP key-transport recipient.
    pub fn add_rsa_oaep_recipient(
        mut self,
        certificate: &Certificate,
        cipher: Cipher,
        hash: crate::x509::algorithm::Hash,
        rng: &mut impl Rng,
    ) -> Self {
        self.prepare(cipher, rng);
        if self.error.is_some() {
            return self;
        }
        let cek = self.cek.clone().unwrap_or_default();
        let encryption = super::recipient::RsaKeyEncryption::Oaep { hash };
        match KeyTransRecipientInfo::wrap_with(certificate, encryption, &cek, rng) {
            Ok(info) => self.recipients.push(RecipientInfo::KeyTrans(info)),
            Err(err) => self.fail(err),
        }
        self
    }

    /// Add a password (`pwri`) recipient: PBKDF2-SHA-256 plus the RFC 3217
    /// `id-alg-PWRI-KEK` wrap.
    pub fn add_password_recipient(
        mut self,
        password: &[u8],
        cipher: Cipher,
        iterations: u32,
    ) -> Self {
        self.set_cipher(cipher);
        self.pending_password.push((password.to_vec(), iterations));
        self
    }

    /// Add a KEK (`kekri`) recipient using RFC 3394 AES key wrap.
    pub fn add_kek_recipient(mut self, kek: &[u8], key_id: &[u8], cipher: Cipher) -> Self {
        self.set_cipher(cipher);
        if self.cek.is_some() {
            let cek = self.cek.clone().unwrap_or_default();
            match KekRecipientInfo::wrap(kek, key_id, &cek) {
                Ok(info) => self.recipients.push(RecipientInfo::Kek(info)),
                Err(err) => self.fail(err),
            }
        } else {
            self.pending_kek.push((kek.to_vec(), key_id.to_vec()));
        }
        self
    }

    /// Add an ECDH key-agreement (`kari`) recipient with an ephemeral key.
    pub fn add_key_agree_recipient(
        mut self,
        certificate: &Certificate,
        cipher: Cipher,
        rng: &mut impl Rng,
    ) -> Self {
        self.prepare(cipher, rng);
        if self.error.is_some() {
            return self;
        }
        let cek = self.cek.clone().unwrap_or_default();
        match KeyAgreeRecipientInfo::wrap(certificate, &cek, rng) {
            Ok(info) => self.recipients.push(RecipientInfo::KeyAgree(info)),
            Err(err) => self.fail(err),
        }
        self
    }

    /// Generate the CEK, wrap it for every recipient and encrypt the content.
    pub fn build(mut self, rng: &mut impl Rng) -> CryptoResult<EnvelopedData> {
        if let Some(error) = self.error.take() {
            return Err(CryptoError::UnsupportedOperation(error));
        }
        let cipher = self
            .cipher
            .ok_or(CryptoError::StrError("cms: no recipients"))?;
        self.ensure_cek(cipher, rng);
        let cek = self
            .cek
            .clone()
            .ok_or(CryptoError::StrError("cms: missing CEK"))?;

        for (kek, key_id) in core::mem::take(&mut self.pending_kek) {
            let info = KekRecipientInfo::wrap(&kek, &key_id, &cek)?;
            self.recipients.push(RecipientInfo::Kek(info));
        }
        for (password, iterations) in core::mem::take(&mut self.pending_password) {
            let info = PasswordRecipientInfo::wrap(&password, iterations, cipher, &cek, rng)?;
            self.recipients.push(RecipientInfo::Password(info));
        }
        if self.recipients.is_empty() {
            return Err(CryptoError::StrError("cms: no recipients"));
        }
        let content_cipher = cipher.new_content_cipher(rng);
        let encrypted_content = content_cipher.encrypt(&cek, &self.content)?;
        let version = envelope_version(
            &self.recipients,
            &self.originator_info,
            &self.unprotected_attrs,
        );
        Ok(EnvelopedData {
            version,
            originator_info: self.originator_info,
            recipient_infos: self.recipients,
            encrypted_content_info: EncryptedContentInfo {
                content_type: oid_of(oid::OID_PKCS7_DATA),
                content_encryption_algorithm: content_cipher.to_algorithm(),
                encrypted_content: Some(encrypted_content),
            },
            unprotected_attrs: self.unprotected_attrs,
        })
    }

    /// Build an AEAD `AuthEnvelopedData` (RFC 5083) instead of plain
    /// `EnvelopedData`; requires an AEAD `cipher` (AES-GCM). The tag is moved
    /// from the ciphertext into the `mac` field, which is what OpenSSL emits
    /// for `cms -encrypt -aes-256-gcm`.
    pub fn build_auth_enveloped(
        self,
        rng: &mut impl Rng,
    ) -> CryptoResult<super::auth::AuthEnvelopedData> {
        let data = self.build(rng)?;
        super::auth::AuthEnvelopedData::from_enveloped_data(data)
    }

    fn set_cipher(&mut self, cipher: Cipher) {
        match self.cipher {
            Some(existing) if existing != cipher => {
                self.record_error("cms: inconsistent content cipher".to_string());
            }
            Some(_) => {}
            None => self.cipher = Some(cipher),
        }
    }

    fn prepare(&mut self, cipher: Cipher, rng: &mut impl Rng) {
        self.set_cipher(cipher);
        if self.error.is_none() {
            self.ensure_cek(cipher, rng);
        }
    }

    fn ensure_cek(&mut self, cipher: Cipher, rng: &mut impl Rng) {
        if self.cek.is_none() {
            let mut cek = vec![0u8; cipher.key_len()];
            rng.fill_bytes(&mut cek);
            self.cek = Some(cek);
        }
    }

    fn fail(&mut self, error: CryptoError) {
        self.record_error(alloc::format!("{error}"));
    }

    fn record_error(&mut self, error: String) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }
}

/// The CMS `EnvelopedData` version rules.
fn envelope_version(
    recipients: &[RecipientInfo],
    originator_info: &Option<OriginatorInfo>,
    unprotected_attrs: &[Attribute],
) -> u8 {
    if recipients
        .iter()
        .any(|recipient| matches!(recipient, RecipientInfo::Password(_)))
    {
        return 3;
    }
    let mut version = 0;
    for recipient in recipients {
        match recipient {
            RecipientInfo::KeyTrans(info) if info.version == 0 => {}
            _ => version = 2,
        }
    }
    if originator_info.is_some() || !unprotected_attrs.is_empty() {
        version = 2;
    }
    version
}

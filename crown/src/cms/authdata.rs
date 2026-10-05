//! `AuthenticatedData` (RFC 5652 section 9.1): content protected by a MAC,
//! with the MAC key carried to the recipients (RSA, ECDH, KEK or password).

use alloc::string::String;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::ObjectIdentifier;
use crate::asn1::pem;
use crate::error::{CryptoError, CryptoResult};
use crate::x509::algorithm::{AlgorithmIdentifier, Hash};
use crate::x509::attribute::{content_type, message_digest, Attribute};
use crate::x509::cert::Certificate;
use crate::x509::keys::PrivateKey;

use crate::pkcs7::EncapsulatedContentInfo;

use super::enveloped::OriginatorInfo;
use super::recipient::{
    IssuerAndSerialNumber, RecipientIdentifier, RecipientInfo, RsaKeyEncryption,
};
use super::{oid_of, ContentInfo};

/// `id-ct-authData` (1.2.840.113549.1.9.16.1.2).
pub const OID_AUTH_DATA: &[u64] = &[1, 2, 840, 113549, 1, 9, 16, 1, 2];

/// HMAC algorithm identifiers used by `AuthenticatedData`.
pub const OID_HMAC_SHA1: &[u64] = &[1, 2, 840, 113549, 2, 7];
/// `hmacWithSHA224`.
pub const OID_HMAC_SHA224: &[u64] = &[1, 2, 840, 113549, 2, 8];
/// `hmacWithSHA256`.
pub const OID_HMAC_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];
/// `hmacWithSHA384`.
pub const OID_HMAC_SHA384: &[u64] = &[1, 2, 840, 113549, 2, 10];
/// `hmacWithSHA512`.
pub const OID_HMAC_SHA512: &[u64] = &[1, 2, 840, 113549, 2, 11];

/// The digest behind an HMAC algorithm identifier (also accepts a plain
/// digest OID for leniency).
fn hash_for_mac(algorithm: &AlgorithmIdentifier) -> Option<Hash> {
    let known: &[(&[u64], Hash)] = &[
        (OID_HMAC_SHA1, Hash::Sha1),
        (OID_HMAC_SHA224, Hash::Sha224),
        (OID_HMAC_SHA256, Hash::Sha256),
        (OID_HMAC_SHA384, Hash::Sha384),
        (OID_HMAC_SHA512, Hash::Sha512),
    ];
    known
        .iter()
        .find(|(arcs, _)| algorithm.oid.matches(arcs))
        .map(|(_, hash)| *hash)
        .or_else(|| Hash::from_oid(&algorithm.oid))
}

/// The HMAC algorithm identifier for a digest.
pub fn mac_algorithm_for(hash: Hash) -> AlgorithmIdentifier {
    let arcs = match hash {
        Hash::Sha1 => OID_HMAC_SHA1,
        Hash::Sha224 => OID_HMAC_SHA224,
        Hash::Sha384 => OID_HMAC_SHA384,
        Hash::Sha512 => OID_HMAC_SHA512,
        _ => OID_HMAC_SHA256,
    };
    AlgorithmIdentifier::with_null(oid_of(arcs))
}

/// `AuthenticatedData`.
#[derive(Debug, Clone)]
pub struct AuthenticatedData {
    /// CMS version.
    pub version: u8,
    /// Optional originator certificates and CRLs.
    pub originator_info: Option<OriginatorInfo>,
    /// One entry per recipient.
    pub recipient_infos: Vec<RecipientInfo>,
    /// The MAC algorithm.
    pub mac_algorithm: AlgorithmIdentifier,
    /// Optional digest algorithm (when authAttrs carry a message digest).
    pub digest_algorithm: Option<AlgorithmIdentifier>,
    /// The content type and content.
    pub encap_content_info: EncapsulatedContentInfo,
    /// Authenticated attributes.
    pub auth_attrs: Vec<Attribute>,
    /// The MAC value.
    pub mac: Vec<u8>,
    /// Unauthenticated attributes.
    pub unauth_attrs: Vec<Attribute>,
}

impl AuthenticatedData {
    /// Parse a DER `AuthenticatedData`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let data = Self::parse_reader(&mut reader)?;
        reader.expect_end()?;
        Ok(data)
    }

    /// Parse an `AuthenticatedData` from a reader.
    pub fn parse_reader(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let version = u8::try_from(seq.read_integer_i64()?)
            .map_err(|_| CryptoError::StrError("cms: invalid authenticated data version"))?;
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
        let mac_algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        let digest_algorithm =
            if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(1) {
                let mut inner = seq.read_implicit_constructed(1)?;
                let parsed = AlgorithmIdentifier::parse(&mut inner)?;
                inner.expect_end()?;
                Some(parsed)
            } else {
                None
            };
        let encap_content_info = EncapsulatedContentInfo::parse(&mut seq)?;
        let auth_attrs = parse_attribute_set(&mut seq, 2)?;
        let mac = seq.read_octet_string()?.to_vec();
        let unauth_attrs = parse_attribute_set(&mut seq, 3)?;
        seq.expect_end()?;
        Ok(AuthenticatedData {
            version,
            originator_info,
            recipient_infos,
            mac_algorithm,
            digest_algorithm,
            encap_content_info,
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
        content.extend_from_slice(&self.mac_algorithm.encode());
        if let Some(digest) = &self.digest_algorithm {
            content.extend_from_slice(&der::implicit(1, true, &digest.encode()));
        }
        content.extend_from_slice(&self.encap_content_info.encode());
        if !self.auth_attrs.is_empty() {
            content.extend_from_slice(&der::implicit(
                2,
                true,
                &encode_attributes(&self.auth_attrs),
            ));
        }
        content.extend_from_slice(&der::octet_string(&self.mac));
        if !self.unauth_attrs.is_empty() {
            content.extend_from_slice(&der::implicit(
                3,
                true,
                &encode_attributes(&self.unauth_attrs),
            ));
        }
        der::sequence(&content)
    }

    /// Wrap in an `id-ct-authData` `ContentInfo`.
    pub fn to_content_info(&self) -> ContentInfo {
        ContentInfo {
            content_type: oid_of(OID_AUTH_DATA),
            content: self.encode(),
        }
    }

    /// Parse the content of an `id-ct-authData` `ContentInfo`.
    pub fn from_content_info(info: &ContentInfo) -> CryptoResult<Self> {
        super::check_content_type(info, OID_AUTH_DATA, "authenticated data")?;
        Self::parse(&info.content)
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

    /// The encapsulated content, when attached.
    pub fn content(&self) -> CryptoResult<&[u8]> {
        self.encap_content_info
            .content
            .as_deref()
            .ok_or(CryptoError::StrError("cms: content is detached"))
    }

    /// Verify the MAC under an explicit key and return the content.
    pub fn verify_mac(&self, mac_key: &[u8]) -> CryptoResult<Vec<u8>> {
        let content = self.content()?;
        let computed = self.compute_mac(mac_key, content)?;
        if crate::utils::subtle::constant_time_eq(&computed, &self.mac) {
            Ok(content.to_vec())
        } else {
            Err(CryptoError::AuthenticationFailed)
        }
    }

    /// Verify the MAC with the key transported to the recipient matching
    /// `certificate`.
    pub fn verify_with_key(
        &self,
        key: &PrivateKey,
        certificate: &Certificate,
    ) -> CryptoResult<Vec<u8>> {
        for recipient in &self.recipient_infos {
            match recipient {
                RecipientInfo::KeyTrans(info) => {
                    if info.rid.matches(certificate) {
                        return self.verify_mac(&info.decrypt(key)?);
                    }
                }
                RecipientInfo::KeyAgree(info) => {
                    if let Some(mac_key) = info.decrypt(key, certificate)? {
                        return self.verify_mac(&mac_key);
                    }
                }
                _ => {}
            }
        }
        Err(CryptoError::StrError("cms: no matching recipient"))
    }

    /// Verify the MAC with a password recipient.
    pub fn verify_with_password(&self, password: &[u8]) -> CryptoResult<Vec<u8>> {
        for recipient in &self.recipient_infos {
            if let RecipientInfo::Password(info) = recipient {
                return self.verify_mac(&info.decrypt(password)?);
            }
        }
        Err(CryptoError::StrError("cms: no password recipient"))
    }

    /// Verify the MAC with a `kekri` recipient.
    pub fn verify_with_kek(&self, kek: &[u8], key_id: &[u8]) -> CryptoResult<Vec<u8>> {
        for recipient in &self.recipient_infos {
            if let RecipientInfo::Kek(info) = recipient {
                if info.kekid.key_id == key_id {
                    return self.verify_mac(&info.decrypt(kek)?);
                }
            }
        }
        Err(CryptoError::StrError("cms: no matching KEK recipient"))
    }

    /// The MAC input: the content followed by the DER `SET OF` authAttrs.
    pub fn mac_input(&self) -> CryptoResult<Vec<u8>> {
        let mut input = self.content()?.to_vec();
        if !self.auth_attrs.is_empty() {
            input.extend_from_slice(&der::set(&encode_attributes(&self.auth_attrs)));
        }
        Ok(input)
    }

    fn compute_mac(&self, mac_key: &[u8], content: &[u8]) -> CryptoResult<Vec<u8>> {
        let hash = hash_for_mac(&self.mac_algorithm).ok_or_else(|| {
            CryptoError::UnsupportedOperation("cms: unsupported MAC algorithm".into())
        })?;
        let mut message = content.to_vec();
        if !self.auth_attrs.is_empty() {
            message.extend_from_slice(&der::set(&encode_attributes(&self.auth_attrs)));
        }
        hash.hmac(mac_key, &message)
    }
}

/// Builder for `AuthenticatedData`.
#[derive(Debug, Clone)]
pub struct AuthenticatedDataBuilder {
    content: Vec<u8>,
    mac_algorithm: AlgorithmIdentifier,
    digest_algorithm: Option<AlgorithmIdentifier>,
    recipients: Vec<RecipientKind>,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum RecipientKind {
    Rsa { certificate: Certificate },
    Password { password: Vec<u8>, iterations: u32 },
    Kek { kek: Vec<u8>, key_id: Vec<u8> },
}

impl AuthenticatedDataBuilder {
    /// A builder authenticating `content` with HMAC-SHA256.
    pub fn new(content: Vec<u8>) -> Self {
        AuthenticatedDataBuilder {
            content,
            mac_algorithm: mac_algorithm_for(Hash::Sha256),
            digest_algorithm: Some(AlgorithmIdentifier::with_null(
                ObjectIdentifier::new(Hash::Sha256.oid()).expect("static oid"),
            )),
            recipients: Vec::new(),
        }
    }

    /// Use a different MAC algorithm.
    pub fn mac_algorithm(mut self, mac_algorithm: AlgorithmIdentifier) -> Self {
        self.mac_algorithm = mac_algorithm;
        self
    }

    /// Wrap the MAC key to an RSA recipient (PKCS#1 v1.5 key transport).
    pub fn add_rsa_recipient(mut self, certificate: &Certificate) -> Self {
        self.recipients.push(RecipientKind::Rsa {
            certificate: certificate.clone(),
        });
        self
    }

    /// Wrap the MAC key with a password recipient.
    pub fn add_password_recipient(mut self, password: &[u8], iterations: u32) -> Self {
        self.recipients.push(RecipientKind::Password {
            password: password.to_vec(),
            iterations,
        });
        self
    }

    /// Wrap the MAC key with a KEK.
    pub fn add_kek_recipient(mut self, kek: &[u8], key_id: &[u8]) -> Self {
        self.recipients.push(RecipientKind::Kek {
            kek: kek.to_vec(),
            key_id: key_id.to_vec(),
        });
        self
    }

    /// Build the structure.
    pub fn build(self, rng: &mut impl crate::rng::Rng) -> CryptoResult<AuthenticatedData> {
        let hash = hash_for_mac(&self.mac_algorithm).ok_or_else(|| {
            CryptoError::UnsupportedOperation("cms: unsupported MAC algorithm".into())
        })?;
        let mut mac_key = alloc::vec![0u8; hash.output_len()];
        rng.fill_bytes(&mut mac_key);

        let mut recipient_infos = Vec::new();
        for recipient in &self.recipients {
            match recipient {
                RecipientKind::Rsa { certificate } => {
                    let public = match certificate.public_key() {
                        crate::x509::keys::PublicKey::Rsa(key) => key,
                        _ => {
                            return Err(CryptoError::UnsupportedOperation(
                                "cms: RSA recipient required".into(),
                            ));
                        }
                    };
                    let encrypted_key =
                        RsaKeyEncryption::Pkcs1v15.encrypt(public, rng, &mac_key)?;
                    recipient_infos.push(RecipientInfo::KeyTrans(
                        super::recipient::KeyTransRecipientInfo {
                            version: 0,
                            rid: RecipientIdentifier::IssuerAndSerialNumber(
                                IssuerAndSerialNumber::of(certificate),
                            ),
                            key_encryption_algorithm: AlgorithmIdentifier::with_null(
                                ObjectIdentifier::new(crate::asn1::oid::OID_RSA_ENCRYPTION)
                                    .expect("static oid"),
                            ),
                            encrypted_key,
                        },
                    ));
                }
                RecipientKind::Password {
                    password,
                    iterations,
                } => {
                    let info = super::recipient::PasswordRecipientInfo::wrap(
                        password,
                        *iterations,
                        super::Cipher::Aes256Cbc,
                        &mac_key,
                        rng,
                    )?;
                    recipient_infos.push(RecipientInfo::Password(info));
                }
                RecipientKind::Kek { kek, key_id } => {
                    let info = super::recipient::KekRecipientInfo::wrap(kek, key_id, &mac_key)?;
                    recipient_infos.push(RecipientInfo::Kek(info));
                }
            }
        }
        if recipient_infos.is_empty() {
            return Err(CryptoError::StrError("cms: no recipients"));
        }

        let digest_value = hash.digest(&self.content)?;
        let mut attributes = alloc::vec![
            content_type(
                &ObjectIdentifier::new(crate::asn1::oid::OID_PKCS7_DATA).expect("static oid"),
            ),
            message_digest(&digest_value),
        ];
        attributes.sort_by_key(|attribute| attribute.encode());
        let message = {
            let mut message = self.content.clone();
            message.extend_from_slice(&der::set(&encode_attributes(&attributes)));
            message
        };
        let mac = hash.hmac(&mac_key, &message)?;

        Ok(AuthenticatedData {
            version: 0,
            originator_info: None,
            recipient_infos,
            mac_algorithm: self.mac_algorithm,
            digest_algorithm: self.digest_algorithm,
            encap_content_info: EncapsulatedContentInfo {
                content_type: ObjectIdentifier::new(crate::asn1::oid::OID_PKCS7_DATA)
                    .expect("static oid"),
                content: Some(self.content),
            },
            auth_attrs: attributes,
            mac,
            unauth_attrs: Vec::new(),
        })
    }
}

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

fn encode_attributes(attrs: &[Attribute]) -> Vec<u8> {
    let mut content = Vec::new();
    for attribute in attrs {
        content.extend_from_slice(&attribute.encode());
    }
    content
}

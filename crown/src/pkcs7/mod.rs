//! PKCS#7 / CMS: `ContentInfo` and `SignedData`.
//!
//! Parsing, signature verification and creation of the signed-data structures
//! used by S/MIME and CMS. Verification checks the `messageDigest` and
//! `contentType` signed attributes when present and verifies the signature
//! with the signer certificate's public key, including RSA PKCS#1 v1.5/PSS,
//! ECDSA, Ed25519/Ed448, SM2 and DSA.
//!
//! ```
//! use crown::pkcs7::Pkcs7;
//!
//! # let der = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pki/cms_attached.der"));
//! let Pkcs7::SignedData(signed_data) = Pkcs7::parse(der)? else {
//!     unreachable!()
//! };
//! signed_data.verify(None)?;
//! # Ok::<(), crown::error::CryptoError>(())
//! ```
//!
//! `EnvelopedData` (content encryption with RSA/ECDH key transport) is not
//! implemented; only the certificate-related signed-data structures are.

use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::{self, ObjectIdentifier};
use crate::asn1::time::Asn1Time;
use crate::error::{CryptoError, CryptoResult};
use crate::rng::Rng;
use crate::x509::algorithm::{AlgorithmIdentifier, Hash, SignatureAlgorithm};
use crate::x509::attribute::Attribute;
use crate::x509::cert::Certificate;
use crate::x509::crl::CertificateList;
use crate::x509::keys::PrivateKey;
use crate::x509::name::Name;

/// `ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY
/// OPTIONAL }`.
#[derive(Debug, Clone)]
pub struct ContentInfo {
    /// The content type OID.
    pub content_type: ObjectIdentifier,
    /// The raw DER of the content's inner element (never the `[0]` wrapper).
    pub content: Vec<u8>,
}

impl ContentInfo {
    /// Parse a DER `ContentInfo`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let info = Self::parse_reader(&mut reader)?;
        reader.expect_end()?;
        Ok(info)
    }

    /// Parse a `ContentInfo` from a reader.
    pub fn parse_reader(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let content_type = seq.read_oid()?;
        let content = if !seq.is_empty() {
            let mut inner = seq.read_explicit(0)?;
            inner.read_raw_tlv()?.to_vec()
        } else {
            Vec::new()
        };
        seq.expect_end()?;
        Ok(ContentInfo {
            content_type,
            content,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::oid(&self.content_type);
        if !self.content.is_empty() {
            content.extend_from_slice(&der::explicit(0, &self.content));
        }
        der::sequence(&content)
    }

    /// Wrap `id-data` content.
    pub fn data(content: &[u8]) -> Self {
        ContentInfo {
            content_type: ObjectIdentifier::new(oid::OID_PKCS7_DATA).expect("static oid"),
            content: der::octet_string(content),
        }
    }

    /// Whether the content is `id-signedData`.
    pub fn is_signed_data(&self) -> bool {
        self.content_type.matches(oid::OID_PKCS7_SIGNED_DATA)
    }
}

/// `EncapsulatedContentInfo ::= SEQUENCE { eContentType OID, eContent [0]
/// EXPLICIT OCTET STRING OPTIONAL }`.
#[derive(Debug, Clone)]
pub struct EncapsulatedContentInfo {
    /// The encapsulated content type.
    pub content_type: ObjectIdentifier,
    /// The content octets, absent for detached signatures.
    pub content: Option<Vec<u8>>,
}

impl EncapsulatedContentInfo {
    /// Parse an `EncapsulatedContentInfo`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let content_type = seq.read_oid()?;
        let content = if seq.is_empty() {
            None
        } else {
            let mut inner = seq.read_explicit(0)?;
            Some(inner.read_octet_string_owned()?)
        };
        seq.expect_end()?;
        Ok(EncapsulatedContentInfo {
            content_type,
            content,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::oid(&self.content_type);
        if let Some(data) = &self.content {
            content.extend_from_slice(&der::explicit(0, &der::octet_string(data)));
        }
        der::sequence(&content)
    }
}

/// How a signer is identified.
#[derive(Debug, Clone)]
pub enum SignerIdentifier {
    /// `issuerAndSerialNumber`.
    IssuerAndSerialNumber {
        /// Issuer name.
        issuer: Name,
        /// Serial number magnitude.
        serial_number: Vec<u8>,
    },
    /// `subjectKeyIdentifier`.
    SubjectKeyIdentifier(Vec<u8>),
}

/// `SignerInfo`.
#[derive(Debug, Clone)]
pub struct SignerInfo {
    /// CMS version (1 for issuerAndSerialNumber, 3 for SKI).
    pub version: u8,
    /// Signer identifier.
    pub sid: SignerIdentifier,
    /// Digest algorithm.
    pub digest_algorithm: AlgorithmIdentifier,
    /// Parsed signed attributes.
    pub signed_attrs: Option<Vec<Attribute>>,
    /// The signed attributes re-tagged as a DER `SET OF` (the exact bytes the
    /// signature covers).
    pub signed_attrs_der: Option<Vec<u8>>,
    /// Signature algorithm.
    pub signature_algorithm: AlgorithmIdentifier,
    /// The raw signature.
    pub signature: Vec<u8>,
    /// Unsigned attributes.
    pub unsigned_attrs: Vec<Attribute>,
}

impl SignerInfo {
    /// Parse a `SignerInfo`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let version = u8::try_from(seq.read_integer_i64()?)
            .map_err(|_| CryptoError::StrError("pkcs7: invalid signer version"))?;
        let sid = if seq.peek_tag()? == der::SEQUENCE {
            let mut inner = seq.read_sequence()?;
            let issuer = Name::parse(&mut inner)?;
            let serial_number = inner.read_integer()?.to_vec();
            SignerIdentifier::IssuerAndSerialNumber {
                issuer,
                serial_number,
            }
        } else {
            SignerIdentifier::SubjectKeyIdentifier(seq.read_implicit(0, false)?.to_vec())
        };
        let digest_algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        // signedAttrs [0] IMPLICIT SET OF Attribute.
        let (signed_attrs, signed_attrs_der) =
            if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(0) {
                let content = seq.read_implicit(0, true)?;
                let mut attrs = Reader::new(content);
                let mut parsed = Vec::new();
                while !attrs.is_empty() {
                    parsed.push(Attribute::parse(&mut attrs)?);
                }
                // The signature covers the same content with the universal SET
                // tag (CMS section 5.4).
                (Some(parsed), Some(der::set(content)))
            } else {
                (None, None)
            };
        let signature_algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        let signature = seq.read_octet_string()?.to_vec();
        let mut unsigned_attrs = Vec::new();
        if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(1) {
            let mut attrs = seq.read_implicit_constructed(1)?;
            while !attrs.is_empty() {
                unsigned_attrs.push(Attribute::parse(&mut attrs)?);
            }
        }
        seq.expect_end()?;
        Ok(SignerInfo {
            version,
            sid,
            digest_algorithm,
            signed_attrs,
            signed_attrs_der,
            signature_algorithm,
            signature,
            unsigned_attrs,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.version]);
        match &self.sid {
            SignerIdentifier::IssuerAndSerialNumber {
                issuer,
                serial_number,
            } => {
                let mut sid = issuer.encode();
                sid.extend_from_slice(&der::integer(serial_number));
                content.extend_from_slice(&der::sequence(&sid));
            }
            SignerIdentifier::SubjectKeyIdentifier(key_id) => {
                content.extend_from_slice(&der::implicit(0, false, key_id));
            }
        }
        content.extend_from_slice(&self.digest_algorithm.encode());
        if let Some(attrs) = &self.signed_attrs {
            // Prefer the preserved SET OF encoding (it is what the signature
            // covers); fall back to re-encoding the attributes.
            let rebuilt: Vec<u8> = attrs
                .iter()
                .flat_map(|attribute| attribute.encode())
                .collect();
            let set_content = self
                .signed_attrs_der
                .as_deref()
                .and_then(strip_tlv)
                .map(<[u8]>::to_vec)
                .unwrap_or(rebuilt);
            content.extend_from_slice(&der::implicit(0, true, &set_content));
        }
        content.extend_from_slice(&self.signature_algorithm.encode());
        content.extend_from_slice(&der::octet_string(&self.signature));
        if !self.unsigned_attrs.is_empty() {
            let mut set_content = Vec::new();
            for attribute in &self.unsigned_attrs {
                set_content.extend_from_slice(&attribute.encode());
            }
            content.extend_from_slice(&der::implicit(1, true, &set_content));
        }
        der::sequence(&content)
    }
}

/// `SignedData`.
#[derive(Debug, Clone)]
pub struct SignedData {
    /// CMS version.
    pub version: u8,
    /// Digest algorithms used by the signers.
    pub digest_algorithms: Vec<AlgorithmIdentifier>,
    /// The encapsulated content.
    pub encap_content_info: EncapsulatedContentInfo,
    /// Embedded certificates.
    pub certificates: Vec<Certificate>,
    /// Embedded CRLs.
    pub crls: Vec<CertificateList>,
    /// The signers.
    pub signer_infos: Vec<SignerInfo>,
}

impl SignedData {
    /// Parse a `SignedData` (the inner element of an `id-signedData`
    /// `ContentInfo`).
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let signed_data = Self::parse_reader(&mut reader)?;
        reader.expect_end()?;
        Ok(signed_data)
    }

    /// Parse a `SignedData` from a reader.
    pub fn parse_reader(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let version = u8::try_from(seq.read_integer_i64()?)
            .map_err(|_| CryptoError::StrError("pkcs7: invalid version"))?;
        let mut digest_reader = seq.read_set()?;
        let mut digest_algorithms = Vec::new();
        while !digest_reader.is_empty() {
            digest_algorithms.push(AlgorithmIdentifier::parse(&mut digest_reader)?);
        }
        let encap_content_info = EncapsulatedContentInfo::parse(&mut seq)?;
        let mut certificates = Vec::new();
        let mut crls = Vec::new();
        if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(0) {
            let mut inner = seq.read_implicit_constructed(0)?;
            while !inner.is_empty() {
                let raw = inner.read_raw_tlv()?;
                // CertificateChoices also allows attribute certificates
                // ([1]/[2]); only X.509 certificates are decoded.
                let element = Reader::new(raw);
                if element.peek_tag()? == der::SEQUENCE {
                    certificates.push(Certificate::parse(raw)?);
                }
            }
        }
        if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(1) {
            let mut inner = seq.read_implicit_constructed(1)?;
            while !inner.is_empty() {
                crls.push(CertificateList::parse(inner.read_raw_tlv()?)?);
            }
        }
        let mut signers = seq.read_set()?;
        let mut signer_infos = Vec::new();
        while !signers.is_empty() {
            signer_infos.push(SignerInfo::parse(&mut signers)?);
        }
        seq.expect_end()?;
        Ok(SignedData {
            version,
            digest_algorithms,
            encap_content_info,
            certificates,
            crls,
            signer_infos,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.version]);
        let mut digests = Vec::new();
        for algorithm in &self.digest_algorithms {
            digests.extend_from_slice(&algorithm.encode());
        }
        content.extend_from_slice(&der::set(&digests));
        content.extend_from_slice(&self.encap_content_info.encode());
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
        let mut signers = Vec::new();
        for signer in &self.signer_infos {
            signers.extend_from_slice(&signer.encode());
        }
        content.extend_from_slice(&der::set(&signers));
        der::sequence(&content)
    }

    /// Wrap in an `id-signedData` `ContentInfo`.
    pub fn to_content_info(&self) -> ContentInfo {
        ContentInfo {
            content_type: ObjectIdentifier::new(oid::OID_PKCS7_SIGNED_DATA).expect("static oid"),
            content: self.encode(),
        }
    }

    /// The certificate matching a signer identifier, if embedded.
    pub fn certificate_for(&self, sid: &SignerIdentifier) -> Option<&Certificate> {
        self.certificates.iter().find(|certificate| match sid {
            SignerIdentifier::IssuerAndSerialNumber {
                issuer,
                serial_number,
            } => {
                &certificate.tbs().issuer == issuer
                    && certificate.serial_number() == serial_number.as_slice()
            }
            SignerIdentifier::SubjectKeyIdentifier(key_id) => certificate
                .tbs()
                .subject_key_identifier()
                .is_some_and(|id| &id == key_id),
        })
    }

    /// The content to authenticate: embedded content, or `detached` for
    /// detached signatures.
    pub fn content<'a>(&'a self, detached: Option<&'a [u8]>) -> CryptoResult<&'a [u8]> {
        match (&self.encap_content_info.content, detached) {
            (Some(content), _) => Ok(content),
            (None, Some(content)) => Ok(content),
            (None, None) => Err(CryptoError::StrError("pkcs7: detached content missing")),
        }
    }

    /// Verify every signer's signature.
    ///
    /// `detached` must supply the content for detached signatures. SM2
    /// signatures use the GM/T default identity; see
    /// [`Self::verify_with_sm2_id`] to override it.
    pub fn verify(&self, detached: Option<&[u8]>) -> CryptoResult<()> {
        self.verify_with_sm2_id(detached, crate::sm2::DEFAULT_ID)
    }

    /// [`Self::verify`] with an explicit SM2 identity.
    pub fn verify_with_sm2_id(&self, detached: Option<&[u8]>, sm2_id: &[u8]) -> CryptoResult<()> {
        if self.signer_infos.is_empty() {
            return Ok(());
        }
        let content = self.content(detached)?;
        for signer in &self.signer_infos {
            self.verify_signer(signer, content, sm2_id)?;
        }
        Ok(())
    }

    /// Verify one signer against `content`.
    pub fn verify_signer(
        &self,
        signer: &SignerInfo,
        content: &[u8],
        sm2_id: &[u8],
    ) -> CryptoResult<()> {
        let certificate = self
            .certificate_for(&signer.sid)
            .ok_or(CryptoError::StrError("pkcs7: signer certificate not found"))?;
        let hash = Hash::from_oid(&signer.digest_algorithm.oid)
            .ok_or_else(|| CryptoError::UnsupportedOperation("pkcs7: unsupported digest".into()))?;
        let algorithm = SignatureAlgorithm::from_identifier_with_digest(
            &signer.signature_algorithm,
            Some(&signer.digest_algorithm),
        )?;
        match (&signer.signed_attrs, &signer.signed_attrs_der) {
            (Some(attributes), Some(attrs_der)) => {
                // messageDigest must equal the digest of the content.
                let digest_attr = attributes
                    .iter()
                    .find(|attr| attr.oid.matches(oid::OID_PKCS9_MESSAGE_DIGEST))
                    .ok_or(CryptoError::StrError(
                        "pkcs7: messageDigest attribute missing",
                    ))?;
                let expected = hash.digest(content)?;
                let actual = crate::x509::attribute::octet_string_value(digest_attr)?;
                if !crate::utils::subtle::constant_time_eq(&expected, actual) {
                    return Err(CryptoError::AuthenticationFailed);
                }
                // contentType, when present, must match the encapsulated
                // content type.
                if let Some(attr) = attributes
                    .iter()
                    .find(|attr| attr.oid.matches(oid::OID_PKCS9_CONTENT_TYPE))
                {
                    let value = attr
                        .values
                        .first()
                        .ok_or(CryptoError::StrError("pkcs7: empty contentType attribute"))?;
                    let mut reader = Reader::new(value);
                    let content_type = reader.read_oid()?;
                    if content_type != self.encap_content_info.content_type {
                        return Err(CryptoError::AuthenticationFailed);
                    }
                }
                if !algorithm.verify_with_sm2_id(
                    certificate.public_key(),
                    attrs_der,
                    &signer.signature,
                    sm2_id,
                )? {
                    return Err(CryptoError::AuthenticationFailed);
                }
            }
            (None, None) => {
                if !algorithm.verify_with_sm2_id(
                    certificate.public_key(),
                    content,
                    &signer.signature,
                    sm2_id,
                )? {
                    return Err(CryptoError::AuthenticationFailed);
                }
            }
            _ => {
                return Err(CryptoError::StrError(
                    "pkcs7: inconsistent signed attributes",
                ));
            }
        }
        Ok(())
    }
}

/// A parsed PKCS#7 object.
#[derive(Debug, Clone)]
pub enum Pkcs7 {
    /// An `id-signedData` object.
    SignedData(SignedData),
    /// An `id-data` object.
    Data(Vec<u8>),
    /// Any other content type (raw `ContentInfo`).
    Other(ContentInfo),
}

impl Pkcs7 {
    /// Parse a DER PKCS#7 object.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let info = ContentInfo::parse(der)?;
        if info.is_signed_data() {
            return Ok(Pkcs7::SignedData(SignedData::parse(&info.content)?));
        }
        if info.content_type.matches(oid::OID_PKCS7_DATA) {
            let mut reader = Reader::new(&info.content);
            return Ok(Pkcs7::Data(reader.read_octet_string()?.to_vec()));
        }
        Ok(Pkcs7::Other(info))
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Pkcs7::SignedData(signed_data) => signed_data.to_content_info().encode(),
            Pkcs7::Data(content) => ContentInfo::data(content).encode(),
            Pkcs7::Other(info) => info.encode(),
        }
    }
}

/// Builder for `SignedData` with detached or attached content.
#[derive(Debug, Clone)]
pub struct SignedDataBuilder {
    /// Encapsulated content type (defaults to `id-data`).
    pub content_type: ObjectIdentifier,
    /// The content being signed.
    pub content: Vec<u8>,
    /// Whether to omit the eContent (a detached signature).
    pub detached: bool,
    /// Certificates to embed.
    pub certificates: Vec<Certificate>,
    /// Optional signing time attribute.
    pub signing_time: Option<Asn1Time>,
}

impl SignedDataBuilder {
    /// An attached `id-data` builder over `content`.
    pub fn new(content: Vec<u8>) -> Self {
        SignedDataBuilder {
            content_type: ObjectIdentifier::new(oid::OID_PKCS7_DATA).expect("static oid"),
            content,
            detached: false,
            certificates: Vec::new(),
            signing_time: None,
        }
    }

    /// A detached `id-data` builder: the digest covers `content`, but the
    /// eContent is omitted from the message.
    pub fn detached(content: Vec<u8>) -> Self {
        SignedDataBuilder {
            detached: true,
            ..Self::new(content)
        }
    }

    /// Embed a certificate.
    pub fn add_certificate(mut self, certificate: Certificate) -> Self {
        self.certificates.push(certificate);
        self
    }

    /// Set the signing time attribute (included when signing).
    pub fn signing_time(mut self, time: Asn1Time) -> Self {
        self.signing_time = Some(time);
        self
    }

    /// Sign with one signer, producing a single-signer `SignedData`.
    pub fn sign(
        self,
        key: &PrivateKey,
        certificate: &Certificate,
        digest: Hash,
        signature_algorithm: SignatureAlgorithm,
        rng: &mut impl Rng,
    ) -> CryptoResult<SignedData> {
        self.sign_with_sm2_id(
            key,
            certificate,
            digest,
            signature_algorithm,
            crate::sm2::DEFAULT_ID,
            rng,
        )
    }

    /// [`Self::sign`] with an explicit SM2 identity.
    pub fn sign_with_sm2_id(
        self,
        key: &PrivateKey,
        certificate: &Certificate,
        digest: Hash,
        signature_algorithm: SignatureAlgorithm,
        sm2_id: &[u8],
        rng: &mut impl Rng,
    ) -> CryptoResult<SignedData> {
        let content = self.content.clone();
        let digest_value = digest.digest(&content)?;
        let mut attributes = alloc::vec![
            crate::x509::attribute::content_type(&self.content_type),
            crate::x509::attribute::message_digest(&digest_value),
        ];
        if let Some(time) = &self.signing_time {
            attributes.push(crate::x509::attribute::signing_time(time));
        }
        // DER SET OF requires sorting by encoding.
        let mut encoded: Vec<Vec<u8>> = attributes.iter().map(|attr| attr.encode()).collect();
        encoded.sort();
        let set_content: Vec<u8> = encoded.concat();
        let signed_attrs_der = der::set(&set_content);

        let signature =
            key.sign_with_sm2_id(signature_algorithm, &signed_attrs_der, sm2_id, rng)?;

        let sid = SignerIdentifier::IssuerAndSerialNumber {
            issuer: certificate.tbs().issuer.clone(),
            serial_number: certificate.serial_number().to_vec(),
        };
        let signer = SignerInfo {
            version: 1,
            sid,
            digest_algorithm: AlgorithmIdentifier::new(
                ObjectIdentifier::new(digest.oid()).expect("static oid"),
                None,
            ),
            signed_attrs: Some(attributes),
            signed_attrs_der: Some(signed_attrs_der),
            signature_algorithm: signature_algorithm.to_identifier(),
            signature,
            unsigned_attrs: Vec::new(),
        };
        Ok(SignedData {
            version: 1,
            digest_algorithms: alloc::vec![signer.digest_algorithm.clone()],
            encap_content_info: EncapsulatedContentInfo {
                content_type: self.content_type,
                content: if self.detached {
                    None
                } else {
                    Some(self.content)
                },
            },
            certificates: self.certificates,
            crls: Vec::new(),
            signer_infos: alloc::vec![signer],
        })
    }
}

/// Strip a TLV's tag and length, returning its content octets.
fn strip_tlv(der: &[u8]) -> Option<&[u8]> {
    let mut reader = Reader::new(der);
    let (_, content) = reader.read_tlv().ok()?;
    Some(content)
}

#[cfg(test)]
mod tests;

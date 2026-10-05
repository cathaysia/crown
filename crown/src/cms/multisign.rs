//! Multi-signer `SignedData` builder.
//!
//! The single-signer builder lives in [`crate::pkcs7::SignedDataBuilder`];
//! this one assembles any number of signers over one content, each with its
//! own digest/signature algorithm and extra signed attributes.

use alloc::vec::Vec;

use crate::asn1::der;
use crate::asn1::oid::ObjectIdentifier;
use crate::asn1::time::Asn1Time;
use crate::error::CryptoResult;
use crate::pkcs7::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo};
use crate::rng::Rng;
use crate::x509::algorithm::{AlgorithmIdentifier, Hash, SignatureAlgorithm};
use crate::x509::attribute::{content_type, message_digest, signing_time, Attribute};
use crate::x509::cert::Certificate;
use crate::x509::keys::PrivateKey;

/// One signer of a [`SignedDataMultiBuilder`].
#[derive(Debug, Clone)]
pub struct SignerSpec {
    /// The signing key.
    pub key: PrivateKey,
    /// The signer certificate (embedded automatically when missing).
    pub certificate: Certificate,
    /// Content digest algorithm.
    pub digest: Hash,
    /// Signature algorithm.
    pub signature_algorithm: SignatureAlgorithm,
    /// Extra signed attributes.
    pub extra_attributes: Vec<Attribute>,
    /// Optional `signingTime` signed attribute.
    pub signing_time: Option<Asn1Time>,
    /// SM2 identity (defaults to the GM/T value).
    pub sm2_id: Vec<u8>,
}

impl SignerSpec {
    /// A signer with contentType/messageDigest attributes only.
    pub fn new(
        key: PrivateKey,
        certificate: Certificate,
        digest: Hash,
        signature_algorithm: SignatureAlgorithm,
    ) -> Self {
        SignerSpec {
            key,
            certificate,
            digest,
            signature_algorithm,
            extra_attributes: Vec::new(),
            signing_time: None,
            sm2_id: crate::sm2::DEFAULT_ID.to_vec(),
        }
    }

    /// Use an explicit SM2 identity.
    pub fn sm2_id(mut self, sm2_id: Vec<u8>) -> Self {
        self.sm2_id = sm2_id;
        self
    }
}

/// Builder for a `SignedData` with several signers.
#[derive(Debug, Clone)]
pub struct SignedDataMultiBuilder {
    content_type: ObjectIdentifier,
    content: Vec<u8>,
    detached: bool,
    certificates: Vec<Certificate>,
    signers: Vec<SignerSpec>,
}

impl SignedDataMultiBuilder {
    /// An attached `id-data` builder over `content`.
    pub fn new(content: Vec<u8>) -> Self {
        SignedDataMultiBuilder {
            content_type: ObjectIdentifier::new(crate::asn1::oid::OID_PKCS7_DATA)
                .expect("static oid"),
            content,
            detached: false,
            certificates: Vec::new(),
            signers: Vec::new(),
        }
    }

    /// A detached `id-data` builder: the digest covers `content`, but the
    /// eContent is omitted.
    pub fn detached(content: Vec<u8>) -> Self {
        SignedDataMultiBuilder {
            detached: true,
            ..Self::new(content)
        }
    }

    /// Use a different encapsulated content type.
    pub fn content_type(mut self, content_type: ObjectIdentifier) -> Self {
        self.content_type = content_type;
        self
    }

    /// Embed a certificate.
    pub fn add_certificate(mut self, certificate: Certificate) -> Self {
        self.certificates.push(certificate);
        self
    }

    /// Add a signer.
    pub fn add_signer(mut self, signer: SignerSpec) -> Self {
        self.signers.push(signer);
        self
    }

    /// Build and sign.
    pub fn build(&self, rng: &mut impl Rng) -> CryptoResult<SignedData> {
        let mut certificates = self.certificates.clone();
        let mut digest_algorithms: Vec<AlgorithmIdentifier> = Vec::new();
        let mut signer_infos = Vec::new();
        for signer in &self.signers {
            if !certificates
                .iter()
                .any(|certificate| certificate.tbs_der() == signer.certificate.tbs_der())
            {
                certificates.push(signer.certificate.clone());
            }
            let digest_algorithm = AlgorithmIdentifier::with_null(
                ObjectIdentifier::new(signer.digest.oid()).expect("static oid"),
            );
            if !digest_algorithms
                .iter()
                .any(|existing| existing.oid == digest_algorithm.oid)
            {
                digest_algorithms.push(digest_algorithm.clone());
            }
            let digest_value = signer.digest.digest(&self.content)?;
            let mut attributes = alloc::vec![
                content_type(&self.content_type),
                message_digest(&digest_value),
            ];
            if let Some(time) = &signer.signing_time {
                attributes.push(signing_time(time));
            }
            attributes.extend(signer.extra_attributes.iter().cloned());
            // DER SET OF requires sorting by encoding; duplicate OIDs would
            // be invalid, keep the first occurrence.
            attributes.sort_by_key(Attribute::encode);
            attributes.dedup_by_key(|attribute| attribute.oid.clone());
            let encoded: Vec<Vec<u8>> = attributes.iter().map(Attribute::encode).collect();
            let signed_attrs_der = der::set(&encoded.concat());
            let signature = signer.key.sign_with_sm2_id(
                signer.signature_algorithm,
                &signed_attrs_der,
                &signer.sm2_id,
                rng,
            )?;
            signer_infos.push(SignerInfo {
                version: 1,
                sid: SignerIdentifier::IssuerAndSerialNumber {
                    issuer: signer.certificate.issuer().clone(),
                    serial_number: signer.certificate.serial_number().to_vec(),
                },
                digest_algorithm,
                signed_attrs: Some(attributes),
                signed_attrs_der: Some(signed_attrs_der),
                signature_algorithm: signer.signature_algorithm.to_identifier(),
                signature,
                unsigned_attrs: Vec::new(),
            });
        }
        if signer_infos.is_empty() {
            return Err(crate::error::CryptoError::StrError("cms: no signers"));
        }
        Ok(SignedData {
            version: 1,
            digest_algorithms,
            encap_content_info: EncapsulatedContentInfo {
                content_type: self.content_type.clone(),
                content: (!self.detached).then(|| self.content.clone()),
            },
            certificates,
            crls: Vec::new(),
            signer_infos,
        })
    }
}

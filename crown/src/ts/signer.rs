//! Timestamp authority signing (RFC 3161 token generation).

use alloc::vec;
use alloc::vec::Vec;

use crate::asn1::der;
use crate::asn1::oid::ObjectIdentifier;
use crate::asn1::time::Asn1Time;
use crate::error::CryptoResult;
use crate::pkcs7::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo};
use crate::rng::Rng;
use crate::x509::algorithm::{AlgorithmIdentifier, Hash, SignatureAlgorithm};
use crate::x509::attribute::{self, Attribute};
use crate::x509::cert::Certificate;
use crate::x509::extensions::GeneralName;
use crate::x509::keys::PrivateKey;

use super::ess::SigningCertificateV2;
use super::request::TimeStampReq;
use super::response::{PkiStatusInfo, TimeStampResp};
use super::tst_info::{Accuracy, TstInfo};
use super::{oid_of, OID_PKCS9_SIGNING_TIME};

/// A timestamp authority: a certificate, its private key, an optional chain
/// and the signature algorithm used for tokens.
///
/// ```
/// use crown::ts::TimeStampSigner;
/// use crown::x509::algorithm::{Hash, SignatureAlgorithm};
/// use crown::x509::cert::Certificate;
/// use crown::x509::keys::{PrivateKey, PrivateKeyInfo};
///
/// # let cert_pem = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pki/ts_tsa.pem"));
/// # let key_pem = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pki/ts_tsa_key.pem"));
/// # struct ZeroRng;
/// # impl crown::rng::Rng for ZeroRng {
/// #     fn fill_bytes(&mut self, out: &mut [u8]) { out.fill(0); }
/// # }
/// let certificate = Certificate::from_pem(cert_pem)?;
/// let key_der = crown::asn1::pem::parse_first(key_pem)?.data;
/// let key = PrivateKeyInfo::parse(&key_der)?.decode()?;
/// let signer = TimeStampSigner::new(
///     certificate,
///     key,
///     Vec::new(),
///     SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
/// );
/// # let _ = signer;
/// # Ok::<(), crown::error::CryptoError>(())
/// ```
#[derive(Debug, Clone)]
pub struct TimeStampSigner {
    certificate: Certificate,
    key: PrivateKey,
    chain: Vec<Certificate>,
    algorithm: SignatureAlgorithm,
    signing_time: Option<Asn1Time>,
}

impl TimeStampSigner {
    /// Create a signer.
    pub fn new(
        certificate: Certificate,
        key: PrivateKey,
        chain: Vec<Certificate>,
        algorithm: SignatureAlgorithm,
    ) -> Self {
        TimeStampSigner {
            certificate,
            key,
            chain,
            algorithm,
            signing_time: None,
        }
    }

    /// Also include a `signingTime` signed attribute with the given value.
    pub fn signing_time(mut self, time: Asn1Time) -> Self {
        self.signing_time = Some(time);
        self
    }

    /// The TSA certificate.
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// Build and sign a token for `request`.
    ///
    /// The token is a CMS `SignedData` whose encapsulated content type is
    /// `id-ct-TSTInfo`, with `contentType`, `messageDigest`,
    /// `signingCertificateV2` and (when configured) `signingTime` signed
    /// attributes. The digest algorithm is the request's message imprint
    /// hash; for digest-based schemes it also replaces the hash component of
    /// the configured signature algorithm. `rng` is used only by randomized
    /// signature schemes.
    pub fn reply(
        &self,
        request: &TimeStampReq,
        policy: ObjectIdentifier,
        serial: &[u8],
        gen_time: Asn1Time,
        accuracy: Option<Accuracy>,
        rng: &mut impl Rng,
    ) -> CryptoResult<TimeStampResp> {
        let hash = request.message_imprint.hash()?;
        // CMS carries the digest separately from the signature algorithm: the
        // request's imprint hash selects the digest the token is signed with.
        let signing_algorithm = signature_algorithm_for(self.algorithm, hash);
        let info = TstInfo {
            version: 1,
            policy,
            message_imprint: request.message_imprint.clone(),
            serial_number: serial.to_vec(),
            gen_time,
            accuracy,
            ordering: false,
            nonce: request.nonce.clone(),
            tsa: Some(GeneralName::DirectoryName(
                self.certificate.subject().clone(),
            )),
            extensions: None,
        };
        let econtent = info.encode();
        let digest_value = hash.digest(&econtent)?;

        let mut attributes = vec![
            attribute::content_type(&super::response::tst_info_oid()),
            attribute::message_digest(&digest_value),
            SigningCertificateV2::from_certificate(&self.certificate)?.to_attribute(),
        ];
        if let Some(time) = &self.signing_time {
            attributes.push(Attribute::new(
                oid_of(OID_PKCS9_SIGNING_TIME),
                vec![der::time(time)],
            ));
        }
        // DER SET OF requires sorting the encodings.
        let mut encoded: Vec<Vec<u8>> = attributes.iter().map(Attribute::encode).collect();
        encoded.sort();
        let set_content: Vec<u8> = encoded.concat();
        let signed_attrs_der = der::set(&set_content);

        let signature = self.key.sign_with_sm2_id(
            signing_algorithm,
            &signed_attrs_der,
            crate::sm2::DEFAULT_ID,
            rng,
        )?;
        let signer = SignerInfo {
            version: 1,
            sid: SignerIdentifier::IssuerAndSerialNumber {
                issuer: self.certificate.tbs().issuer.clone(),
                serial_number: self.certificate.serial_number().to_vec(),
            },
            digest_algorithm: request.message_imprint.hash_algorithm.clone(),
            signed_attrs: Some(attributes),
            signed_attrs_der: Some(signed_attrs_der),
            signature_algorithm: signature_identifier(signing_algorithm),
            signature,
            unsigned_attrs: Vec::new(),
        };
        let mut certificates = vec![self.certificate.clone()];
        for certificate in &self.chain {
            if !certificates
                .iter()
                .any(|existing| existing.encode() == certificate.encode())
            {
                certificates.push(certificate.clone());
            }
        }
        let signed_data = SignedData {
            // Version 3 because the encapsulated content type is not id-data.
            version: 3,
            digest_algorithms: vec![signer.digest_algorithm.clone()],
            encap_content_info: EncapsulatedContentInfo {
                content_type: super::response::tst_info_oid(),
                content: Some(econtent),
            },
            certificates,
            crls: Vec::new(),
            signer_infos: vec![signer],
        };
        Ok(TimeStampResp {
            status: PkiStatusInfo::granted(),
            time_stamp_token: Some(signed_data.to_content_info()),
        })
    }
}

/// Combine the configured signature scheme with the request's digest.
///
/// For the digest-based schemes the hash carried by the request's message
/// imprint replaces the one the signer was configured with; Ed25519/Ed448
/// (which sign the message directly) keep their identifier.
fn signature_algorithm_for(algorithm: SignatureAlgorithm, hash: Hash) -> SignatureAlgorithm {
    match algorithm {
        SignatureAlgorithm::RsaPkcs1v15(_) => SignatureAlgorithm::RsaPkcs1v15(hash),
        SignatureAlgorithm::RsaPss { salt_len, .. } => {
            SignatureAlgorithm::RsaPss { hash, salt_len }
        }
        SignatureAlgorithm::Ecdsa(_) => SignatureAlgorithm::Ecdsa(hash),
        SignatureAlgorithm::Dsa(_) => SignatureAlgorithm::Dsa(hash),
        other => other,
    }
}

/// The CMS `signatureAlgorithm` for a signature algorithm.
///
/// CMS uses `rsaEncryption` for RSA PKCS#1 v1.5 (RFC 5652 section 5.3); all
/// other algorithms use their usual identifier.
fn signature_identifier(algorithm: SignatureAlgorithm) -> AlgorithmIdentifier {
    match algorithm {
        SignatureAlgorithm::RsaPkcs1v15(_) => {
            AlgorithmIdentifier::with_null(oid_of(crate::asn1::oid::OID_RSA_ENCRYPTION))
        }
        other => other.to_identifier(),
    }
}

//! X.509 certificates: parsing, encoding, signing and verification.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid;
use crate::asn1::pem;
use crate::asn1::time::Asn1Time;
use crate::error::{CryptoError, CryptoResult};
use crate::rng::Rng;

use super::algorithm::{AlgorithmIdentifier, Hash, SignatureAlgorithm};
use super::extensions::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, Extension, GeneralName, KeyUsage,
    ParsedExtension,
};
use super::keys::{PrivateKey, PublicKey, SubjectPublicKeyInfo};
use super::name::Name;

/// Certificate validity period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    /// `notBefore`.
    pub not_before: Asn1Time,
    /// `notAfter`.
    pub not_after: Asn1Time,
}

impl Validity {
    /// Whether the Unix timestamp `now` falls inside the window.
    pub fn contains(&self, now: i64) -> bool {
        self.not_before.to_unix() <= now && now <= self.not_after.to_unix()
    }
}

/// The parsed `TBSCertificate`.
#[derive(Debug, Clone)]
pub struct TbsCertificate {
    /// Version: 0 = v1, 1 = v2, 2 = v3.
    pub version: u8,
    /// Serial number magnitude.
    pub serial_number: Vec<u8>,
    /// The inner signature algorithm (must match the outer one).
    pub signature: AlgorithmIdentifier,
    /// Issuer name.
    pub issuer: Name,
    /// Validity window.
    pub validity: Validity,
    /// Subject name.
    pub subject: Name,
    /// Subject public key.
    pub subject_public_key_info: SubjectPublicKeyInfo,
    /// `issuerUniqueID` BIT STRING payload.
    pub issuer_unique_id: Option<Vec<u8>>,
    /// `subjectUniqueID` BIT STRING payload.
    pub subject_unique_id: Option<Vec<u8>>,
    /// The v3 extensions.
    pub extensions: Vec<Extension>,
}

impl TbsCertificate {
    /// Parse a `TBSCertificate`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let version = if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(0) {
            let mut inner = seq.read_explicit(0)?;
            inner.read_integer_i64()? as u8
        } else {
            0
        };
        if version > 2 {
            return Err(CryptoError::StrError(
                "x509: unsupported certificate version",
            ));
        }
        let serial_number = seq.read_integer()?.to_vec();
        let signature = AlgorithmIdentifier::parse(&mut seq)?;
        let issuer = Name::parse(&mut seq)?;
        let mut validity_reader = seq.read_sequence()?;
        let not_before = validity_reader.read_time()?;
        let not_after = validity_reader.read_time()?;
        validity_reader.expect_end()?;
        let subject = Name::parse(&mut seq)?;
        let spki_raw = seq.read_raw_tlv()?;
        let subject_public_key_info = SubjectPublicKeyInfo::parse(spki_raw)?;
        let mut issuer_unique_id = None;
        let mut subject_unique_id = None;
        let mut extensions = Vec::new();
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            match tag {
                t if t == der::Tag::context(1) => {
                    issuer_unique_id = Some(read_unique_id(&mut seq, 1)?);
                }
                t if t == der::Tag::context(2) => {
                    subject_unique_id = Some(read_unique_id(&mut seq, 2)?);
                }
                t if t == der::Tag::context_constructed(3) => {
                    let mut inner = seq.read_explicit(3)?;
                    let mut ext_reader = inner.read_sequence()?;
                    while !ext_reader.is_empty() {
                        extensions.push(Extension::parse(&mut ext_reader)?);
                    }
                }
                _ => return Err(CryptoError::StrError("x509: invalid TBSCertificate")),
            }
        }
        Ok(TbsCertificate {
            version,
            serial_number,
            signature,
            issuer,
            validity: Validity {
                not_before,
                not_after,
            },
            subject,
            subject_public_key_info,
            issuer_unique_id,
            subject_unique_id,
            extensions,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        if self.version != 0 {
            content.extend_from_slice(&der::explicit(0, &der::integer(&[self.version])));
        }
        content.extend_from_slice(&der::integer(&self.serial_number));
        content.extend_from_slice(&self.signature.encode());
        content.extend_from_slice(&self.issuer.encode());
        let mut validity = der::time(&self.validity.not_before);
        validity.extend_from_slice(&der::time(&self.validity.not_after));
        content.extend_from_slice(&der::sequence(&validity));
        content.extend_from_slice(&self.subject.encode());
        content.extend_from_slice(&self.subject_public_key_info.encode());
        if let Some(id) = &self.issuer_unique_id {
            content.extend_from_slice(&der::implicit(1, false, &der::bit_string_payload(id)));
        }
        if let Some(id) = &self.subject_unique_id {
            content.extend_from_slice(&der::implicit(2, false, &der::bit_string_payload(id)));
        }
        if !self.extensions.is_empty() {
            let mut exts_content = Vec::new();
            for extension in &self.extensions {
                exts_content.extend_from_slice(&extension.encode());
            }
            content.extend_from_slice(&der::explicit(3, &der::sequence(&exts_content)));
        }
        der::sequence(&content)
    }

    /// The extension with the given OID.
    pub fn extension(&self, arcs: &[u64]) -> Option<&Extension> {
        self.extensions.iter().find(|ext| ext.oid.matches(arcs))
    }

    /// The parsed `basicConstraints` extension, when present.
    pub fn basic_constraints(&self) -> Option<BasicConstraints> {
        match self.extension(oid::OID_BASIC_CONSTRAINTS)?.parsed().ok()? {
            ParsedExtension::BasicConstraints(value) => Some(value),
            _ => None,
        }
    }

    /// The parsed `keyUsage` extension, when present.
    pub fn key_usage(&self) -> Option<KeyUsage> {
        match self.extension(oid::OID_KEY_USAGE)?.parsed().ok()? {
            ParsedExtension::KeyUsage(value) => Some(value),
            _ => None,
        }
    }

    /// The parsed `extKeyUsage` extension, when present.
    pub fn extended_key_usage(&self) -> Option<ExtendedKeyUsage> {
        match self.extension(oid::OID_EXTENDED_KEY_USAGE)?.parsed().ok()? {
            ParsedExtension::ExtendedKeyUsage(value) => Some(value),
            _ => None,
        }
    }

    /// The parsed `subjectAltName` extension, when present.
    pub fn subject_alt_names(&self) -> Option<Vec<GeneralName>> {
        match self.extension(oid::OID_SUBJECT_ALT_NAME)?.parsed().ok()? {
            ParsedExtension::SubjectAltName(value) => Some(value),
            _ => None,
        }
    }

    /// The parsed `subjectKeyIdentifier` extension, when present.
    pub fn subject_key_identifier(&self) -> Option<Vec<u8>> {
        match self
            .extension(oid::OID_SUBJECT_KEY_IDENTIFIER)?
            .parsed()
            .ok()?
        {
            ParsedExtension::SubjectKeyIdentifier(value) => Some(value),
            _ => None,
        }
    }

    /// The parsed `authorityKeyIdentifier` extension, when present.
    pub fn authority_key_identifier(&self) -> Option<AuthorityKeyIdentifier> {
        match self
            .extension(oid::OID_AUTHORITY_KEY_IDENTIFIER)?
            .parsed()
            .ok()?
        {
            ParsedExtension::AuthorityKeyIdentifier(value) => Some(value),
            _ => None,
        }
    }

    /// Whether the certificate claims to be a CA.
    pub fn is_ca(&self) -> bool {
        self.basic_constraints().is_some_and(|bc| bc.ca)
    }
}

/// An X.509 certificate.
#[derive(Debug, Clone)]
pub struct Certificate {
    tbs: TbsCertificate,
    signature_algorithm: AlgorithmIdentifier,
    signature: Vec<u8>,
    tbs_raw: Vec<u8>,
}

impl Certificate {
    /// Parse a DER certificate.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let tbs_raw = seq.read_raw_tlv()?.to_vec();
        let tbs = TbsCertificate::parse(&tbs_raw)?;
        let signature_algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        let signature = seq.read_bit_string_bytes()?.to_vec();
        seq.expect_end()?;
        reader.expect_end()?;
        Ok(Certificate {
            tbs,
            signature_algorithm,
            signature,
            tbs_raw,
        })
    }

    /// Parse a PEM certificate.
    pub fn from_pem(pem_text: &str) -> CryptoResult<Self> {
        let block = pem::parse_first(pem_text)?;
        if block.label != "CERTIFICATE" && block.label != "X509 CERTIFICATE" {
            return Err(CryptoError::StrError("x509: not a certificate PEM block"));
        }
        Self::parse(&block.data)
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.tbs_raw.clone();
        content.extend_from_slice(&self.signature_algorithm.encode());
        content.extend_from_slice(&der::bit_string(0, &self.signature));
        der::sequence(&content)
    }

    /// Encode as PEM.
    pub fn to_pem(&self) -> String {
        pem::encode("CERTIFICATE", &self.encode())
    }

    /// The parsed `TBSCertificate`.
    pub fn tbs(&self) -> &TbsCertificate {
        &self.tbs
    }

    /// The exact DER bytes of the signed `TBSCertificate`.
    pub fn tbs_der(&self) -> &[u8] {
        &self.tbs_raw
    }

    /// The outer signature algorithm identifier.
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// The raw signature.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Convenience: the subject name.
    pub fn subject(&self) -> &Name {
        &self.tbs.subject
    }

    /// Convenience: the issuer name.
    pub fn issuer(&self) -> &Name {
        &self.tbs.issuer
    }

    /// Convenience: the serial number magnitude.
    pub fn serial_number(&self) -> &[u8] {
        &self.tbs.serial_number
    }

    /// Convenience: the validity window.
    pub fn validity(&self) -> Validity {
        self.tbs.validity
    }

    /// Convenience: the extensions.
    pub fn extensions(&self) -> &[Extension] {
        &self.tbs.extensions
    }

    /// Convenience: the subject public key info.
    pub fn subject_public_key_info(&self) -> &SubjectPublicKeyInfo {
        &self.tbs.subject_public_key_info
    }

    /// Convenience: the decoded subject public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.tbs.subject_public_key_info.public_key
    }

    /// Whether subject and issuer are the same name.
    pub fn is_self_signed(&self) -> bool {
        self.tbs.subject == self.tbs.issuer
    }

    /// A digest (fingerprint) over the DER encoding.
    pub fn fingerprint(&self, hash: Hash) -> CryptoResult<Vec<u8>> {
        hash.digest(&self.encode())
    }

    /// Verify this certificate's signature with an issuer public key.
    ///
    /// SM2 signatures use the GM/T default identity; see
    /// [`Self::verify_signature_with_sm2_id`] to override it (OpenSSL's
    /// provider CLI signs with an empty ID unless `distid` is set).
    pub fn verify_signature(&self, issuer: &PublicKey) -> CryptoResult<bool> {
        self.verify_signature_with_sm2_id(issuer, crate::sm2::DEFAULT_ID)
    }

    /// Verify this certificate's signature with an explicit SM2 identity.
    pub fn verify_signature_with_sm2_id(
        &self,
        issuer: &PublicKey,
        sm2_id: &[u8],
    ) -> CryptoResult<bool> {
        if self.tbs.signature != self.signature_algorithm {
            return Ok(false);
        }
        let algorithm = SignatureAlgorithm::from_identifier(&self.tbs.signature)?;
        algorithm.verify_with_sm2_id(issuer, &self.tbs_raw, &self.signature, sm2_id)
    }

    /// Verify this certificate against its issuer: name chaining, validity
    /// window (when `now` is given), CA basic constraints/key usage on the
    /// issuer, and the signature.
    ///
    /// This is the certificate-level check, not a full RFC 5280 path
    /// validation (no name constraints, policies, or revocation).
    pub fn verify(&self, issuer: &Certificate, now: Option<i64>) -> CryptoResult<()> {
        self.verify_with_sm2_id(issuer, now, crate::sm2::DEFAULT_ID)
    }

    /// [`Self::verify`] with an explicit SM2 identity.
    pub fn verify_with_sm2_id(
        &self,
        issuer: &Certificate,
        now: Option<i64>,
        sm2_id: &[u8],
    ) -> CryptoResult<()> {
        if self.tbs.issuer != issuer.tbs.subject {
            return Err(CryptoError::StrError("x509: issuer name mismatch"));
        }
        if let Some(now) = now {
            if !self.tbs.validity.contains(now) {
                return Err(CryptoError::StrError(
                    "x509: certificate expired or not yet valid",
                ));
            }
        }
        let issuer_bc = issuer.tbs.basic_constraints();
        if issuer_bc.is_some_and(|bc| !bc.ca) {
            return Err(CryptoError::StrError("x509: issuer is not a CA"));
        }
        if issuer_bc.is_none() && issuer.tbs.version >= 2 && issuer.tbs.key_usage().is_some() {
            return Err(CryptoError::StrError("x509: issuer is not a CA"));
        }
        if issuer.tbs.key_usage().is_some_and(|ku| !ku.key_cert_sign) {
            return Err(CryptoError::StrError(
                "x509: issuer key usage forbids signing",
            ));
        }
        if !self.verify_signature_with_sm2_id(issuer.public_key(), sm2_id)? {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }

    /// Build a self-signed certificate.
    pub fn self_signed(
        subject: Name,
        signature_algorithm: SignatureAlgorithm,
        key: &PrivateKey,
        not_before: Asn1Time,
        not_after: Asn1Time,
        extensions: Vec<Extension>,
        rng: &mut impl Rng,
    ) -> CryptoResult<Self> {
        let spki = SubjectPublicKeyInfo::from_public_key(&key.public_key()?)?;
        let mut builder = CertificateBuilder::new(subject.clone(), spki, signature_algorithm);
        builder.issuer = subject;
        builder.not_before = not_before;
        builder.not_after = not_after;
        builder.extensions = extensions;
        builder.sign(key, rng)
    }
}

/// Builder for certificates signed by a [`PrivateKey`].
#[derive(Debug, Clone)]
pub struct CertificateBuilder {
    /// Version: 0 = v1, 1 = v2, 2 = v3.
    pub version: u8,
    /// Serial number magnitude.
    pub serial_number: Vec<u8>,
    /// Issuer name.
    pub issuer: Name,
    /// Subject name.
    pub subject: Name,
    /// `notBefore`.
    pub not_before: Asn1Time,
    /// `notAfter`.
    pub not_after: Asn1Time,
    /// Subject public key.
    pub subject_public_key_info: SubjectPublicKeyInfo,
    /// Extensions.
    pub extensions: Vec<Extension>,
    /// Signature algorithm.
    pub signature_algorithm: SignatureAlgorithm,
}

impl CertificateBuilder {
    /// A v3 builder with a default serial number of 1 and a validity window
    /// of 2020-01-01 .. 2049-12-31 (callers normally override both).
    pub fn new(
        subject: Name,
        subject_public_key_info: SubjectPublicKeyInfo,
        signature_algorithm: SignatureAlgorithm,
    ) -> Self {
        CertificateBuilder {
            version: 2,
            serial_number: vec![1],
            issuer: subject.clone(),
            subject,
            not_before: Asn1Time::parse_utc(b"200101000000Z").expect("static time"),
            not_after: Asn1Time::parse_utc(b"491231235959Z").expect("static time"),
            subject_public_key_info,
            extensions: Vec::new(),
            signature_algorithm,
        }
    }

    /// Set the serial number from a positive integer magnitude.
    pub fn serial(mut self, serial_number: Vec<u8>) -> Self {
        self.serial_number = serial_number;
        self
    }

    /// Set the validity window.
    pub fn validity(mut self, not_before: Asn1Time, not_after: Asn1Time) -> Self {
        self.not_before = not_before;
        self.not_after = not_after;
        self
    }

    /// Set the issuer name.
    pub fn issuer(mut self, issuer: Name) -> Self {
        self.issuer = issuer;
        self
    }

    /// Add an extension.
    pub fn extension(mut self, extension: Extension) -> Self {
        self.extensions.push(extension);
        self
    }

    /// Build the TBS structure and sign it.
    pub fn sign(self, key: &PrivateKey, rng: &mut impl Rng) -> CryptoResult<Certificate> {
        let signature = self.signature_algorithm.to_identifier();
        let tbs = TbsCertificate {
            version: self.version,
            serial_number: self.serial_number.clone(),
            signature: signature.clone(),
            issuer: self.issuer.clone(),
            validity: Validity {
                not_before: self.not_before,
                not_after: self.not_after,
            },
            subject: self.subject.clone(),
            subject_public_key_info: self.subject_public_key_info.clone(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: self.extensions.clone(),
        };
        let tbs_raw = tbs.encode();
        let signature_value = self.signature_algorithm.sign(key, &tbs_raw, rng)?;
        Ok(Certificate {
            tbs,
            signature_algorithm: signature,
            signature: signature_value,
            tbs_raw,
        })
    }
}

/// Read an `[n] IMPLICIT BIT STRING` unique-id field.
fn read_unique_id(reader: &mut Reader<'_>, number: u32) -> CryptoResult<Vec<u8>> {
    let content = reader.read_implicit(number, false)?;
    let (unused, data) = content
        .split_first()
        .ok_or(CryptoError::StrError("x509: empty unique id"))?;
    if *unused != 0 {
        return Err(CryptoError::StrError("x509: unsupported unique id padding"));
    }
    Ok(data.to_vec())
}

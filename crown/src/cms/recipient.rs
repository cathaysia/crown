//! `RecipientInfo` variants: key transport (RSA), key agreement (ECDH),
//! KEK and password recipients.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid;
use crate::asn1::time::Asn1Time;
use crate::ec::{self, CurveId, Point};
use crate::ecdh;
use crate::error::{CryptoError, CryptoResult};
use crate::kdf::sskdf::x963_derive_hash;
use crate::rng::Rng;
use crate::rsa::{RsaPrivateKey, RsaPublicKey};
use crate::x509::algorithm::{AlgorithmIdentifier, Hash};
use crate::x509::cert::Certificate;
use crate::x509::keys::{PrivateKey, PublicKey};
use crate::x509::name::Name;

use super::cipher::{Cipher, KekCipher, KeyWrapAlgorithm};
use super::{
    oid_of, OID_DH_STD_SHA1, OID_DH_STD_SHA224, OID_DH_STD_SHA256, OID_DH_STD_SHA384,
    OID_DH_STD_SHA512, OID_RSAES_OAEP,
};

/// `hmacWithSHA224` (1.2.840.113549.2.8).
const OID_HMAC_SHA224: &[u64] = &[1, 2, 840, 113549, 2, 8];

/// `IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerAndSerialNumber {
    /// Issuer name.
    pub issuer: Name,
    /// Serial number magnitude.
    pub serial_number: Vec<u8>,
}

impl IssuerAndSerialNumber {
    /// Parse an `IssuerAndSerialNumber`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let issuer = Name::parse(&mut seq)?;
        let serial_number = seq.read_integer()?.to_vec();
        seq.expect_end()?;
        Ok(IssuerAndSerialNumber {
            issuer,
            serial_number,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.issuer.encode();
        content.extend_from_slice(&der::integer(&self.serial_number));
        der::sequence(&content)
    }

    /// Whether the issuer and serial match `certificate`.
    pub fn matches(&self, certificate: &Certificate) -> bool {
        certificate.tbs().issuer == self.issuer
            && certificate.serial_number() == self.serial_number.as_slice()
    }

    /// The identifier of `certificate`.
    pub fn of(certificate: &Certificate) -> Self {
        IssuerAndSerialNumber {
            issuer: certificate.tbs().issuer.clone(),
            serial_number: certificate.serial_number().to_vec(),
        }
    }
}

/// `RecipientIdentifier ::= CHOICE { issuerAndSerialNumber, [0]
/// subjectKeyIdentifier }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientIdentifier {
    /// `issuerAndSerialNumber`.
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    /// `[0] subjectKeyIdentifier`.
    SubjectKeyIdentifier(Vec<u8>),
}

impl RecipientIdentifier {
    /// Parse a `RecipientIdentifier`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        if reader.peek_tag()? == der::SEQUENCE {
            Ok(RecipientIdentifier::IssuerAndSerialNumber(
                IssuerAndSerialNumber::parse(reader)?,
            ))
        } else {
            Ok(RecipientIdentifier::SubjectKeyIdentifier(
                reader.read_implicit(0, false)?.to_vec(),
            ))
        }
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RecipientIdentifier::IssuerAndSerialNumber(value) => value.encode(),
            RecipientIdentifier::SubjectKeyIdentifier(key_id) => der::implicit(0, false, key_id),
        }
    }

    /// Whether this identifier matches `certificate`.
    pub fn matches(&self, certificate: &Certificate) -> bool {
        match self {
            RecipientIdentifier::IssuerAndSerialNumber(value) => value.matches(certificate),
            RecipientIdentifier::SubjectKeyIdentifier(key_id) => certificate
                .tbs()
                .subject_key_identifier()
                .is_some_and(|id| &id == key_id),
        }
    }
}

/// RSA key-encryption algorithm for `ktri` recipients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKeyEncryption {
    /// `rsaEncryption` (PKCS#1 v1.5).
    Pkcs1v15,
    /// `id-RSAES-OAEP` with the given hash (MGF1 uses the same hash).
    Oaep {
        /// OAEP hash algorithm.
        hash: Hash,
    },
}

impl RsaKeyEncryption {
    /// Parse a `keyEncryptionAlgorithm`.
    pub fn parse(alg: &AlgorithmIdentifier) -> CryptoResult<Self> {
        if alg.oid.matches(oid::OID_RSA_ENCRYPTION) {
            Ok(RsaKeyEncryption::Pkcs1v15)
        } else if alg.oid.matches(OID_RSAES_OAEP) {
            Ok(RsaKeyEncryption::Oaep {
                hash: parse_oaep_parameters(alg.parameters.as_deref())?,
            })
        } else {
            Err(CryptoError::UnsupportedOperation(alloc::format!(
                "cms: unsupported key encryption algorithm {}",
                alg.oid
            )))
        }
    }

    /// The matching `AlgorithmIdentifier`.
    pub fn to_identifier(self) -> AlgorithmIdentifier {
        match self {
            RsaKeyEncryption::Pkcs1v15 => {
                AlgorithmIdentifier::with_null(oid_of(oid::OID_RSA_ENCRYPTION))
            }
            RsaKeyEncryption::Oaep { hash } => {
                let hash_alg = AlgorithmIdentifier::with_null(oid_of(hash.oid()));
                let mut params = der::explicit(0, &hash_alg.encode());
                let mgf1 = AlgorithmIdentifier::new(oid_of(oid::OID_MGF1), Some(hash_alg.encode()));
                params.extend_from_slice(&der::explicit(1, &mgf1.encode()));
                AlgorithmIdentifier::new(oid_of(OID_RSAES_OAEP), Some(der::sequence(&params)))
            }
        }
    }

    /// Encrypt `cek` to an RSA public key.
    pub fn encrypt(
        self,
        key: &RsaPublicKey,
        rng: &mut impl Rng,
        cek: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        match self {
            RsaKeyEncryption::Pkcs1v15 => key.encrypt_pkcs1v15(rng, cek),
            RsaKeyEncryption::Oaep { hash } => key.encrypt_oaep(hash.factory(), rng, cek),
        }
    }

    /// Decrypt a `ktri` encrypted key with an RSA private key.
    pub fn decrypt(self, key: &RsaPrivateKey, encrypted_key: &[u8]) -> CryptoResult<Vec<u8>> {
        match self {
            RsaKeyEncryption::Pkcs1v15 => key.decrypt_pkcs1v15(encrypted_key),
            RsaKeyEncryption::Oaep { hash } => key.decrypt_oaep(hash.factory(), encrypted_key),
        }
    }
}

/// Parse `RSAES-OAEP-params`, returning the OAEP hash.
fn parse_oaep_parameters(params: Option<&[u8]>) -> CryptoResult<Hash> {
    let mut hash = Hash::Sha1;
    let mut mgf_hash = Hash::Sha1;
    if let Some(params) = params {
        let mut reader = Reader::new(params);
        let mut seq = reader.read_sequence()?;
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            match tag.number {
                0 => {
                    let mut inner = seq.read_explicit(0)?;
                    let alg = AlgorithmIdentifier::parse(&mut inner)?;
                    hash = oaep_hash(&alg)?;
                }
                1 => {
                    let mut inner = seq.read_explicit(1)?;
                    let alg = AlgorithmIdentifier::parse(&mut inner)?;
                    if !alg.oid.matches(oid::OID_MGF1) {
                        return Err(CryptoError::UnsupportedOperation(
                            "cms: unsupported OAEP mask generation function".to_string(),
                        ));
                    }
                    let mgf_params = alg
                        .parameters
                        .as_deref()
                        .ok_or(CryptoError::StrError("cms: missing OAEP MGF1 parameters"))?;
                    let mut mgf_reader = Reader::new(mgf_params);
                    mgf_hash = oaep_hash(&AlgorithmIdentifier::parse(&mut mgf_reader)?)?;
                }
                2 => {
                    // pSourceAlgorithm; only id-pSpecified with an empty
                    // label is supported.
                    let mut inner = seq.read_explicit(2)?;
                    let alg = AlgorithmIdentifier::parse(&mut inner)?;
                    if !alg.oid.matches(super::OID_PSPECIFIED) {
                        return Err(CryptoError::UnsupportedOperation(
                            "cms: unsupported OAEP pSource algorithm".to_string(),
                        ));
                    }
                    let params = alg.parameters.as_deref().ok_or(CryptoError::StrError(
                        "cms: missing OAEP pSpecified parameters",
                    ))?;
                    let mut label_reader = Reader::new(params);
                    if !label_reader.read_octet_string()?.is_empty() {
                        return Err(CryptoError::UnsupportedOperation(
                            "cms: OAEP non-empty label is not supported".to_string(),
                        ));
                    }
                }
                _ => return Err(CryptoError::StrError("cms: invalid OAEP parameters")),
            }
        }
        reader.expect_end()?;
    }
    if hash != mgf_hash {
        return Err(CryptoError::UnsupportedOperation(
            "cms: OAEP MGF1 hash differs from the hash".to_string(),
        ));
    }
    Ok(hash)
}

fn oaep_hash(alg: &AlgorithmIdentifier) -> CryptoResult<Hash> {
    let hash = Hash::from_oid(&alg.oid).ok_or_else(|| {
        CryptoError::UnsupportedOperation("cms: unsupported OAEP hash".to_string())
    })?;
    match hash {
        Hash::Sha1 | Hash::Sha224 | Hash::Sha256 | Hash::Sha384 | Hash::Sha512 => Ok(hash),
        _ => Err(CryptoError::UnsupportedOperation(
            "cms: unsupported OAEP hash".to_string(),
        )),
    }
}

/// `KeyTransRecipientInfo ::= SEQUENCE { version, rid,
/// keyEncryptionAlgorithm, encryptedKey }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyTransRecipientInfo {
    /// CMS version (0 for issuerAndSerialNumber, 2 for SKI).
    pub version: u8,
    /// Recipient identifier.
    pub rid: RecipientIdentifier,
    /// Key-encryption algorithm (`rsaEncryption` or `id-RSAES-OAEP`).
    pub key_encryption_algorithm: AlgorithmIdentifier,
    /// The encrypted content-encryption key.
    pub encrypted_key: Vec<u8>,
}

impl KeyTransRecipientInfo {
    /// Parse a `KeyTransRecipientInfo`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let version = read_version(&mut seq, "cms: invalid ktri version")?;
        let rid = RecipientIdentifier::parse(&mut seq)?;
        let key_encryption_algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        let encrypted_key = seq.read_octet_string()?.to_vec();
        seq.expect_end()?;
        Ok(KeyTransRecipientInfo {
            version,
            rid,
            key_encryption_algorithm,
            encrypted_key,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.version]);
        content.extend_from_slice(&self.rid.encode());
        content.extend_from_slice(&self.key_encryption_algorithm.encode());
        content.extend_from_slice(&der::octet_string(&self.encrypted_key));
        der::sequence(&content)
    }

    /// Encrypt `cek` for `certificate` with PKCS#1 v1.5.
    pub(crate) fn wrap(
        certificate: &Certificate,
        cek: &[u8],
        rng: &mut impl Rng,
    ) -> CryptoResult<Self> {
        Self::wrap_with(certificate, RsaKeyEncryption::Pkcs1v15, cek, rng)
    }

    /// Encrypt `cek` for `certificate` with the given RSA scheme.
    pub(crate) fn wrap_with(
        certificate: &Certificate,
        encryption: RsaKeyEncryption,
        cek: &[u8],
        rng: &mut impl Rng,
    ) -> CryptoResult<Self> {
        let PublicKey::Rsa(public) = certificate.public_key() else {
            return Err(CryptoError::UnsupportedOperation(
                "cms: certificate does not carry an RSA key".to_string(),
            ));
        };
        let encrypted_key = encryption.encrypt(public, rng, cek)?;
        let rid =
            RecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber::of(certificate));
        let version = match &rid {
            RecipientIdentifier::IssuerAndSerialNumber(_) => 0,
            RecipientIdentifier::SubjectKeyIdentifier(_) => 2,
        };
        Ok(KeyTransRecipientInfo {
            version,
            rid,
            key_encryption_algorithm: encryption.to_identifier(),
            encrypted_key,
        })
    }

    /// Decrypt the content-encryption key.
    pub fn decrypt(&self, key: &PrivateKey) -> CryptoResult<Vec<u8>> {
        let PrivateKey::Rsa(rsa) = key else {
            return Err(CryptoError::UnsupportedOperation(
                "cms: key transport recipient requires an RSA key".to_string(),
            ));
        };
        let encryption = RsaKeyEncryption::parse(&self.key_encryption_algorithm)?;
        encryption.decrypt(rsa, &self.encrypted_key)
    }
}

/// `PasswordRecipientInfo ::= SEQUENCE { version, [0]
/// keyDerivationAlgorithm OPTIONAL, keyEncryptionAlgorithm, encryptedKey }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordRecipientInfo {
    /// CMS version (0).
    pub version: u8,
    /// The PBKDF2 key-derivation algorithm.
    pub key_derivation_algorithm: Option<AlgorithmIdentifier>,
    /// The CBC key-encryption algorithm (wrapped in `id-alg-PWRI-KEK`).
    pub key_encryption_algorithm: AlgorithmIdentifier,
    /// The encrypted content-encryption key.
    pub encrypted_key: Vec<u8>,
}

impl PasswordRecipientInfo {
    /// Parse a `PasswordRecipientInfo` `SEQUENCE`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let info = Self::parse_body(&mut seq)?;
        seq.expect_end()?;
        Ok(info)
    }

    /// Parse the fields of a `PasswordRecipientInfo` (the `[3]` IMPLICIT
    /// form inside `EnvelopedData` has no SEQUENCE tag).
    pub(crate) fn parse_body(seq: &mut Reader<'_>) -> CryptoResult<Self> {
        let version = read_version(seq, "cms: invalid pwri version")?;
        // RFC 5652's ASN.1 module is IMPLICIT TAGS: `[0]` replaces the
        // AlgorithmIdentifier SEQUENCE tag.
        let key_derivation_algorithm =
            if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(0) {
                let mut inner = seq.read_implicit_constructed(0)?;
                let algorithm = parse_algorithm_identifier_body(&mut inner)?;
                inner.expect_end()?;
                Some(algorithm)
            } else {
                None
            };
        let key_encryption_algorithm = AlgorithmIdentifier::parse(seq)?;
        let encrypted_key = seq.read_octet_string()?.to_vec();
        Ok(PasswordRecipientInfo {
            version,
            key_derivation_algorithm,
            key_encryption_algorithm,
            encrypted_key,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.version]);
        if let Some(kdf) = &self.key_derivation_algorithm {
            content.extend_from_slice(&der::implicit(0, true, &sequence_content(&kdf.encode())));
        }
        content.extend_from_slice(&self.key_encryption_algorithm.encode());
        content.extend_from_slice(&der::octet_string(&self.encrypted_key));
        der::sequence(&content)
    }

    /// Wrap `cek` under `password` with PBKDF2-SHA-256 and the RFC 3217
    /// double-CBC scheme used by `id-alg-PWRI-KEK`.
    pub(crate) fn wrap(
        password: &[u8],
        iterations: u32,
        cipher: Cipher,
        cek: &[u8],
        rng: &mut impl Rng,
    ) -> CryptoResult<Self> {
        if iterations == 0 {
            return Err(CryptoError::StrError("cms: zero PBKDF2 iterations"));
        }
        let kek_cipher = KekCipher::for_content(cipher);
        let mut salt = vec![0u8; 16];
        rng.fill_bytes(&mut salt);
        let mut kek = vec![0u8; kek_cipher.key_len()];
        crate::x509::pbe::pbkdf2(Hash::Sha256, password, &salt, iterations, &mut kek)?;
        let mut iv = vec![0u8; kek_cipher.block_size()];
        rng.fill_bytes(&mut iv);
        let encrypted_key = kek_cipher.wrap(&kek, &iv, cek, rng)?;

        // PBKDF2-params with an explicit HMAC-SHA-256 PRF.
        let mut kdf_params = der::octet_string(&salt);
        kdf_params.extend_from_slice(&der::integer(&(iterations as u64).to_be_bytes()));
        kdf_params.extend_from_slice(
            &AlgorithmIdentifier::with_null(oid_of(oid::OID_HMAC_SHA256)).encode(),
        );
        let kdf =
            AlgorithmIdentifier::new(oid_of(oid::OID_PBKDF2), Some(der::sequence(&kdf_params)));
        // id-alg-PWRI-KEK parameters are the inner CBC AlgorithmIdentifier.
        let key_encryption_algorithm = AlgorithmIdentifier::new(
            oid_of(super::OID_PWRI_KEK),
            Some(kek_cipher.to_identifier(&iv).encode()),
        );
        Ok(PasswordRecipientInfo {
            version: 0,
            key_derivation_algorithm: Some(kdf),
            key_encryption_algorithm,
            encrypted_key,
        })
    }

    /// Derive the KEK from `password` and unwrap the content-encryption key.
    pub fn decrypt(&self, password: &[u8]) -> CryptoResult<Vec<u8>> {
        if !self
            .key_encryption_algorithm
            .oid
            .matches(super::OID_PWRI_KEK)
        {
            return Err(CryptoError::UnsupportedOperation(alloc::format!(
                "cms: unsupported PWRI key encryption algorithm {}",
                self.key_encryption_algorithm.oid
            )));
        }
        let kdf = self
            .key_derivation_algorithm
            .as_ref()
            .ok_or(CryptoError::StrError(
                "cms: PWRI key derivation algorithm missing",
            ))?;
        if !kdf.oid.matches(oid::OID_PBKDF2) {
            return Err(CryptoError::UnsupportedOperation(alloc::format!(
                "cms: unsupported PWRI key derivation function {}",
                kdf.oid
            )));
        }
        let params = kdf
            .parameters
            .as_deref()
            .ok_or(CryptoError::StrError("cms: PBKDF2 parameters missing"))?;
        let mut reader = Reader::new(params);
        let mut seq = reader.read_sequence()?;
        let salt = seq.read_octet_string()?.to_vec();
        let iterations = u32::try_from(seq.read_integer_i64()?)
            .map_err(|_| CryptoError::StrError("cms: invalid PBKDF2 iterations"))?;
        let key_length = if !seq.is_empty() && seq.peek_tag()? == der::INTEGER {
            Some(
                usize::try_from(seq.read_integer_i64()?)
                    .map_err(|_| CryptoError::StrError("cms: invalid PBKDF2 key length"))?,
            )
        } else {
            None
        };
        // RFC 8018 defaults the PRF to HMAC-SHA-1 when absent, which is what
        // OpenSSL emits from `cms -pwri_password`.
        let prf = if seq.is_empty() {
            Hash::Sha1
        } else {
            prf_hash(&AlgorithmIdentifier::parse(&mut seq)?)?
        };
        seq.expect_end()?;
        reader.expect_end()?;

        let inner =
            self.key_encryption_algorithm
                .parameters
                .as_deref()
                .ok_or(CryptoError::StrError(
                    "cms: PWRI key encryption parameters missing",
                ))?;
        let mut inner_reader = Reader::new(inner);
        let inner_alg = AlgorithmIdentifier::parse(&mut inner_reader)?;
        inner_reader.expect_end()?;
        let (kek_cipher, iv) = KekCipher::parse(&inner_alg)?;
        if let Some(key_length) = key_length {
            if key_length != kek_cipher.key_len() {
                return Err(CryptoError::StrError("cms: invalid PWRI KEK size"));
            }
        }
        let mut kek = vec![0u8; kek_cipher.key_len()];
        crate::x509::pbe::pbkdf2(prf, password, &salt, iterations, &mut kek)?;
        kek_cipher.unwrap(&kek, &iv, &self.encrypted_key)
    }
}

fn prf_hash(alg: &AlgorithmIdentifier) -> CryptoResult<Hash> {
    if alg.oid.matches(oid::OID_HMAC_SHA1) {
        Ok(Hash::Sha1)
    } else if alg.oid.matches(OID_HMAC_SHA224) {
        Ok(Hash::Sha224)
    } else if alg.oid.matches(oid::OID_HMAC_SHA256) {
        Ok(Hash::Sha256)
    } else if alg.oid.matches(oid::OID_HMAC_SHA384) {
        Ok(Hash::Sha384)
    } else if alg.oid.matches(oid::OID_HMAC_SHA512) {
        Ok(Hash::Sha512)
    } else {
        Err(CryptoError::UnsupportedOperation(
            "cms: unsupported PBKDF2 PRF".to_string(),
        ))
    }
}

/// `KEKIdentifier ::= SEQUENCE { keyIdentifier OCTET STRING, date
/// GeneralizedTime OPTIONAL, otherKeyAttribute OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KekIdentifier {
    /// Key identifier.
    pub key_id: Vec<u8>,
    /// Optional generation time.
    pub date: Option<Asn1Time>,
    /// Optional `otherKeyAttribute`, kept as raw DER.
    pub other: Option<Vec<u8>>,
}

impl KekIdentifier {
    /// Parse a `KEKIdentifier`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let key_id = seq.read_octet_string()?.to_vec();
        let date = if !seq.is_empty() && seq.peek_tag()? == der::GENERALIZED_TIME {
            Some(seq.read_generalized_time()?)
        } else {
            None
        };
        let other = if !seq.is_empty() {
            Some(seq.read_raw_tlv()?.to_vec())
        } else {
            None
        };
        seq.expect_end()?;
        Ok(KekIdentifier {
            key_id,
            date,
            other,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::octet_string(&self.key_id);
        if let Some(date) = &self.date {
            content.extend_from_slice(&der::generalized_time(date));
        }
        if let Some(other) = &self.other {
            content.extend_from_slice(other);
        }
        der::sequence(&content)
    }
}

/// `KEKRecipientInfo ::= SEQUENCE { version, kekid, keyEncryptionAlgorithm,
/// encryptedKey }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KekRecipientInfo {
    /// CMS version (4).
    pub version: u8,
    /// KEK identifier.
    pub kekid: KekIdentifier,
    /// `id-aes{128,192,256}-wrap`.
    pub key_encryption_algorithm: AlgorithmIdentifier,
    /// The wrapped content-encryption key.
    pub encrypted_key: Vec<u8>,
}

impl KekRecipientInfo {
    /// Parse a `KEKRecipientInfo` `SEQUENCE`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let info = Self::parse_body(&mut seq)?;
        seq.expect_end()?;
        Ok(info)
    }

    /// Parse the fields of a `KEKRecipientInfo` (the `[2]` IMPLICIT form
    /// inside `EnvelopedData` has no SEQUENCE tag).
    pub(crate) fn parse_body(seq: &mut Reader<'_>) -> CryptoResult<Self> {
        let version = read_version(seq, "cms: invalid kekri version")?;
        let kekid = KekIdentifier::parse(seq)?;
        let key_encryption_algorithm = AlgorithmIdentifier::parse(seq)?;
        let encrypted_key = seq.read_octet_string()?.to_vec();
        Ok(KekRecipientInfo {
            version,
            kekid,
            key_encryption_algorithm,
            encrypted_key,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.version]);
        content.extend_from_slice(&self.kekid.encode());
        content.extend_from_slice(&self.key_encryption_algorithm.encode());
        content.extend_from_slice(&der::octet_string(&self.encrypted_key));
        der::sequence(&content)
    }

    /// Wrap `cek` under `kek` with RFC 3394.
    pub(crate) fn wrap(kek: &[u8], key_id: &[u8], cek: &[u8]) -> CryptoResult<Self> {
        let algorithm = KeyWrapAlgorithm::from_key_len(kek.len())?;
        let encrypted_key = algorithm.wrap(kek, cek)?;
        Ok(KekRecipientInfo {
            version: 4,
            kekid: KekIdentifier {
                key_id: key_id.to_vec(),
                date: None,
                other: None,
            },
            key_encryption_algorithm: algorithm.to_identifier(),
            encrypted_key,
        })
    }

    /// Unwrap the content-encryption key under `kek`.
    pub fn decrypt(&self, kek: &[u8]) -> CryptoResult<Vec<u8>> {
        let algorithm = KeyWrapAlgorithm::parse(&self.key_encryption_algorithm)?;
        algorithm.unwrap(kek, &self.encrypted_key)
    }
}

/// `OriginatorPublicKey ::= SEQUENCE { algorithm AlgorithmIdentifier,
/// publicKey BIT STRING }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginatorPublicKey {
    /// Public-key algorithm (for EC keys, the named curve OID).
    pub algorithm: AlgorithmIdentifier,
    /// The BIT STRING payload (an uncompressed EC point).
    pub public_key: Vec<u8>,
}

impl OriginatorPublicKey {
    /// Parse an `OriginatorPublicKey` from a reader positioned at the first
    /// field (the `SEQUENCE` itself is implicit when tagged `[1]`).
    pub fn parse_body(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let algorithm = AlgorithmIdentifier::parse(reader)?;
        let public_key = reader.read_bit_string_bytes()?.to_vec();
        reader.expect_end()?;
        Ok(OriginatorPublicKey {
            algorithm,
            public_key,
        })
    }

    /// Encode as a DER `SEQUENCE`.
    pub fn encode(&self) -> Vec<u8> {
        der::sequence(&self.encode_body())
    }

    fn encode_body(&self) -> Vec<u8> {
        let mut content = self.algorithm.encode();
        content.extend_from_slice(&der::bit_string(0, &self.public_key));
        content
    }
}

/// `OriginatorIdentifierOrKey` CHOICE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginatorIdentifierOrKey {
    /// `issuerAndSerialNumber`.
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    /// `[0] subjectKeyIdentifier`.
    SubjectKeyIdentifier(Vec<u8>),
    /// `[1] originatorKey`.
    OriginatorKey(OriginatorPublicKey),
}

impl OriginatorIdentifierOrKey {
    /// Parse from a reader positioned at the choice.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let tag = reader.peek_tag()?;
        if tag == der::SEQUENCE {
            Ok(OriginatorIdentifierOrKey::IssuerAndSerialNumber(
                IssuerAndSerialNumber::parse(reader)?,
            ))
        } else if tag == der::Tag::context(0) {
            Ok(OriginatorIdentifierOrKey::SubjectKeyIdentifier(
                reader.read_implicit(0, false)?.to_vec(),
            ))
        } else if tag == der::Tag::context_constructed(1) {
            let mut inner = reader.read_implicit_constructed(1)?;
            Ok(OriginatorIdentifierOrKey::OriginatorKey(
                OriginatorPublicKey::parse_body(&mut inner)?,
            ))
        } else {
            Err(CryptoError::StrError("cms: invalid originator identifier"))
        }
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            OriginatorIdentifierOrKey::IssuerAndSerialNumber(value) => value.encode(),
            OriginatorIdentifierOrKey::SubjectKeyIdentifier(key_id) => {
                der::implicit(0, false, key_id)
            }
            OriginatorIdentifierOrKey::OriginatorKey(key) => {
                // [1] IMPLICIT OriginatorPublicKey replaces the SEQUENCE tag.
                der::implicit(1, true, &key.encode_body())
            }
        }
    }
}

/// `RecipientKeyIdentifier ::= SEQUENCE { subjectKeyIdentifier,
/// date GeneralizedTime OPTIONAL, other OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeyIdentifier {
    /// Subject key identifier.
    pub key_id: Vec<u8>,
    /// Optional generation time.
    pub date: Option<Asn1Time>,
    /// Optional `otherKeyAttribute`, kept as raw DER.
    pub other: Option<Vec<u8>>,
}

impl RecipientKeyIdentifier {
    fn parse_body(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let key_id = reader.read_octet_string()?.to_vec();
        let date = if !reader.is_empty() && reader.peek_tag()? == der::GENERALIZED_TIME {
            Some(reader.read_generalized_time()?)
        } else {
            None
        };
        let other = if !reader.is_empty() {
            Some(reader.read_raw_tlv()?.to_vec())
        } else {
            None
        };
        reader.expect_end()?;
        Ok(RecipientKeyIdentifier {
            key_id,
            date,
            other,
        })
    }

    fn encode_body(&self) -> Vec<u8> {
        let mut content = der::octet_string(&self.key_id);
        if let Some(date) = &self.date {
            content.extend_from_slice(&der::generalized_time(date));
        }
        if let Some(other) = &self.other {
            content.extend_from_slice(other);
        }
        content
    }

    /// Whether this identifier matches `certificate`.
    pub fn matches(&self, certificate: &Certificate) -> bool {
        certificate
            .tbs()
            .subject_key_identifier()
            .is_some_and(|id| id == self.key_id)
    }
}

/// `KeyAgreeRecipientIdentifier` CHOICE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAgreeRecipientIdentifier {
    /// `issuerAndSerialNumber`.
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    /// `[0] rKeyId`.
    RecipientKeyIdentifier(RecipientKeyIdentifier),
}

impl KeyAgreeRecipientIdentifier {
    /// Parse from a reader positioned at the choice.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        if reader.peek_tag()? == der::SEQUENCE {
            Ok(KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(
                IssuerAndSerialNumber::parse(reader)?,
            ))
        } else {
            let mut inner = reader.read_implicit_constructed(0)?;
            Ok(KeyAgreeRecipientIdentifier::RecipientKeyIdentifier(
                RecipientKeyIdentifier::parse_body(&mut inner)?,
            ))
        }
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(value) => value.encode(),
            KeyAgreeRecipientIdentifier::RecipientKeyIdentifier(key) => {
                der::implicit(0, true, &key.encode_body())
            }
        }
    }

    /// Whether this identifier matches `certificate`.
    pub fn matches(&self, certificate: &Certificate) -> bool {
        match self {
            KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(value) => value.matches(certificate),
            KeyAgreeRecipientIdentifier::RecipientKeyIdentifier(key) => key.matches(certificate),
        }
    }
}

/// `RecipientEncryptedKey ::= SEQUENCE { rid, encryptedKey }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientEncryptedKey {
    /// Recipient identifier.
    pub rid: KeyAgreeRecipientIdentifier,
    /// The wrapped content-encryption key.
    pub encrypted_key: Vec<u8>,
}

impl RecipientEncryptedKey {
    /// Parse a `RecipientEncryptedKey`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let rid = KeyAgreeRecipientIdentifier::parse(&mut seq)?;
        let encrypted_key = seq.read_octet_string()?.to_vec();
        seq.expect_end()?;
        Ok(RecipientEncryptedKey { rid, encrypted_key })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.rid.encode();
        content.extend_from_slice(&der::octet_string(&self.encrypted_key));
        der::sequence(&content)
    }
}

/// `KeyAgreeRecipientInfo ::= SEQUENCE { version, originator [0] EXPLICIT,
/// ukm [1] EXPLICIT OPTIONAL, keyEncryptionAlgorithm,
/// recipientEncryptedKeys }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAgreeRecipientInfo {
    /// CMS version (3).
    pub version: u8,
    /// The originator's identifier or ephemeral public key.
    pub originator: OriginatorIdentifierOrKey,
    /// Optional user keying material.
    pub ukm: Option<Vec<u8>>,
    /// The key-agreement scheme plus the key-wrap algorithm.
    pub key_encryption_algorithm: AlgorithmIdentifier,
    /// One wrapped key per recipient.
    pub recipient_encrypted_keys: Vec<RecipientEncryptedKey>,
}

impl KeyAgreeRecipientInfo {
    /// Parse a `KeyAgreeRecipientInfo` `SEQUENCE`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let info = Self::parse_body(&mut seq)?;
        seq.expect_end()?;
        Ok(info)
    }

    /// Parse the fields of a `KeyAgreeRecipientInfo` (the `[1]` IMPLICIT
    /// form inside `EnvelopedData` has no SEQUENCE tag).
    pub(crate) fn parse_body(seq: &mut Reader<'_>) -> CryptoResult<Self> {
        let version = read_version(seq, "cms: invalid kari version")?;
        let mut originator_inner = seq.read_explicit(0)?;
        let originator = OriginatorIdentifierOrKey::parse(&mut originator_inner)?;
        originator_inner.expect_end()?;
        let ukm = if !seq.is_empty() && seq.peek_tag()? == der::Tag::context_constructed(1) {
            let mut inner = seq.read_explicit(1)?;
            Some(inner.read_octet_string()?.to_vec())
        } else {
            None
        };
        let key_encryption_algorithm = AlgorithmIdentifier::parse(seq)?;
        let mut keys = seq.read_sequence()?;
        let mut recipient_encrypted_keys = Vec::new();
        while !keys.is_empty() {
            recipient_encrypted_keys.push(RecipientEncryptedKey::parse(&mut keys)?);
        }
        Ok(KeyAgreeRecipientInfo {
            version,
            originator,
            ukm,
            key_encryption_algorithm,
            recipient_encrypted_keys,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[self.version]);
        content.extend_from_slice(&der::explicit(0, &self.originator.encode()));
        if let Some(ukm) = &self.ukm {
            content.extend_from_slice(&der::explicit(1, &der::octet_string(ukm)));
        }
        content.extend_from_slice(&self.key_encryption_algorithm.encode());
        let mut keys = Vec::new();
        for key in &self.recipient_encrypted_keys {
            keys.extend_from_slice(&key.encode());
        }
        content.extend_from_slice(&der::sequence(&keys));
        der::sequence(&content)
    }

    /// Encrypt `cek` for the EC `certificate`, generating an ephemeral key.
    pub(crate) fn wrap(
        certificate: &Certificate,
        cek: &[u8],
        rng: &mut impl Rng,
    ) -> CryptoResult<Self> {
        let (curve, point) = match certificate.public_key() {
            PublicKey::Ec { curve, point } => (*curve, point),
            _ => {
                return Err(CryptoError::UnsupportedOperation(
                    "cms: key agreement recipient requires an EC key".to_string(),
                ))
            }
        };
        let (ephemeral_scalar, ephemeral_point) = ecdh::generate(curve, rng)?;
        let shared = ecdh::agree(curve, &ephemeral_scalar, point)?;
        let (scheme_oid, hash) = scheme_for_curve(curve)?;
        let wrap = KeyWrapAlgorithm::from_key_len(cek.len())?;
        let info = shared_info(wrap, None);
        let kek = x963_derive_hash(hash.factory(), &shared, &info, wrap.key_len())?;
        let encrypted_key = wrap.wrap(&kek, cek)?;

        let algorithm = AlgorithmIdentifier::new(
            oid_of(oid::OID_EC_PUBLIC_KEY),
            Some(der::oid(&oid_of(ec_curve_oid(curve)))),
        );
        let originator = OriginatorIdentifierOrKey::OriginatorKey(OriginatorPublicKey {
            algorithm,
            public_key: ephemeral_point.to_bytes_with(&ec::curve(curve)),
        });
        let key_encryption_algorithm =
            AlgorithmIdentifier::new(oid_of(scheme_oid), Some(wrap.to_identifier().encode()));
        Ok(KeyAgreeRecipientInfo {
            version: 3,
            originator,
            ukm: None,
            key_encryption_algorithm,
            recipient_encrypted_keys: vec![RecipientEncryptedKey {
                rid: KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber::of(
                    certificate,
                )),
                encrypted_key,
            }],
        })
    }

    /// Decrypt the content-encryption key, or `Ok(None)` when no
    /// `RecipientEncryptedKey` matches the certificate.
    pub fn decrypt(
        &self,
        key: &PrivateKey,
        certificate: &Certificate,
    ) -> CryptoResult<Option<Vec<u8>>> {
        let Some(rek) = self
            .recipient_encrypted_keys
            .iter()
            .find(|rek| rek.rid.matches(certificate))
        else {
            return Ok(None);
        };
        let certificate_curve = match certificate.public_key() {
            PublicKey::Ec { curve, .. } => *curve,
            _ => {
                return Err(CryptoError::UnsupportedOperation(
                    "cms: key agreement recipient requires an EC certificate".to_string(),
                ))
            }
        };
        let PrivateKey::Ec { curve, scalar } = key else {
            return Err(CryptoError::UnsupportedOperation(
                "cms: key agreement recipient requires an EC private key".to_string(),
            ));
        };
        if *curve != certificate_curve {
            return Err(CryptoError::StrError(
                "cms: EC key does not match the certificate curve",
            ));
        }
        let (_, hash, wrap) = parse_scheme(&self.key_encryption_algorithm)?;
        let originator = match &self.originator {
            OriginatorIdentifierOrKey::OriginatorKey(key) => key,
            _ => {
                return Err(CryptoError::UnsupportedOperation(
                    "cms: unsupported originator identifier".to_string(),
                ))
            }
        };
        let point = parse_originator_point(originator, *curve)?;
        let shared = ecdh::agree(*curve, scalar, &point)?;
        let info = shared_info(wrap, self.ukm.as_deref());
        let kek = x963_derive_hash(hash.factory(), &shared, &info, wrap.key_len())?;
        Ok(Some(wrap.unwrap(&kek, &rek.encrypted_key)?))
    }
}

/// The KDF hash and key-wrap algorithm of a `KeyAgreeRecipientInfo`.
fn parse_scheme(
    algorithm: &AlgorithmIdentifier,
) -> CryptoResult<(&'static [u64], Hash, KeyWrapAlgorithm)> {
    let (scheme_oid, hash) = if algorithm.oid.matches(OID_DH_STD_SHA1) {
        (OID_DH_STD_SHA1, Hash::Sha1)
    } else if algorithm.oid.matches(OID_DH_STD_SHA224) {
        (OID_DH_STD_SHA224, Hash::Sha224)
    } else if algorithm.oid.matches(OID_DH_STD_SHA256) {
        (OID_DH_STD_SHA256, Hash::Sha256)
    } else if algorithm.oid.matches(OID_DH_STD_SHA384) {
        (OID_DH_STD_SHA384, Hash::Sha384)
    } else if algorithm.oid.matches(OID_DH_STD_SHA512) {
        (OID_DH_STD_SHA512, Hash::Sha512)
    } else {
        return Err(CryptoError::UnsupportedOperation(alloc::format!(
            "cms: unsupported key agreement scheme {}",
            algorithm.oid
        )));
    };
    let params = algorithm
        .parameters
        .as_deref()
        .ok_or(CryptoError::StrError("cms: key wrap parameters missing"))?;
    let mut reader = Reader::new(params);
    let wrap = AlgorithmIdentifier::parse(&mut reader)?;
    reader.expect_end()?;
    Ok((scheme_oid, hash, KeyWrapAlgorithm::parse(&wrap)?))
}

/// The RFC 5753 `SharedInfo` fed to the X9.63 KDF:
/// `SEQUENCE { keyInfo AlgorithmIdentifier, entityUInfo [0] EXPLICIT OCTET
/// STRING OPTIONAL, suppPubInfo [2] EXPLICIT OCTET STRING }` where
/// `suppPubInfo` is the KEK length in bits, four bytes big-endian.
fn shared_info(wrap: KeyWrapAlgorithm, ukm: Option<&[u8]>) -> Vec<u8> {
    let mut content = wrap.to_identifier().encode();
    if let Some(ukm) = ukm {
        content.extend_from_slice(&der::explicit(0, &der::octet_string(ukm)));
    }
    let key_bits = ((wrap.key_len() * 8) as u32).to_be_bytes();
    content.extend_from_slice(&der::explicit(2, &der::octet_string(&key_bits)));
    der::sequence(&content)
}

/// The `dhSinglePass-stdDH-*-kdf-scheme` OID and hash for a curve.
fn scheme_for_curve(curve: CurveId) -> CryptoResult<(&'static [u64], Hash)> {
    match curve {
        CurveId::P256 => Ok((OID_DH_STD_SHA256, Hash::Sha256)),
        CurveId::P384 => Ok((OID_DH_STD_SHA384, Hash::Sha384)),
        CurveId::P521 => Ok((OID_DH_STD_SHA512, Hash::Sha512)),
    }
}

fn ec_curve_oid(curve: CurveId) -> &'static [u64] {
    match curve {
        CurveId::P256 => oid::OID_SECP256R1,
        CurveId::P384 => oid::OID_SECP384R1,
        CurveId::P521 => oid::OID_SECP521R1,
    }
}

fn parse_originator_point(
    originator: &OriginatorPublicKey,
    default_curve: CurveId,
) -> CryptoResult<Point> {
    let curve = if originator.algorithm.oid.matches(oid::OID_EC_PUBLIC_KEY) {
        match originator.algorithm.parameters.as_deref() {
            // OpenSSL omits the curve parameters in the ephemeral key; the
            // recipient's curve then applies.
            None => default_curve,
            Some(params) => {
                let mut reader = Reader::new(params);
                let curve_oid = reader.read_oid()?;
                if curve_oid.matches(oid::OID_SECP256R1) {
                    CurveId::P256
                } else if curve_oid.matches(oid::OID_SECP384R1) {
                    CurveId::P384
                } else if curve_oid.matches(oid::OID_SECP521R1) {
                    CurveId::P521
                } else {
                    return Err(CryptoError::UnsupportedOperation(alloc::format!(
                        "cms: unsupported ephemeral curve {curve_oid}"
                    )));
                }
            }
        }
    } else {
        return Err(CryptoError::UnsupportedOperation(alloc::format!(
            "cms: unsupported ephemeral key algorithm {}",
            originator.algorithm.oid
        )));
    };
    if curve != default_curve {
        return Err(CryptoError::StrError(
            "cms: ephemeral key curve differs from the recipient curve",
        ));
    }
    Point::from_bytes(&ec::curve(curve), &originator.public_key)
}

/// Parse the body of an `AlgorithmIdentifier` (OID plus optional raw
/// parameters) from an IMPLICIT `[n]` tag.
fn parse_algorithm_identifier_body(reader: &mut Reader<'_>) -> CryptoResult<AlgorithmIdentifier> {
    let oid = reader.read_oid()?;
    let parameters = if reader.is_empty() {
        None
    } else {
        Some(reader.read_raw_tlv()?.to_vec())
    };
    Ok(AlgorithmIdentifier::new(oid, parameters))
}

/// Read a CMS version INTEGER.
fn read_version(reader: &mut Reader<'_>, error: &'static str) -> CryptoResult<u8> {
    u8::try_from(reader.read_integer_i64()?).map_err(|_| CryptoError::StrError(error))
}

/// The full `RecipientInfo` CHOICE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientInfo {
    /// `ktri` (key transport, RSA).
    KeyTrans(KeyTransRecipientInfo),
    /// `kari [1]` (key agreement, ECDH).
    KeyAgree(KeyAgreeRecipientInfo),
    /// `kekri [2]` (key wrap).
    Kek(KekRecipientInfo),
    /// `pwri [3]` (password).
    Password(PasswordRecipientInfo),
}

impl RecipientInfo {
    /// Parse a `RecipientInfo` CHOICE.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let tag = reader.peek_tag()?;
        if tag == der::SEQUENCE {
            return Ok(RecipientInfo::KeyTrans(KeyTransRecipientInfo::parse(
                reader,
            )?));
        }
        // kari/kekri/pwri are IMPLICIT context tags: the fields follow
        // directly, without a SEQUENCE tag.
        match tag.number {
            1 => {
                let mut inner = reader.read_implicit_constructed(1)?;
                let info = KeyAgreeRecipientInfo::parse_body(&mut inner)?;
                inner.expect_end()?;
                Ok(RecipientInfo::KeyAgree(info))
            }
            2 => {
                let mut inner = reader.read_implicit_constructed(2)?;
                let info = KekRecipientInfo::parse_body(&mut inner)?;
                inner.expect_end()?;
                Ok(RecipientInfo::Kek(info))
            }
            3 => {
                let mut inner = reader.read_implicit_constructed(3)?;
                let info = PasswordRecipientInfo::parse_body(&mut inner)?;
                inner.expect_end()?;
                Ok(RecipientInfo::Password(info))
            }
            _ => Err(CryptoError::UnsupportedOperation(
                "cms: unsupported recipient info type".to_string(),
            )),
        }
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RecipientInfo::KeyTrans(info) => info.encode(),
            RecipientInfo::KeyAgree(info) => {
                der::implicit(1, true, &sequence_content(&info.encode()))
            }
            RecipientInfo::Kek(info) => der::implicit(2, true, &sequence_content(&info.encode())),
            RecipientInfo::Password(info) => {
                der::implicit(3, true, &sequence_content(&info.encode()))
            }
        }
    }
}

/// The content octets of a DER `SEQUENCE`.
fn sequence_content(der: &[u8]) -> Vec<u8> {
    let mut reader = Reader::new(der);
    match reader.read_tlv() {
        Ok((_, content)) => content.to_vec(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::oid::{self, ObjectIdentifier};

    fn round_trip<T, F, G>(value: &T, encode: F, parse: G) -> T
    where
        F: Fn(&T) -> Vec<u8>,
        G: Fn(&mut Reader<'_>) -> CryptoResult<T>,
    {
        let der = encode(value);
        let mut reader = Reader::new(&der);
        let parsed = parse(&mut reader).expect("parse");
        reader.expect_end().expect("trailing data");
        parsed
    }

    #[test]
    fn rsa_key_encryption_round_trips() {
        for encryption in [
            RsaKeyEncryption::Pkcs1v15,
            RsaKeyEncryption::Oaep { hash: Hash::Sha1 },
            RsaKeyEncryption::Oaep { hash: Hash::Sha256 },
            RsaKeyEncryption::Oaep { hash: Hash::Sha512 },
        ] {
            let identifier = encryption.to_identifier();
            let parsed = RsaKeyEncryption::parse(&identifier).unwrap();
            assert_eq!(parsed, encryption);
        }
        // Absent OAEP parameters mean the SHA-1 default.
        let bare = AlgorithmIdentifier::new(ObjectIdentifier::new(oid::OID_MGF1).unwrap(), None);
        assert!(RsaKeyEncryption::parse(&bare).is_err());
        let default_oaep = AlgorithmIdentifier::new(
            ObjectIdentifier::new(super::super::OID_RSAES_OAEP).unwrap(),
            None,
        );
        assert_eq!(
            RsaKeyEncryption::parse(&default_oaep).unwrap(),
            RsaKeyEncryption::Oaep { hash: Hash::Sha1 }
        );
    }

    #[test]
    fn recipient_identifier_round_trips() {
        let issuer_and_serial = RecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: Name::from_common_name("leaf.crown.example"),
            serial_number: vec![0x01, 0x80, 0xff],
        });
        let parsed = round_trip(
            &issuer_and_serial,
            RecipientIdentifier::encode,
            RecipientIdentifier::parse,
        );
        assert_eq!(parsed, issuer_and_serial);

        let ski = RecipientIdentifier::SubjectKeyIdentifier(vec![0xaa; 20]);
        let parsed = round_trip(
            &ski,
            RecipientIdentifier::encode,
            RecipientIdentifier::parse,
        );
        assert_eq!(parsed, ski);
    }

    #[test]
    fn originator_key_round_trips() {
        let originator = OriginatorIdentifierOrKey::OriginatorKey(OriginatorPublicKey {
            algorithm: AlgorithmIdentifier::new(
                ObjectIdentifier::new(oid::OID_EC_PUBLIC_KEY).unwrap(),
                Some(der::oid(
                    &ObjectIdentifier::new(oid::OID_SECP256R1).unwrap(),
                )),
            ),
            public_key: vec![0x04; 65],
        });
        let parsed = round_trip(
            &originator,
            OriginatorIdentifierOrKey::encode,
            OriginatorIdentifierOrKey::parse,
        );
        assert_eq!(parsed, originator);

        let ski = OriginatorIdentifierOrKey::SubjectKeyIdentifier(vec![0x11; 8]);
        let parsed = round_trip(
            &ski,
            OriginatorIdentifierOrKey::encode,
            OriginatorIdentifierOrKey::parse,
        );
        assert_eq!(parsed, ski);
    }

    #[test]
    fn kek_recipient_info_round_trips() {
        let info = KekRecipientInfo {
            version: 4,
            kekid: KekIdentifier {
                key_id: b"crown-kek".to_vec(),
                date: Some(Asn1Time::from_unix(1_700_000_000, false)),
                other: None,
            },
            key_encryption_algorithm: KeyWrapAlgorithm::Aes256.to_identifier(),
            encrypted_key: vec![0x5a; 40],
        };
        let parsed = round_trip(&info, KekRecipientInfo::encode, |reader| {
            KekRecipientInfo::parse_body(&mut reader.read_sequence()?)
        });
        assert_eq!(parsed, info);
    }

    #[test]
    fn recipient_info_implicit_tags_round_trip() {
        let password = RecipientInfo::Password(PasswordRecipientInfo {
            version: 0,
            key_derivation_algorithm: Some(AlgorithmIdentifier::new(
                ObjectIdentifier::new(oid::OID_PBKDF2).unwrap(),
                Some(der::sequence(&der::octet_string(b"salt"))),
            )),
            key_encryption_algorithm: AlgorithmIdentifier::new(
                ObjectIdentifier::new(super::super::OID_PWRI_KEK).unwrap(),
                Some(KekCipher::Aes128.to_identifier(&[0u8; 16]).encode()),
            ),
            encrypted_key: vec![0x77; 32],
        });
        let parsed = round_trip(&password, RecipientInfo::encode, RecipientInfo::parse);
        assert_eq!(parsed, password);

        let kek = RecipientInfo::Kek(KekRecipientInfo {
            version: 4,
            kekid: KekIdentifier {
                key_id: b"id".to_vec(),
                date: None,
                other: None,
            },
            key_encryption_algorithm: KeyWrapAlgorithm::Aes128.to_identifier(),
            encrypted_key: vec![0x11; 24],
        });
        let parsed = round_trip(&kek, RecipientInfo::encode, RecipientInfo::parse);
        assert_eq!(parsed, kek);
    }

    #[test]
    fn shared_info_matches_rfc5753() {
        let info = shared_info(KeyWrapAlgorithm::Aes256, Some(b"ukm"));
        let mut reader = Reader::new(&info);
        let mut seq = reader.read_sequence().unwrap();
        let key_info = AlgorithmIdentifier::parse(&mut seq).unwrap();
        assert!(key_info.oid.matches(super::super::OID_AES_256_WRAP));
        let mut ukm = seq.read_explicit(0).unwrap();
        assert_eq!(ukm.read_octet_string().unwrap(), b"ukm");
        let mut pub_info = seq.read_explicit(2).unwrap();
        assert_eq!(pub_info.read_octet_string().unwrap(), 256u32.to_be_bytes());
        seq.expect_end().unwrap();
        reader.expect_end().unwrap();
    }
}

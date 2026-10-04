//! Public/private key structures, SubjectPublicKeyInfo and PKCS#8.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::{self, ObjectIdentifier};
use crate::bn::Bn;
use crate::dsa::{DsaKeyPair, DsaParams};
use crate::ec::{self, CurveId, Point};
use crate::error::{CryptoError, CryptoResult};
use crate::ml_dsa::{self, MlDsaPrivateKey, MlDsaPublicKey, MlDsaVariant};
use crate::rng::Rng;
use crate::rsa::{RsaPrivateKey, RsaPublicKey};
use crate::slh_dsa::{self, SlhDsaPrivateKey, SlhDsaPublicKey, SlhDsaVariant};

use super::algorithm::{AlgorithmIdentifier, SignatureAlgorithm};

/// A parsed public key of any supported type.
#[derive(Clone)]
pub enum PublicKey {
    /// RSA public key.
    Rsa(RsaPublicKey),
    /// Short-Weierstrass NIST curve public key.
    Ec {
        /// Curve identifier.
        curve: CurveId,
        /// Public point.
        point: Point,
    },
    /// Ed25519 public key.
    Ed25519([u8; 32]),
    /// Ed448 public key.
    Ed448([u8; 57]),
    /// X25519 public key (key agreement only).
    X25519([u8; 32]),
    /// X448 public key (key agreement only).
    X448([u8; 56]),
    /// SM2 public point.
    Sm2(Point),
    /// DSA public key with its domain parameters.
    Dsa {
        /// Domain parameters.
        params: DsaParams,
        /// Public value `y`.
        y: Bn,
    },
    /// ML-DSA public key.
    MlDsa(MlDsaPublicKey),
    /// SLH-DSA public key.
    SlhDsa(SlhDsaPublicKey),
    /// An algorithm crown does not implement.
    Unknown {
        /// The key's algorithm identifier.
        algorithm: AlgorithmIdentifier,
        /// The raw BIT STRING payload.
        key: Vec<u8>,
    },
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PublicKey::Rsa(_) => f.write_str("PublicKey::Rsa"),
            PublicKey::Ec { curve, .. } => write!(f, "PublicKey::Ec({curve:?})"),
            PublicKey::Ed25519(_) => f.write_str("PublicKey::Ed25519"),
            PublicKey::Ed448(_) => f.write_str("PublicKey::Ed448"),
            PublicKey::X25519(_) => f.write_str("PublicKey::X25519"),
            PublicKey::X448(_) => f.write_str("PublicKey::X448"),
            PublicKey::Sm2(_) => f.write_str("PublicKey::Sm2"),
            PublicKey::Dsa { .. } => f.write_str("PublicKey::Dsa"),
            PublicKey::MlDsa(key) => write!(f, "PublicKey::MlDsa({:?})", key.variant()),
            PublicKey::SlhDsa(key) => write!(f, "PublicKey::SlhDsa({:?})", key.variant()),
            PublicKey::Unknown { algorithm, .. } => {
                write!(f, "PublicKey::Unknown({})", algorithm.oid)
            }
        }
    }
}

/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }`.
#[derive(Clone)]
pub struct SubjectPublicKeyInfo {
    /// Algorithm identifier.
    pub algorithm: AlgorithmIdentifier,
    /// The raw BIT STRING payload.
    pub key: Vec<u8>,
    /// The decoded public key.
    pub public_key: PublicKey,
}

impl core::fmt::Debug for SubjectPublicKeyInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SubjectPublicKeyInfo")
            .field("algorithm", &self.algorithm.oid)
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl SubjectPublicKeyInfo {
    /// Parse DER `SubjectPublicKeyInfo`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        let key = seq.read_bit_string_bytes()?.to_vec();
        seq.expect_end()?;
        reader.expect_end()?;
        let public_key = PublicKey::from_algorithm(&algorithm, &key)?;
        Ok(SubjectPublicKeyInfo {
            algorithm,
            key,
            public_key,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.algorithm.encode();
        content.extend_from_slice(&der::bit_string(0, &self.key));
        der::sequence(&content)
    }

    /// Build from a decoded public key.
    pub fn from_public_key(public_key: &PublicKey) -> CryptoResult<Self> {
        let (algorithm, key) = public_key.to_algorithm_and_key()?;
        Ok(SubjectPublicKeyInfo {
            algorithm,
            key,
            public_key: public_key.clone(),
        })
    }

    /// The RFC 5280 method-1 key identifier: SHA-1 of the BIT STRING
    /// contents.
    pub fn key_identifier(&self) -> CryptoResult<Vec<u8>> {
        let digest = super::algorithm::Hash::Sha1.digest(&self.key)?;
        Ok(digest)
    }
}

impl PublicKey {
    /// Decode a key from an SPKI algorithm identifier and BIT STRING
    /// contents.
    pub fn from_algorithm(algorithm: &AlgorithmIdentifier, key: &[u8]) -> CryptoResult<Self> {
        if algorithm.oid.matches(oid::OID_RSA_ENCRYPTION) {
            let (n, e) = crate::rsa::der::parse_rsa_public_key(key)?;
            return Ok(PublicKey::Rsa(RsaPublicKey::from_components(&n, &e)?));
        }
        if algorithm.oid.matches(oid::OID_SM2) {
            // Bare SM2 algorithm; parameters, when present, must be the SM2
            // curve OID.
            if let Some(params) = &algorithm.parameters {
                if !algorithm.is_null() {
                    let mut reader = Reader::new(params);
                    let params_oid = reader.read_oid()?;
                    if !params_oid.matches(oid::OID_SM2) {
                        return Err(CryptoError::UnsupportedOperation(
                            "unsupported SM2 parameters".to_string(),
                        ));
                    }
                }
            }
            let curve = crate::sm2::sm2_curve();
            return Ok(PublicKey::Sm2(Point::from_bytes(&curve, key)?));
        }
        if algorithm.oid.matches(oid::OID_EC_PUBLIC_KEY) {
            let params = algorithm
                .parameters
                .as_deref()
                .ok_or(CryptoError::StrError("x509: missing EC curve parameters"))?;
            let mut reader = Reader::new(params);
            let curve_oid = reader.read_oid()?;
            if curve_oid.matches(oid::OID_SM2) {
                let curve = crate::sm2::sm2_curve();
                return Ok(PublicKey::Sm2(Point::from_bytes(&curve, key)?));
            }
            if curve_oid.matches(oid::OID_SECP256K1) {
                return Err(CryptoError::UnsupportedOperation(
                    "secp256k1 is not implemented".to_string(),
                ));
            }
            let curve_id = curve_id_from_oid(&curve_oid).ok_or_else(|| {
                CryptoError::UnsupportedOperation("unsupported named curve".to_string())
            })?;
            let curve = ec::curve(curve_id);
            return Ok(PublicKey::Ec {
                curve: curve_id,
                point: Point::from_bytes(&curve, key)?,
            });
        }
        if algorithm.oid.matches(oid::OID_ED25519) {
            let key: [u8; 32] = key
                .try_into()
                .map_err(|_| CryptoError::StrError("x509: invalid Ed25519 key size"))?;
            return Ok(PublicKey::Ed25519(key));
        }
        if algorithm.oid.matches(oid::OID_ED448) {
            let key: [u8; 57] = key
                .try_into()
                .map_err(|_| CryptoError::StrError("x509: invalid Ed448 key size"))?;
            return Ok(PublicKey::Ed448(key));
        }
        if algorithm.oid.matches(oid::OID_X25519) {
            let key: [u8; 32] = key
                .try_into()
                .map_err(|_| CryptoError::StrError("x509: invalid X25519 key size"))?;
            return Ok(PublicKey::X25519(key));
        }
        if algorithm.oid.matches(oid::OID_X448) {
            let key: [u8; 56] = key
                .try_into()
                .map_err(|_| CryptoError::StrError("x509: invalid X448 key size"))?;
            return Ok(PublicKey::X448(key));
        }
        if algorithm.oid.matches(oid::OID_DSA) {
            let params_der = algorithm
                .parameters
                .as_deref()
                .ok_or(CryptoError::StrError(
                    "x509: DSA parameters missing from SPKI",
                ))?;
            let params = parse_dsa_params(params_der)?;
            let mut reader = Reader::new(key);
            let y = Bn::from_be_bytes(reader.read_integer()?);
            reader.expect_end()?;
            return Ok(PublicKey::Dsa { params, y });
        }
        if let Some(variant) = ml_dsa_from_oid(&algorithm.oid) {
            let key = MlDsaPublicKey::from_bytes(variant, key)?;
            return Ok(PublicKey::MlDsa(key));
        }
        if let Some(variant) = slh_dsa_from_oid(&algorithm.oid) {
            let key = SlhDsaPublicKey::from_bytes(variant, key)?;
            return Ok(PublicKey::SlhDsa(key));
        }
        Err(CryptoError::UnsupportedOperation(alloc::format!(
            "unsupported public key algorithm {}",
            algorithm.oid
        )))
    }

    /// Encode as `(AlgorithmIdentifier, BIT STRING payload)`.
    pub fn to_algorithm_and_key(&self) -> CryptoResult<(AlgorithmIdentifier, Vec<u8>)> {
        match self {
            PublicKey::Rsa(key) => Ok((
                AlgorithmIdentifier::with_null(
                    ObjectIdentifier::new(oid::OID_RSA_ENCRYPTION).expect("static oid"),
                ),
                crate::rsa::der::rsa_public_key_der(&key.n(), &key.e()),
            )),
            PublicKey::Ec { curve, point } => {
                let curve_oid = curve_id_to_oid(*curve);
                Ok((
                    AlgorithmIdentifier::new(
                        ObjectIdentifier::new(oid::OID_EC_PUBLIC_KEY).expect("static oid"),
                        Some(der::oid(
                            &ObjectIdentifier::new(curve_oid).expect("static oid"),
                        )),
                    ),
                    point.to_bytes_with(&ec::curve(*curve)),
                ))
            }
            PublicKey::Ed25519(key) => Ok((
                AlgorithmIdentifier::new(
                    ObjectIdentifier::new(oid::OID_ED25519).expect("static oid"),
                    None,
                ),
                key.to_vec(),
            )),
            PublicKey::Ed448(key) => Ok((
                AlgorithmIdentifier::new(
                    ObjectIdentifier::new(oid::OID_ED448).expect("static oid"),
                    None,
                ),
                key.to_vec(),
            )),
            PublicKey::X25519(key) => Ok((
                AlgorithmIdentifier::new(
                    ObjectIdentifier::new(oid::OID_X25519).expect("static oid"),
                    None,
                ),
                key.to_vec(),
            )),
            PublicKey::X448(key) => Ok((
                AlgorithmIdentifier::new(
                    ObjectIdentifier::new(oid::OID_X448).expect("static oid"),
                    None,
                ),
                key.to_vec(),
            )),
            PublicKey::Sm2(point) => Ok((
                AlgorithmIdentifier::new(
                    ObjectIdentifier::new(oid::OID_EC_PUBLIC_KEY).expect("static oid"),
                    Some(der::oid(
                        &ObjectIdentifier::new(oid::OID_SM2).expect("static oid"),
                    )),
                ),
                point.to_bytes_with(&crate::sm2::sm2_curve()),
            )),
            PublicKey::Dsa { params, y } => {
                let mut params_content = der::integer(&params.p.to_be_bytes());
                params_content.extend_from_slice(&der::integer(&params.q.to_be_bytes()));
                params_content.extend_from_slice(&der::integer(&params.g.to_be_bytes()));
                Ok((
                    AlgorithmIdentifier::new(
                        ObjectIdentifier::new(oid::OID_DSA).expect("static oid"),
                        Some(der::sequence(&params_content)),
                    ),
                    der::integer(&y.to_be_bytes()),
                ))
            }
            PublicKey::MlDsa(key) => Ok((
                AlgorithmIdentifier::new(
                    ObjectIdentifier::new(ml_dsa_oid(key.variant())).expect("static oid"),
                    None,
                ),
                key.to_bytes(),
            )),
            PublicKey::SlhDsa(key) => Ok((
                AlgorithmIdentifier::new(
                    ObjectIdentifier::new(slh_dsa_oid(key.variant())).expect("static oid"),
                    None,
                ),
                key.to_bytes().to_vec(),
            )),
            PublicKey::Unknown { algorithm, key } => Ok((algorithm.clone(), key.clone())),
        }
    }
}

/// A private key of any supported type.
#[derive(Clone)]
pub enum PrivateKey {
    /// RSA private key.
    Rsa(RsaPrivateKey),
    /// NIST-curve EC private key with its scalar.
    Ec {
        /// Curve identifier.
        curve: CurveId,
        /// Private scalar.
        scalar: Bn,
    },
    /// Ed25519 seed.
    Ed25519([u8; 32]),
    /// Ed448 seed.
    Ed448([u8; 57]),
    /// X25519 key (key agreement only).
    X25519([u8; 32]),
    /// X448 key (key agreement only).
    X448([u8; 56]),
    /// SM2 private scalar.
    Sm2(Bn),
    /// DSA key pair.
    Dsa(DsaKeyPair),
    /// ML-DSA private key.
    MlDsa(MlDsaPrivateKey),
    /// SLH-DSA private key.
    SlhDsa(SlhDsaPrivateKey),
}

impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PrivateKey::Rsa(_) => f.write_str("PrivateKey::Rsa"),
            PrivateKey::Ec { curve, .. } => write!(f, "PrivateKey::Ec({curve:?})"),
            PrivateKey::Ed25519(_) => f.write_str("PrivateKey::Ed25519"),
            PrivateKey::Ed448(_) => f.write_str("PrivateKey::Ed448"),
            PrivateKey::X25519(_) => f.write_str("PrivateKey::X25519"),
            PrivateKey::X448(_) => f.write_str("PrivateKey::X448"),
            PrivateKey::Sm2(_) => f.write_str("PrivateKey::Sm2"),
            PrivateKey::Dsa(_) => f.write_str("PrivateKey::Dsa"),
            PrivateKey::MlDsa(key) => write!(f, "PrivateKey::MlDsa({:?})", key.variant()),
            PrivateKey::SlhDsa(key) => write!(f, "PrivateKey::SlhDsa({:?})", key.variant()),
        }
    }
}

impl PrivateKey {
    /// Derive the matching public key.
    pub fn public_key(&self) -> CryptoResult<PublicKey> {
        match self {
            PrivateKey::Rsa(key) => Ok(PublicKey::Rsa(key.public().clone())),
            PrivateKey::Ec { curve, scalar } => {
                let curve_ref = ec::curve(*curve);
                let point = ec::mul_base(&curve_ref, scalar);
                Ok(PublicKey::Ec {
                    curve: *curve,
                    point,
                })
            }
            PrivateKey::Ed25519(secret) => Ok(PublicKey::Ed25519(
                crate::ed25519::public_from_secret(secret),
            )),
            PrivateKey::Ed448(secret) => {
                Ok(PublicKey::Ed448(crate::ed448::public_from_secret(secret)))
            }
            PrivateKey::X25519(secret) => Ok(PublicKey::X25519(
                crate::x25519::public_from_private(secret),
            )),
            PrivateKey::X448(secret) => {
                Ok(PublicKey::X448(crate::x448::public_from_private(secret)))
            }
            PrivateKey::Sm2(scalar) => {
                let curve = crate::sm2::sm2_curve();
                Ok(PublicKey::Sm2(ec::mul_base(&curve, scalar)))
            }
            PrivateKey::Dsa(key) => Ok(PublicKey::Dsa {
                params: key.params.clone(),
                y: key.y.clone(),
            }),
            PrivateKey::MlDsa(key) => Ok(PublicKey::MlDsa(key.public_key()?)),
            PrivateKey::SlhDsa(key) => Ok(PublicKey::SlhDsa(key.public_key())),
        }
    }

    /// Sign `msg` with the given algorithm.
    ///
    /// SM2 signatures use the GM/T default identity; see
    /// [`Self::sign_with_sm2_id`] for a different one.
    pub fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        msg: &[u8],
        rng: &mut impl Rng,
    ) -> CryptoResult<Vec<u8>> {
        self.sign_with_sm2_id(algorithm, msg, crate::sm2::DEFAULT_ID, rng)
    }

    /// Sign `msg` with an explicit SM2 identity.
    pub fn sign_with_sm2_id(
        &self,
        algorithm: SignatureAlgorithm,
        msg: &[u8],
        sm2_id: &[u8],
        rng: &mut impl Rng,
    ) -> CryptoResult<Vec<u8>> {
        use SignatureAlgorithm as Alg;
        match (algorithm, self) {
            (Alg::RsaPkcs1v15(hash), PrivateKey::Rsa(key)) => {
                key.sign_pkcs1v15(hash.factory(), msg)
            }
            (Alg::RsaPss { hash, salt_len }, PrivateKey::Rsa(key)) => {
                key.sign_pss(hash.factory(), msg, salt_len, rng)
            }
            (Alg::Ecdsa(hash), PrivateKey::Ec { curve, scalar }) => {
                let digest = hash.digest_id().ok_or_else(|| {
                    CryptoError::UnsupportedOperation("digest not usable with ECDSA".to_string())
                })?;
                let (r, s) = crate::ecdsa::sign(*curve, digest, scalar, msg, rng)?;
                Ok(super::algorithm::encode_ecdsa_signature(&r, &s))
            }
            (Alg::Ed25519, PrivateKey::Ed25519(secret)) => {
                Ok(crate::ed25519::sign(secret, msg).to_vec())
            }
            (Alg::Ed448, PrivateKey::Ed448(secret)) => {
                Ok(crate::ed448::sign(secret, msg, b"").to_vec())
            }
            (Alg::Sm2, PrivateKey::Sm2(scalar)) => {
                let (r, s) = crate::sm2::sign(scalar, msg, sm2_id, rng)?;
                Ok(super::algorithm::encode_ecdsa_signature(&r, &s))
            }
            (Alg::Dsa(hash), PrivateKey::Dsa(key)) => {
                let digest = hash.digest_id().ok_or_else(|| {
                    CryptoError::UnsupportedOperation("digest not usable with DSA".to_string())
                })?;
                let (r, s) = crate::dsa::sign(key, digest, msg, rng)?;
                Ok(super::algorithm::encode_ecdsa_signature(&r, &s))
            }
            (Alg::MlDsa(_), PrivateKey::MlDsa(key)) => ml_dsa::sign(key, msg, b"", None),
            (Alg::SlhDsa(_), PrivateKey::SlhDsa(key)) => slh_dsa::sign(key, msg, b"", false),
            _ => Err(CryptoError::UnsupportedOperation(
                "signature algorithm does not match private key".to_string(),
            )),
        }
    }
}

/// PKCS#8 `PrivateKeyInfo`.
#[derive(Clone)]
pub struct PrivateKeyInfo {
    /// Key algorithm.
    pub algorithm: AlgorithmIdentifier,
    /// The private key octets.
    pub private_key: Vec<u8>,
    /// Raw `[0] IMPLICIT` attributes, when present.
    pub attributes: Option<Vec<u8>>,
    /// Raw `[1] IMPLICIT` public-key BIT STRING payload, when present.
    pub public_key: Option<Vec<u8>>,
}

impl core::fmt::Debug for PrivateKeyInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKeyInfo")
            .field("algorithm", &self.algorithm.oid)
            .finish()
    }
}

impl PrivateKeyInfo {
    /// Parse DER `PrivateKeyInfo`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let _version = seq.read_integer()?;
        let algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        let private_key = seq.read_octet_string()?.to_vec();
        let mut attributes = None;
        let mut public_key = None;
        while !seq.is_empty() {
            let tag = seq.peek_tag()?;
            match (tag.class, tag.number) {
                (der::Class::ContextSpecific, 0) => {
                    attributes = Some(seq.read_implicit(0, true)?.to_vec());
                }
                (der::Class::ContextSpecific, 1) => {
                    let content = seq.read_implicit(1, false)?;
                    let (unused, data) = content
                        .split_first()
                        .ok_or(CryptoError::StrError("x509: empty public key"))?;
                    if *unused != 0 {
                        return Err(CryptoError::StrError("x509: invalid public key padding"));
                    }
                    public_key = Some(data.to_vec());
                }
                _ => return Err(CryptoError::StrError("x509: invalid PKCS#8 attribute")),
            }
        }
        reader.expect_end()?;
        Ok(PrivateKeyInfo {
            algorithm,
            private_key,
            attributes,
            public_key,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = der::integer(&[]);
        content.extend_from_slice(&self.algorithm.encode());
        content.extend_from_slice(&der::octet_string(&self.private_key));
        if let Some(attributes) = &self.attributes {
            content.extend_from_slice(&der::implicit(0, true, attributes));
        }
        if let Some(public_key) = &self.public_key {
            let mut bit_string_content = vec![0u8];
            bit_string_content.extend_from_slice(public_key);
            content.extend_from_slice(&der::implicit(1, false, &bit_string_content));
        }
        der::sequence(&content)
    }

    /// Decode the private key according to its algorithm.
    pub fn decode(&self) -> CryptoResult<PrivateKey> {
        let oid = &self.algorithm.oid;
        if oid.matches(oid::OID_RSA_ENCRYPTION) {
            let rsa = crate::rsa::der::parse_rsa_private_key(&self.private_key)?;
            return Ok(PrivateKey::Rsa(RsaPrivateKey::from_components(
                &rsa.0,
                &rsa.1,
                &rsa.2,
                Some(&rsa.3),
                Some(&rsa.4),
                Some(&rsa.5),
                Some(&rsa.6),
                Some(&rsa.7),
            )?));
        }
        if oid.matches(oid::OID_EC_PUBLIC_KEY) || oid.matches(oid::OID_SM2) {
            let (curve_oid, scalar) = parse_ec_private_key(&self.private_key, &self.algorithm)?;
            if curve_oid.matches(oid::OID_SM2) {
                return Ok(PrivateKey::Sm2(scalar));
            }
            let curve_id = curve_id_from_oid(&curve_oid).ok_or_else(|| {
                CryptoError::UnsupportedOperation("unsupported named curve".to_string())
            })?;
            return Ok(PrivateKey::Ec {
                curve: curve_id,
                scalar,
            });
        }
        if oid.matches(oid::OID_ED25519) {
            return Ok(PrivateKey::Ed25519(curve_key(&self.private_key)?));
        }
        if oid.matches(oid::OID_ED448) {
            return Ok(PrivateKey::Ed448(curve_key(&self.private_key)?));
        }
        if oid.matches(oid::OID_X25519) {
            return Ok(PrivateKey::X25519(curve_key(&self.private_key)?));
        }
        if oid.matches(oid::OID_X448) {
            return Ok(PrivateKey::X448(curve_key(&self.private_key)?));
        }
        if oid.matches(oid::OID_DSA) {
            let params_der = self
                .algorithm
                .parameters
                .as_deref()
                .ok_or(CryptoError::StrError("x509: DSA parameters missing"))?;
            let params = parse_dsa_params(params_der)?;
            let mut reader = Reader::new(&self.private_key);
            let x = Bn::from_be_bytes(reader.read_integer()?);
            if !reader.is_empty() {
                return Err(CryptoError::StrError("x509: trailing DSA key data"));
            }
            let y = params.g.mod_pow(&x, &params.p)?;
            return Ok(PrivateKey::Dsa(DsaKeyPair { params, x, y }));
        }
        if let Some(variant) = ml_dsa_from_oid(oid) {
            return Ok(PrivateKey::MlDsa(decode_ml_dsa_private_key(
                variant,
                &self.private_key,
            )?));
        }
        if let Some(variant) = slh_dsa_from_oid(oid) {
            let key = if self.private_key.len() == variant.private_key_len() {
                SlhDsaPrivateKey::from_bytes(variant, &self.private_key)?
            } else {
                slh_dsa::keygen(variant, &self.private_key)?.1
            };
            return Ok(PrivateKey::SlhDsa(key));
        }
        Err(CryptoError::UnsupportedOperation(alloc::format!(
            "unsupported private key algorithm {}",
            oid
        )))
    }
}

/// PKCS#8 `EncryptedPrivateKeyInfo`.
#[derive(Clone)]
pub struct EncryptedPrivateKeyInfo {
    /// Encryption algorithm identifier (PBES2 or a legacy PBE).
    pub algorithm: AlgorithmIdentifier,
    /// The encrypted PKCS#8 octets.
    pub encrypted_data: Vec<u8>,
}

impl core::fmt::Debug for EncryptedPrivateKeyInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncryptedPrivateKeyInfo")
            .field("algorithm", &self.algorithm.oid)
            .finish()
    }
}

impl EncryptedPrivateKeyInfo {
    /// Parse DER `EncryptedPrivateKeyInfo`.
    pub fn parse(der: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let algorithm = AlgorithmIdentifier::parse(&mut seq)?;
        let encrypted_data = seq.read_octet_string()?.to_vec();
        seq.expect_end()?;
        reader.expect_end()?;
        Ok(EncryptedPrivateKeyInfo {
            algorithm,
            encrypted_data,
        })
    }

    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = self.algorithm.encode();
        content.extend_from_slice(&der::octet_string(&self.encrypted_data));
        der::sequence(&content)
    }
}

/// Encode an EC private key as RFC 5915 `ECPrivateKey`, including the public
/// key.
pub fn encode_ec_private_key(
    curve_oid: &[u64],
    scalar: &Bn,
    public_key: Option<&[u8]>,
) -> CryptoResult<Vec<u8>> {
    let curve = ec_curve_from_oid(curve_oid)?;
    let width = ec::field_bytes(&curve);
    let mut content = der::integer(&[1]);
    content.extend_from_slice(&der::octet_string(&scalar.to_be_bytes_padded(width)?));
    content.extend_from_slice(&der::explicit(
        0,
        &der::oid(&ObjectIdentifier::new(curve_oid).expect("static oid")),
    ));
    if let Some(public_key) = public_key {
        content.extend_from_slice(&der::explicit(1, &der::bit_string(0, public_key)));
    }
    Ok(der::sequence(&content))
}

/// Parse an RFC 5915 `ECPrivateKey`, returning the curve OID and scalar.
///
/// The curve is taken from the embedded `[0] parameters` when present,
/// falling back to the PKCS#8 algorithm parameters.
pub(crate) fn parse_ec_private_key(
    der: &[u8],
    algorithm: &AlgorithmIdentifier,
) -> CryptoResult<(ObjectIdentifier, Bn)> {
    let mut reader = Reader::new(der);
    let mut seq = reader.read_sequence()?;
    let version = seq.read_integer_i64()?;
    if version != 1 {
        return Err(CryptoError::StrError("x509: invalid EC key version"));
    }
    let scalar = Bn::from_be_bytes(seq.read_octet_string()?);
    let mut curve_oid = None;
    while !seq.is_empty() {
        let tag = seq.peek_tag()?;
        match tag.number {
            0 if tag.class == der::Class::ContextSpecific => {
                let mut inner = seq.read_explicit(0)?;
                curve_oid = Some(inner.read_oid()?);
            }
            1 if tag.class == der::Class::ContextSpecific => {
                // RFC 5915 uses EXPLICIT tags: [1] wraps a BIT STRING.
                let mut inner = seq.read_explicit(1)?;
                inner.read_bit_string()?;
            }
            _ => return Err(CryptoError::StrError("x509: invalid EC private key")),
        }
    }
    let curve_oid = match curve_oid {
        Some(value) => value,
        None => {
            let params = algorithm
                .parameters
                .as_deref()
                .ok_or(CryptoError::StrError(
                    "x509: EC curve missing from private key",
                ))?;
            let mut reader = Reader::new(params);
            reader.read_oid()?
        }
    };
    Ok((curve_oid, scalar))
}

/// Unwrap an RFC 8410 `CurvePrivateKey` octet string, tolerating both the
/// nested OCTET STRING form OpenSSL emits and the bare form.
fn curve_key<const N: usize>(bytes: &[u8]) -> CryptoResult<[u8; N]> {
    let inner: &[u8] = if bytes.len() == N {
        bytes
    } else {
        let mut reader = Reader::new(bytes);
        reader.read_octet_string()?
    };
    inner
        .try_into()
        .map_err(|_| CryptoError::StrError("x509: invalid curve private key size"))
}

/// Parse `DSA-Params ::= SEQUENCE { p, q, g }`.
pub(crate) fn parse_dsa_params(der: &[u8]) -> CryptoResult<DsaParams> {
    let mut reader = Reader::new(der);
    let mut seq = reader.read_sequence()?;
    let p = Bn::from_be_bytes(seq.read_integer()?);
    let q = Bn::from_be_bytes(seq.read_integer()?);
    let g = Bn::from_be_bytes(seq.read_integer()?);
    seq.expect_end()?;
    reader.expect_end()?;
    Ok(DsaParams { p, q, g })
}

/// Decode an ML-DSA private key from PKCS#8 octets.
///
/// Accepts the bare FIPS 204 encoding, the 32-byte seed, and the OpenSSL
/// wrapper `SEQUENCE { OCTET STRING seed, OCTET STRING expanded-key }`.
fn decode_ml_dsa_private_key(variant: MlDsaVariant, bytes: &[u8]) -> CryptoResult<MlDsaPrivateKey> {
    if bytes.len() == 32 {
        let seed: [u8; 32] = bytes.try_into().expect("length checked");
        return Ok(ml_dsa::keygen(variant, &seed)?.1);
    }
    if bytes.len() == crate::ml_dsa::private_key_size(variant) {
        return MlDsaPrivateKey::from_bytes(variant, bytes);
    }
    let mut reader = Reader::new(bytes);
    let mut seq = reader.read_sequence()?;
    let first = seq.read_octet_string()?;
    if first.len() == 32 {
        let seed: [u8; 32] = first.try_into().expect("length checked");
        return Ok(ml_dsa::keygen(variant, &seed)?.1);
    }
    MlDsaPrivateKey::from_bytes(variant, first)
}

/// Map an EC curve OID to its [`Curve`](crate::ec::Curve).
pub(crate) fn ec_curve_from_oid(oid: &[u64]) -> CryptoResult<crate::ec::Curve> {
    if oid == oid::OID_SM2 {
        return Ok(crate::sm2::sm2_curve());
    }
    let curve_id = curve_id_from_oid_slice(oid)
        .ok_or_else(|| CryptoError::UnsupportedOperation("unsupported named curve".to_string()))?;
    Ok(ec::curve(curve_id))
}

/// Map a curve OID to the NIST curve id.
pub(crate) fn curve_id_from_oid(oid: &ObjectIdentifier) -> Option<CurveId> {
    if oid.matches(oid::OID_SECP256R1) {
        Some(CurveId::P256)
    } else if oid.matches(oid::OID_SECP384R1) {
        Some(CurveId::P384)
    } else if oid.matches(oid::OID_SECP521R1) {
        Some(CurveId::P521)
    } else {
        None
    }
}

fn curve_id_from_oid_slice(oid: &[u64]) -> Option<CurveId> {
    if oid == oid::OID_SECP256R1 {
        Some(CurveId::P256)
    } else if oid == oid::OID_SECP384R1 {
        Some(CurveId::P384)
    } else if oid == oid::OID_SECP521R1 {
        Some(CurveId::P521)
    } else {
        None
    }
}

/// The OID of a NIST curve.
pub(crate) fn curve_id_to_oid(curve: CurveId) -> &'static [u64] {
    match curve {
        CurveId::P256 => oid::OID_SECP256R1,
        CurveId::P384 => oid::OID_SECP384R1,
        CurveId::P521 => oid::OID_SECP521R1,
    }
}

/// The OID of an ML-DSA parameter set.
pub(crate) fn ml_dsa_oid(variant: MlDsaVariant) -> &'static [u64] {
    match variant {
        MlDsaVariant::MlDsa44 => oid::OID_ML_DSA_44,
        MlDsaVariant::MlDsa65 => oid::OID_ML_DSA_65,
        MlDsaVariant::MlDsa87 => oid::OID_ML_DSA_87,
    }
}

/// Look up an ML-DSA parameter set by OID.
pub(crate) fn ml_dsa_from_oid(oid: &ObjectIdentifier) -> Option<MlDsaVariant> {
    [
        MlDsaVariant::MlDsa44,
        MlDsaVariant::MlDsa65,
        MlDsaVariant::MlDsa87,
    ]
    .into_iter()
    .find(|variant| oid.matches(ml_dsa_oid(*variant)))
}

/// The OID of an SLH-DSA parameter set.
pub(crate) fn slh_dsa_oid(variant: SlhDsaVariant) -> &'static [u64] {
    match variant {
        SlhDsaVariant::Sha2_128s => oid::OID_SLH_DSA_SHA2_128S,
        SlhDsaVariant::Sha2_128f => oid::OID_SLH_DSA_SHA2_128F,
        SlhDsaVariant::Sha2_192s => oid::OID_SLH_DSA_SHA2_192S,
        SlhDsaVariant::Sha2_192f => oid::OID_SLH_DSA_SHA2_192F,
        SlhDsaVariant::Sha2_256s => oid::OID_SLH_DSA_SHA2_256S,
        SlhDsaVariant::Sha2_256f => oid::OID_SLH_DSA_SHA2_256F,
        SlhDsaVariant::Shake_128s => oid::OID_SLH_DSA_SHAKE_128S,
        SlhDsaVariant::Shake_128f => oid::OID_SLH_DSA_SHAKE_128F,
        SlhDsaVariant::Shake_192s => oid::OID_SLH_DSA_SHAKE_192S,
        SlhDsaVariant::Shake_192f => oid::OID_SLH_DSA_SHAKE_192F,
        SlhDsaVariant::Shake_256s => oid::OID_SLH_DSA_SHAKE_256S,
        SlhDsaVariant::Shake_256f => oid::OID_SLH_DSA_SHAKE_256F,
    }
}

/// Look up an SLH-DSA parameter set by OID.
pub(crate) fn slh_dsa_from_oid(oid: &ObjectIdentifier) -> Option<SlhDsaVariant> {
    SlhDsaVariant::all()
        .iter()
        .find(|variant| oid.matches(slh_dsa_oid(**variant)))
        .copied()
}

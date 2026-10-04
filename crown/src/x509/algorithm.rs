//! Algorithm identifiers, digests and signature algorithm dispatch.

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::{self, ObjectIdentifier};
use crate::core::CoreWrite;
use crate::ecdsa::DigestId;
use crate::envelope::EvpHash;
use crate::error::{CryptoError, CryptoResult};
use crate::kdf::HashFactory;
use crate::ml_dsa::MlDsaVariant;
use crate::slh_dsa::SlhDsaVariant;

use super::keys::{PrivateKey, PublicKey};

/// `SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }`.
///
/// `parameters` keeps the raw DER of the parameter element so re-encoding is
/// byte-exact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmIdentifier {
    /// The algorithm OID.
    pub oid: ObjectIdentifier,
    /// Raw DER of the optional parameters element.
    pub parameters: Option<Vec<u8>>,
}

impl AlgorithmIdentifier {
    /// Build from an OID and optional raw parameter DER.
    pub fn new(oid: ObjectIdentifier, parameters: Option<Vec<u8>>) -> Self {
        AlgorithmIdentifier { oid, parameters }
    }

    /// Build with an explicit NULL parameter.
    pub fn with_null(oid: ObjectIdentifier) -> Self {
        AlgorithmIdentifier {
            oid,
            parameters: Some(der::null()),
        }
    }

    /// Parse an `AlgorithmIdentifier`.
    pub fn parse(reader: &mut Reader<'_>) -> CryptoResult<Self> {
        let mut seq = reader.read_sequence()?;
        let oid = seq.read_oid()?;
        let parameters = if seq.is_empty() {
            None
        } else {
            Some(seq.read_raw_tlv()?.to_vec())
        };
        seq.expect_end()?;
        Ok(AlgorithmIdentifier { oid, parameters })
    }

    /// Encode as `SEQUENCE { OID, parameters }`.
    pub fn encode(&self) -> Vec<u8> {
        der::algorithm_identifier(&self.oid, self.parameters.as_deref())
    }

    /// Whether the parameters are absent or the DER NULL value.
    pub fn is_null(&self) -> bool {
        match &self.parameters {
            None => true,
            Some(p) => p.as_slice() == [0x05, 0x00],
        }
    }
}

/// A supported digest algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    /// MD2.
    Md2,
    /// MD4.
    Md4,
    /// MD5.
    Md5,
    /// SHA-1.
    Sha1,
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA-512/224.
    Sha512_224,
    /// SHA-512/256.
    Sha512_256,
    /// SHA3-224.
    Sha3_224,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
    /// SM3.
    Sm3,
    /// RIPEMD-160.
    Ripemd160,
}

impl Hash {
    /// Digest algorithm OID.
    pub fn oid(self) -> &'static [u64] {
        match self {
            Hash::Md2 => oid::OID_MD2,
            Hash::Md4 => oid::OID_MD4,
            Hash::Md5 => oid::OID_MD5,
            Hash::Sha1 => oid::OID_SHA1,
            Hash::Sha224 => oid::OID_SHA224,
            Hash::Sha256 => oid::OID_SHA256,
            Hash::Sha384 => oid::OID_SHA384,
            Hash::Sha512 => oid::OID_SHA512,
            Hash::Sha512_224 => oid::OID_SHA512_224,
            Hash::Sha512_256 => oid::OID_SHA512_256,
            Hash::Sha3_224 => oid::OID_SHA3_224,
            Hash::Sha3_256 => oid::OID_SHA3_256,
            Hash::Sha3_384 => oid::OID_SHA3_384,
            Hash::Sha3_512 => oid::OID_SHA3_512,
            Hash::Sm3 => oid::OID_SM3,
            Hash::Ripemd160 => oid::OID_RIPEMD160,
        }
    }

    /// Look up a digest by OID.
    pub fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        const ALL: [Hash; 16] = [
            Hash::Md2,
            Hash::Md4,
            Hash::Md5,
            Hash::Sha1,
            Hash::Sha224,
            Hash::Sha256,
            Hash::Sha384,
            Hash::Sha512,
            Hash::Sha512_224,
            Hash::Sha512_256,
            Hash::Sha3_224,
            Hash::Sha3_256,
            Hash::Sha3_384,
            Hash::Sha3_512,
            Hash::Sm3,
            Hash::Ripemd160,
        ];
        ALL.into_iter().find(|hash| oid.matches(hash.oid()))
    }

    /// Output size in bytes.
    pub fn output_len(self) -> usize {
        match self {
            Hash::Md2 | Hash::Md4 | Hash::Md5 => 16,
            Hash::Sha1 | Hash::Ripemd160 => 20,
            Hash::Sha224 | Hash::Sha512_224 | Hash::Sha3_224 => 28,
            Hash::Sha256 | Hash::Sha512_256 | Hash::Sha3_256 | Hash::Sm3 => 32,
            Hash::Sha384 | Hash::Sha3_384 => 48,
            Hash::Sha512 | Hash::Sha3_512 => 64,
        }
    }

    /// [`EvpHash`] factory for this digest.
    pub fn factory(self) -> HashFactory {
        match self {
            Hash::Md2 => EvpHash::new_md2,
            Hash::Md4 => EvpHash::new_md4,
            Hash::Md5 => EvpHash::new_md5,
            Hash::Sha1 => EvpHash::new_sha1,
            Hash::Sha224 => EvpHash::new_sha224,
            Hash::Sha256 => EvpHash::new_sha256,
            Hash::Sha384 => EvpHash::new_sha384,
            Hash::Sha512 => EvpHash::new_sha512,
            Hash::Sha512_224 => EvpHash::new_sha512_224,
            Hash::Sha512_256 => EvpHash::new_sha512_256,
            Hash::Sha3_224 => EvpHash::new_sha3_224,
            Hash::Sha3_256 => EvpHash::new_sha3_256,
            Hash::Sha3_384 => EvpHash::new_sha3_384,
            Hash::Sha3_512 => EvpHash::new_sha3_512,
            Hash::Sm3 => EvpHash::new_sm3,
            Hash::Ripemd160 => EvpHash::new_ripemd160,
        }
    }

    /// One-shot digest of `msg`.
    pub fn digest(self, msg: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut hasher = (self.factory())()?;
        hasher.write_all(msg)?;
        Ok(hasher.sum())
    }

    /// The ECDSA/DSA digest id, when the algorithm supports this digest.
    pub fn digest_id(self) -> Option<DigestId> {
        Some(match self {
            Hash::Sha1 => DigestId::Sha1,
            Hash::Sha224 => DigestId::Sha224,
            Hash::Sha256 => DigestId::Sha256,
            Hash::Sha384 => DigestId::Sha384,
            Hash::Sha512 => DigestId::Sha512,
            Hash::Sha3_224 => DigestId::Sha3_224,
            Hash::Sha3_256 => DigestId::Sha3_256,
            Hash::Sha3_384 => DigestId::Sha3_384,
            Hash::Sha3_512 => DigestId::Sha3_512,
            Hash::Sm3 => DigestId::Sm3,
            Hash::Ripemd160 => DigestId::Ripemd160,
            Hash::Md2 | Hash::Md4 | Hash::Md5 | Hash::Sha512_224 | Hash::Sha512_256 => {
                return None;
            }
        })
    }

    /// One-shot HMAC of `msg` under `key`.
    pub(crate) fn hmac(self, key: &[u8], msg: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut mac = match self {
            Hash::Md2 => EvpHash::new_md2_hmac(key),
            Hash::Md4 => EvpHash::new_md4_hmac(key),
            Hash::Md5 => EvpHash::new_md5_hmac(key),
            Hash::Sha1 => EvpHash::new_sha1_hmac(key),
            Hash::Sha224 => EvpHash::new_sha224_hmac(key),
            Hash::Sha256 => EvpHash::new_sha256_hmac(key),
            Hash::Sha384 => EvpHash::new_sha384_hmac(key),
            Hash::Sha512 => EvpHash::new_sha512_hmac(key),
            Hash::Sha512_224 => EvpHash::new_sha512_224_hmac(key),
            Hash::Sha512_256 => EvpHash::new_sha512_256_hmac(key),
            Hash::Sha3_224 => EvpHash::new_sha3_224_hmac(key),
            Hash::Sha3_256 => EvpHash::new_sha3_256_hmac(key),
            Hash::Sha3_384 => EvpHash::new_sha3_384_hmac(key),
            Hash::Sha3_512 => EvpHash::new_sha3_512_hmac(key),
            Hash::Sm3 => EvpHash::new_sm3_hmac(key),
            Hash::Ripemd160 => EvpHash::new_ripemd160_hmac(key),
        }?;
        mac.write_all(msg)?;
        Ok(mac.sum())
    }
}

/// A signature algorithm as used by certificates, CSRs and CMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 with the given digest.
    RsaPkcs1v15(Hash),
    /// RSASSA-PSS with the given digest and salt length.
    RsaPss {
        /// Digest algorithm.
        hash: Hash,
        /// Salt length in bytes.
        salt_len: usize,
    },
    /// ECDSA with the given digest.
    Ecdsa(Hash),
    /// Ed25519 (PureEdDSA).
    Ed25519,
    /// Ed448 (PureEdDSA).
    Ed448,
    /// SM2 with SM3.
    Sm2,
    /// DSA with the given digest.
    Dsa(Hash),
    /// ML-DSA.
    MlDsa(MlDsaVariant),
    /// SLH-DSA.
    SlhDsa(SlhDsaVariant),
}

impl SignatureAlgorithm {
    /// Map an `AlgorithmIdentifier` to a signature algorithm, parsing
    /// RSASSA-PSS parameters.
    pub fn from_identifier(alg: &AlgorithmIdentifier) -> CryptoResult<Self> {
        // Digest-specific OIDs first.
        macro_rules! rsa_variants {
            ($($oid:expr => $hash:expr),* $(,)?) => {
                $(if alg.oid.matches($oid) { return Ok(SignatureAlgorithm::RsaPkcs1v15($hash)); })*
            };
        }
        rsa_variants!(
            oid::OID_MD2_WITH_RSA => Hash::Md2,
            oid::OID_MD4_WITH_RSA => Hash::Md4,
            oid::OID_MD5_WITH_RSA => Hash::Md5,
            oid::OID_SHA1_WITH_RSA => Hash::Sha1,
            oid::OID_SHA224_WITH_RSA => Hash::Sha224,
            oid::OID_SHA256_WITH_RSA => Hash::Sha256,
            oid::OID_SHA384_WITH_RSA => Hash::Sha384,
            oid::OID_SHA512_WITH_RSA => Hash::Sha512,
            oid::OID_SHA512_224_WITH_RSA => Hash::Sha512_224,
            oid::OID_SHA512_256_WITH_RSA => Hash::Sha512_256,
            oid::OID_SHA3_224_WITH_RSA => Hash::Sha3_224,
            oid::OID_SHA3_256_WITH_RSA => Hash::Sha3_256,
            oid::OID_SHA3_384_WITH_RSA => Hash::Sha3_384,
            oid::OID_SHA3_512_WITH_RSA => Hash::Sha3_512,
            oid::OID_SM3_WITH_RSA => Hash::Sm3,
            oid::OID_RIPEMD160_WITH_RSA => Hash::Ripemd160,
        );
        macro_rules! ecdsa_variants {
            ($($oid:expr => $hash:expr),* $(,)?) => {
                $(if alg.oid.matches($oid) { return Ok(SignatureAlgorithm::Ecdsa($hash)); })*
            };
        }
        ecdsa_variants!(
            oid::OID_ECDSA_WITH_SHA1 => Hash::Sha1,
            oid::OID_ECDSA_WITH_SHA224 => Hash::Sha224,
            oid::OID_ECDSA_WITH_SHA256 => Hash::Sha256,
            oid::OID_ECDSA_WITH_SHA384 => Hash::Sha384,
            oid::OID_ECDSA_WITH_SHA512 => Hash::Sha512,
            oid::OID_ECDSA_WITH_SHA3_224 => Hash::Sha3_224,
            oid::OID_ECDSA_WITH_SHA3_256 => Hash::Sha3_256,
            oid::OID_ECDSA_WITH_SHA3_384 => Hash::Sha3_384,
            oid::OID_ECDSA_WITH_SHA3_512 => Hash::Sha3_512,
        );
        macro_rules! dsa_variants {
            ($($oid:expr => $hash:expr),* $(,)?) => {
                $(if alg.oid.matches($oid) { return Ok(SignatureAlgorithm::Dsa($hash)); })*
            };
        }
        dsa_variants!(
            oid::OID_DSA_WITH_SHA1 => Hash::Sha1,
            oid::OID_DSA_WITH_SHA224 => Hash::Sha224,
            oid::OID_DSA_WITH_SHA256 => Hash::Sha256,
            oid::OID_DSA_WITH_SHA384 => Hash::Sha384,
            oid::OID_DSA_WITH_SHA512 => Hash::Sha512,
            oid::OID_DSA_WITH_SHA3_224 => Hash::Sha3_224,
            oid::OID_DSA_WITH_SHA3_256 => Hash::Sha3_256,
            oid::OID_DSA_WITH_SHA3_384 => Hash::Sha3_384,
            oid::OID_DSA_WITH_SHA3_512 => Hash::Sha3_512,
        );
        if alg.oid.matches(oid::OID_RSASSA_PSS) {
            return Self::parse_pss(alg);
        }
        if alg.oid.matches(oid::OID_ED25519) {
            return Ok(SignatureAlgorithm::Ed25519);
        }
        if alg.oid.matches(oid::OID_ED448) {
            return Ok(SignatureAlgorithm::Ed448);
        }
        if alg.oid.matches(oid::OID_SM2_WITH_SM3) {
            return Ok(SignatureAlgorithm::Sm2);
        }
        for variant in [
            MlDsaVariant::MlDsa44,
            MlDsaVariant::MlDsa65,
            MlDsaVariant::MlDsa87,
        ] {
            if alg.oid.matches(ml_dsa_oid(variant)) {
                return Ok(SignatureAlgorithm::MlDsa(variant));
            }
        }
        for variant in SlhDsaVariant::all() {
            if alg.oid.matches(slh_dsa_oid(*variant)) {
                return Ok(SignatureAlgorithm::SlhDsa(*variant));
            }
        }
        Err(CryptoError::UnsupportedOperation(
            "unsupported signature algorithm".to_string(),
        ))
    }

    /// Map a CMS `signatureAlgorithm` together with the signer's
    /// `digestAlgorithm`.
    ///
    /// CMS carries the digest separately and uses `rsaEncryption` as the
    /// signature algorithm for RSA PKCS#1 v1.5 (RFC 5652 section 5.3), so the
    /// plain [`Self::from_identifier`] cannot resolve it.
    pub fn from_identifier_with_digest(
        alg: &AlgorithmIdentifier,
        digest: Option<&AlgorithmIdentifier>,
    ) -> CryptoResult<Self> {
        if alg.oid.matches(oid::OID_RSA_ENCRYPTION) {
            let hash = digest
                .and_then(|digest| Hash::from_oid(&digest.oid))
                .ok_or_else(|| {
                    CryptoError::UnsupportedOperation(
                        "CMS rsaEncryption signature without a known digest".to_string(),
                    )
                })?;
            return Ok(SignatureAlgorithm::RsaPkcs1v15(hash));
        }
        Self::from_identifier(alg)
    }

    /// Build the matching `AlgorithmIdentifier`.
    pub fn to_identifier(self) -> AlgorithmIdentifier {
        match self {
            SignatureAlgorithm::RsaPkcs1v15(hash) => AlgorithmIdentifier::with_null(
                ObjectIdentifier::new(match hash {
                    Hash::Md2 => oid::OID_MD2_WITH_RSA,
                    Hash::Md4 => oid::OID_MD4_WITH_RSA,
                    Hash::Md5 => oid::OID_MD5_WITH_RSA,
                    Hash::Sha1 => oid::OID_SHA1_WITH_RSA,
                    Hash::Sha224 => oid::OID_SHA224_WITH_RSA,
                    Hash::Sha256 => oid::OID_SHA256_WITH_RSA,
                    Hash::Sha384 => oid::OID_SHA384_WITH_RSA,
                    Hash::Sha512 => oid::OID_SHA512_WITH_RSA,
                    Hash::Sha512_224 => oid::OID_SHA512_224_WITH_RSA,
                    Hash::Sha512_256 => oid::OID_SHA512_256_WITH_RSA,
                    Hash::Sha3_224 => oid::OID_SHA3_224_WITH_RSA,
                    Hash::Sha3_256 => oid::OID_SHA3_256_WITH_RSA,
                    Hash::Sha3_384 => oid::OID_SHA3_384_WITH_RSA,
                    Hash::Sha3_512 => oid::OID_SHA3_512_WITH_RSA,
                    Hash::Sm3 => oid::OID_SM3_WITH_RSA,
                    Hash::Ripemd160 => oid::OID_RIPEMD160_WITH_RSA,
                })
                .expect("static oid"),
            ),
            SignatureAlgorithm::RsaPss { hash, salt_len } => {
                // RSASSA-PSS-params with MGF1 using the same digest.
                let mut params = Vec::new();
                params.extend_from_slice(&der::explicit(
                    0,
                    &der::algorithm_identifier(
                        &ObjectIdentifier::new(hash.oid()).expect("static oid"),
                        Some(&der::null()),
                    ),
                ));
                let mgf1 = der::algorithm_identifier(
                    &ObjectIdentifier::new(oid::OID_MGF1).expect("static oid"),
                    Some(&der::algorithm_identifier(
                        &ObjectIdentifier::new(hash.oid()).expect("static oid"),
                        Some(&der::null()),
                    )),
                );
                params.extend_from_slice(&der::explicit(1, &mgf1));
                params.extend_from_slice(&der::explicit(
                    2,
                    &der::integer(&(salt_len as u64).to_be_bytes()),
                ));
                AlgorithmIdentifier::new(
                    ObjectIdentifier::new(oid::OID_RSASSA_PSS).expect("static oid"),
                    Some(der::sequence(&params)),
                )
            }
            SignatureAlgorithm::Ecdsa(hash) => AlgorithmIdentifier::new(
                ObjectIdentifier::new(match hash {
                    Hash::Sha1 => oid::OID_ECDSA_WITH_SHA1,
                    Hash::Sha224 => oid::OID_ECDSA_WITH_SHA224,
                    Hash::Sha256 => oid::OID_ECDSA_WITH_SHA256,
                    Hash::Sha384 => oid::OID_ECDSA_WITH_SHA384,
                    Hash::Sha512 => oid::OID_ECDSA_WITH_SHA512,
                    Hash::Sha3_224 => oid::OID_ECDSA_WITH_SHA3_224,
                    Hash::Sha3_256 => oid::OID_ECDSA_WITH_SHA3_256,
                    Hash::Sha3_384 => oid::OID_ECDSA_WITH_SHA3_384,
                    Hash::Sha3_512 => oid::OID_ECDSA_WITH_SHA3_512,
                    _ => oid::OID_ECDSA_WITH_SHA256,
                })
                .expect("static oid"),
                None,
            ),
            SignatureAlgorithm::Ed25519 => AlgorithmIdentifier::new(
                ObjectIdentifier::new(oid::OID_ED25519).expect("static oid"),
                None,
            ),
            SignatureAlgorithm::Ed448 => AlgorithmIdentifier::new(
                ObjectIdentifier::new(oid::OID_ED448).expect("static oid"),
                None,
            ),
            SignatureAlgorithm::Sm2 => AlgorithmIdentifier::new(
                ObjectIdentifier::new(oid::OID_SM2_WITH_SM3).expect("static oid"),
                None,
            ),
            SignatureAlgorithm::Dsa(hash) => AlgorithmIdentifier::new(
                ObjectIdentifier::new(match hash {
                    Hash::Sha1 => oid::OID_DSA_WITH_SHA1,
                    Hash::Sha224 => oid::OID_DSA_WITH_SHA224,
                    Hash::Sha256 => oid::OID_DSA_WITH_SHA256,
                    Hash::Sha384 => oid::OID_DSA_WITH_SHA384,
                    Hash::Sha512 => oid::OID_DSA_WITH_SHA512,
                    Hash::Sha3_224 => oid::OID_DSA_WITH_SHA3_224,
                    Hash::Sha3_256 => oid::OID_DSA_WITH_SHA3_256,
                    Hash::Sha3_384 => oid::OID_DSA_WITH_SHA3_384,
                    Hash::Sha3_512 => oid::OID_DSA_WITH_SHA3_512,
                    _ => oid::OID_DSA_WITH_SHA256,
                })
                .expect("static oid"),
                None,
            ),
            SignatureAlgorithm::MlDsa(variant) => AlgorithmIdentifier::new(
                ObjectIdentifier::new(ml_dsa_oid(variant)).expect("static oid"),
                None,
            ),
            SignatureAlgorithm::SlhDsa(variant) => AlgorithmIdentifier::new(
                ObjectIdentifier::new(slh_dsa_oid(variant)).expect("static oid"),
                None,
            ),
        }
    }

    /// The digest used by this algorithm, if any.
    pub fn hash(self) -> Option<Hash> {
        match self {
            SignatureAlgorithm::RsaPkcs1v15(hash)
            | SignatureAlgorithm::RsaPss { hash, .. }
            | SignatureAlgorithm::Ecdsa(hash)
            | SignatureAlgorithm::Dsa(hash) => Some(hash),
            SignatureAlgorithm::Sm2 => Some(Hash::Sm3),
            SignatureAlgorithm::Ed25519
            | SignatureAlgorithm::Ed448
            | SignatureAlgorithm::MlDsa(_)
            | SignatureAlgorithm::SlhDsa(_) => None,
        }
    }

    /// Verify `sig` over `msg` with a public key of the matching type.
    ///
    /// SM2 signatures use the GM/T default identity
    /// ([`crate::sm2::DEFAULT_ID`]); use [`Self::verify_with_sm2_id`] to
    /// verify with a different identity, which OpenSSL's provider-based CLI
    /// requires (it defaults to an empty ID unless `distid` is set).
    pub fn verify(self, key: &PublicKey, msg: &[u8], sig: &[u8]) -> CryptoResult<bool> {
        self.verify_inner(key, msg, sig, None)
    }

    /// Verify with an explicit SM2 identity.
    pub fn verify_with_sm2_id(
        self,
        key: &PublicKey,
        msg: &[u8],
        sig: &[u8],
        sm2_id: &[u8],
    ) -> CryptoResult<bool> {
        self.verify_inner(key, msg, sig, Some(sm2_id))
    }

    fn verify_inner(
        self,
        key: &PublicKey,
        msg: &[u8],
        sig: &[u8],
        sm2_id: Option<&[u8]>,
    ) -> CryptoResult<bool> {
        match (self, key) {
            (SignatureAlgorithm::RsaPkcs1v15(hash), PublicKey::Rsa(key)) => {
                key.verify_pkcs1v15(hash.factory(), msg, sig)
            }
            (SignatureAlgorithm::RsaPss { hash, salt_len }, PublicKey::Rsa(key)) => {
                key.verify_pss(hash.factory(), msg, sig, salt_len)
            }
            (SignatureAlgorithm::Ecdsa(hash), PublicKey::Ec { curve, point }) => {
                let digest = hash.digest_id().ok_or_else(|| {
                    CryptoError::UnsupportedOperation("digest not usable with ECDSA".to_string())
                })?;
                let (r, s) = decode_ecdsa_signature(sig)?;
                crate::ecdsa::verify(*curve, digest, point, msg, &r, &s)
            }
            (SignatureAlgorithm::Ed25519, PublicKey::Ed25519(public)) => {
                let sig: &[u8; 64] = sig
                    .try_into()
                    .map_err(|_| CryptoError::StrError("x509: invalid Ed25519 signature"))?;
                Ok(crate::ed25519::verify(public, sig, msg))
            }
            (SignatureAlgorithm::Ed448, PublicKey::Ed448(public)) => {
                let sig: &[u8; 114] = sig
                    .try_into()
                    .map_err(|_| CryptoError::StrError("x509: invalid Ed448 signature"))?;
                Ok(crate::ed448::verify(public, sig, msg, b""))
            }
            (SignatureAlgorithm::Sm2, PublicKey::Sm2(point)) => {
                let (r, s) = decode_ecdsa_signature(sig)?;
                let id = sm2_id.unwrap_or(crate::sm2::DEFAULT_ID);
                crate::sm2::verify(point, msg, id, &r, &s)
            }
            (SignatureAlgorithm::Dsa(hash), PublicKey::Dsa { params, y }) => {
                let digest = hash.digest_id().ok_or_else(|| {
                    CryptoError::UnsupportedOperation("digest not usable with DSA".to_string())
                })?;
                let (r, s) = decode_ecdsa_signature(sig)?;
                crate::dsa::verify(params, y, digest, msg, &r, &s)
            }
            (SignatureAlgorithm::MlDsa(variant), PublicKey::MlDsa(key)) => {
                if key.variant() != variant {
                    return Ok(false);
                }
                crate::ml_dsa::verify(key, msg, b"", sig)
            }
            (SignatureAlgorithm::SlhDsa(variant), PublicKey::SlhDsa(key)) => {
                if key.variant() != variant {
                    return Ok(false);
                }
                crate::slh_dsa::verify(key, msg, b"", sig, false)
            }
            _ => Err(CryptoError::UnsupportedOperation(
                "signature algorithm does not match public key".to_string(),
            )),
        }
    }

    /// Sign `msg` with a private key of the matching type.
    pub fn sign(
        self,
        key: &PrivateKey,
        msg: &[u8],
        rng: &mut impl crate::rng::Rng,
    ) -> CryptoResult<Vec<u8>> {
        key.sign(self, msg, rng)
    }

    fn parse_pss(alg: &AlgorithmIdentifier) -> CryptoResult<Self> {
        let mut hash = Hash::Sha1;
        let mut salt_len = 20usize;
        let mut mgf_hash = Hash::Sha1;
        if let Some(params) = &alg.parameters {
            let mut reader = Reader::new(params);
            let mut seq = reader.read_sequence()?;
            while !seq.is_empty() {
                let tag = seq.peek_tag()?;
                match tag.number {
                    0 => {
                        let mut inner = seq.read_explicit(0)?;
                        let alg = AlgorithmIdentifier::parse(&mut inner)?;
                        hash = Hash::from_oid(&alg.oid).ok_or_else(|| {
                            CryptoError::UnsupportedOperation(
                                "unsupported PSS hash algorithm".to_string(),
                            )
                        })?;
                    }
                    1 => {
                        let mut inner = seq.read_explicit(1)?;
                        let alg = AlgorithmIdentifier::parse(&mut inner)?;
                        if !alg.oid.matches(oid::OID_MGF1) {
                            return Err(CryptoError::UnsupportedOperation(
                                "unsupported PSS mask generation function".to_string(),
                            ));
                        }
                        let params = alg
                            .parameters
                            .as_deref()
                            .ok_or(CryptoError::StrError("x509: missing MGF1 parameters"))?;
                        let mut inner = Reader::new(params);
                        let hash_alg = AlgorithmIdentifier::parse(&mut inner)?;
                        mgf_hash = Hash::from_oid(&hash_alg.oid).ok_or_else(|| {
                            CryptoError::UnsupportedOperation(
                                "unsupported MGF1 hash algorithm".to_string(),
                            )
                        })?;
                    }
                    2 => {
                        let mut inner = seq.read_explicit(2)?;
                        let value = inner.read_integer_i64()?;
                        salt_len = usize::try_from(value)
                            .map_err(|_| CryptoError::StrError("x509: invalid PSS salt length"))?;
                    }
                    3 => {
                        let mut inner = seq.read_explicit(3)?;
                        let value = inner.read_integer_i64()?;
                        if value != 1 {
                            return Err(CryptoError::UnsupportedOperation(
                                "unsupported PSS trailer field".to_string(),
                            ));
                        }
                    }
                    _ => {
                        return Err(CryptoError::StrError("x509: invalid PSS parameters"));
                    }
                }
            }
        }
        if mgf_hash != hash {
            return Err(CryptoError::UnsupportedOperation(
                "PSS MGF1 hash differs from the message hash".to_string(),
            ));
        }
        Ok(SignatureAlgorithm::RsaPss { hash, salt_len })
    }
}

/// Decode an ECDSA/DSA/SM2 signature: `SEQUENCE { INTEGER r, INTEGER s }`.
pub fn decode_ecdsa_signature(der_sig: &[u8]) -> CryptoResult<(crate::bn::Bn, crate::bn::Bn)> {
    let mut reader = Reader::new(der_sig);
    let mut seq = reader.read_sequence()?;
    let r = crate::bn::Bn::from_be_bytes(seq.read_integer()?);
    let s = crate::bn::Bn::from_be_bytes(seq.read_integer()?);
    seq.expect_end()?;
    reader.expect_end()?;
    Ok((r, s))
}

/// Encode an ECDSA/DSA/SM2 signature: `SEQUENCE { INTEGER r, INTEGER s }`.
pub fn encode_ecdsa_signature(r: &crate::bn::Bn, s: &crate::bn::Bn) -> Vec<u8> {
    let mut content = der::integer(&r.to_be_bytes());
    content.extend_from_slice(&der::integer(&s.to_be_bytes()));
    der::sequence(&content)
}

/// The OID of an ML-DSA parameter set.
fn ml_dsa_oid(variant: MlDsaVariant) -> &'static [u64] {
    match variant {
        MlDsaVariant::MlDsa44 => oid::OID_ML_DSA_44,
        MlDsaVariant::MlDsa65 => oid::OID_ML_DSA_65,
        MlDsaVariant::MlDsa87 => oid::OID_ML_DSA_87,
    }
}

/// The OID of an SLH-DSA parameter set.
fn slh_dsa_oid(variant: SlhDsaVariant) -> &'static [u64] {
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

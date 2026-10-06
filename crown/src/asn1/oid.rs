//! OBJECT IDENTIFIER support and the OID constants used by the PKI modules.
//!
//! The identifiers are exposed as `&'static [u64]` arc slices; compare them
//! against [`ObjectIdentifier::matches`]. String form uses the usual dotted
//! decimal notation.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use crate::error::{CryptoError, CryptoResult};

/// A parsed OBJECT IDENTIFIER.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectIdentifier {
    arcs: Vec<u64>,
}

impl ObjectIdentifier {
    /// Build an OID from its arcs, validating the first two.
    pub fn new(arcs: &[u64]) -> CryptoResult<Self> {
        if arcs.len() < 2 {
            return Err(CryptoError::StrError("asn1: oid needs at least two arcs"));
        }
        if arcs[0] > 2 {
            return Err(CryptoError::StrError("asn1: invalid oid first arc"));
        }
        if arcs[0] < 2 && arcs[1] > 39 {
            return Err(CryptoError::StrError("asn1: invalid oid second arc"));
        }
        Ok(ObjectIdentifier {
            arcs: arcs.to_vec(),
        })
    }

    /// Parse an OID from the content octets of an OBJECT IDENTIFIER TLV.
    pub fn from_der_content(content: &[u8]) -> CryptoResult<Self> {
        if content.is_empty() {
            return Err(CryptoError::StrError("asn1: empty oid"));
        }
        let mut arcs = Vec::new();
        let mut value: u64 = 0;
        let mut started = false;
        for &byte in content {
            value = value
                .checked_mul(128)
                .and_then(|v| v.checked_add((byte & 0x7f) as u64))
                .ok_or(CryptoError::StrError("asn1: oid arc too large"))?;
            started = true;
            if byte & 0x80 == 0 {
                if arcs.is_empty() {
                    // The first subidentifier packs the first two arcs.
                    let (first, second) = if value < 40 {
                        (0, value)
                    } else if value < 80 {
                        (1, value - 40)
                    } else {
                        (2, value - 80)
                    };
                    arcs.push(first);
                    arcs.push(second);
                } else {
                    arcs.push(value);
                }
                value = 0;
                started = false;
            }
        }
        if started {
            return Err(CryptoError::StrError("asn1: truncated oid"));
        }
        ObjectIdentifier::new(&arcs)
    }

    /// Encode the OID's content octets (without tag and length).
    pub fn to_der_content(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut write_arc = |mut arc: u64| {
            let mut tmp = [0u8; 10];
            let mut i = tmp.len();
            loop {
                i -= 1;
                tmp[i] = (arc & 0x7f) as u8;
                arc >>= 7;
                if arc == 0 {
                    break;
                }
            }
            for (j, &b) in tmp[i..].iter().enumerate() {
                let last = j == tmp.len() - i - 1;
                out.push(if last { b } else { b | 0x80 });
            }
        };
        write_arc(self.arcs[0] * 40 + self.arcs[1]);
        for &arc in &self.arcs[2..] {
            write_arc(arc);
        }
        out
    }

    /// Parse a dotted-decimal OID string.
    pub fn from_dotted_string(value: &str) -> CryptoResult<Self> {
        let mut arcs = Vec::new();
        for part in value.split('.') {
            let arc: u64 = part
                .parse()
                .map_err(|_| CryptoError::StrError("asn1: invalid oid string"))?;
            arcs.push(arc);
        }
        ObjectIdentifier::new(&arcs)
    }

    /// The arc sequence.
    pub fn arcs(&self) -> &[u64] {
        &self.arcs
    }

    /// Whether this OID equals the given arc slice.
    pub fn matches(&self, arcs: &[u64]) -> bool {
        self.arcs == arcs
    }

    /// Render as a dotted-decimal string.
    pub fn to_dotted_string(&self) -> String {
        let mut out = String::new();
        for (i, arc) in self.arcs.iter().enumerate() {
            if i != 0 {
                out.push('.');
            }
            out.push_str(&arc.to_string());
        }
        out
    }
}

impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_dotted_string())
    }
}

/// Build an [`ObjectIdentifier`] from arc literals.
///
/// The arcs are trusted literals; an invalid list panics rather than
/// returning an error.
#[macro_export]
macro_rules! oid {
    ($($arc:expr),+ $(,)?) => {
        $crate::asn1::oid::ObjectIdentifier::new(&[$($arc),+]).expect("oid! literal arcs")
    };
}

// ---------------------------------------------------------------------------
// Hash algorithms
// ---------------------------------------------------------------------------

/// `md2` (1.2.840.113549.2.2).
pub const OID_MD2: &[u64] = &[1, 2, 840, 113549, 2, 2];
/// `md4` (1.2.840.113549.2.4).
pub const OID_MD4: &[u64] = &[1, 2, 840, 113549, 2, 4];
/// `md5` (1.2.840.113549.2.5).
pub const OID_MD5: &[u64] = &[1, 2, 840, 113549, 2, 5];
/// `sha1` (1.3.14.3.2.26).
pub const OID_SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];
/// `sha224` (2.16.840.1.101.3.4.2.4).
pub const OID_SHA224: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 4];
/// `sha256` (2.16.840.1.101.3.4.2.1).
pub const OID_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
/// `sha384` (2.16.840.1.101.3.4.2.2).
pub const OID_SHA384: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 2];
/// `sha512` (2.16.840.1.101.3.4.2.3).
pub const OID_SHA512: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 3];
/// `sha512-224` (2.16.840.1.101.3.4.2.5).
pub const OID_SHA512_224: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 5];
/// `sha512-256` (2.16.840.1.101.3.4.2.6).
pub const OID_SHA512_256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 6];
/// `sha3-224` (2.16.840.1.101.3.4.2.7).
pub const OID_SHA3_224: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 7];
/// `sha3-256` (2.16.840.1.101.3.4.2.8).
pub const OID_SHA3_256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 8];
/// `sha3-384` (2.16.840.1.101.3.4.2.9).
pub const OID_SHA3_384: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 9];
/// `sha3-512` (2.16.840.1.101.3.4.2.10).
pub const OID_SHA3_512: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 10];
/// `shake128` (2.16.840.1.101.3.4.2.11).
pub const OID_SHAKE128: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 11];
/// `shake256` (2.16.840.1.101.3.4.2.12).
pub const OID_SHAKE256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 12];
/// `sm3` (1.2.156.10197.1.401).
pub const OID_SM3: &[u64] = &[1, 2, 156, 10197, 1, 401];
/// `ripemd160` (1.3.36.3.2.1).
pub const OID_RIPEMD160: &[u64] = &[1, 3, 36, 3, 2, 1];

// ---------------------------------------------------------------------------
// Public key and signature algorithms
// ---------------------------------------------------------------------------

/// `rsaEncryption` (1.2.840.113549.1.1.1).
pub const OID_RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
/// `md2WithRSAEncryption` (1.2.840.113549.1.1.2).
pub const OID_MD2_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 2];
/// `md4WithRSAEncryption` (1.2.840.113549.1.1.3).
pub const OID_MD4_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 3];
/// `md5WithRSAEncryption` (1.2.840.113549.1.1.4).
pub const OID_MD5_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 4];
/// `sha1WithRSAEncryption` (1.2.840.113549.1.1.5).
pub const OID_SHA1_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 5];
/// `rsassaPss` (1.2.840.113549.1.1.10).
pub const OID_RSASSA_PSS: &[u64] = &[1, 2, 840, 113549, 1, 1, 10];
/// `id-mgf1` (1.2.840.113549.1.1.8).
pub const OID_MGF1: &[u64] = &[1, 2, 840, 113549, 1, 1, 8];
/// `sm3WithRSAEncryption` (1.2.156.10197.1.504).
pub const OID_SM3_WITH_RSA: &[u64] = &[1, 2, 156, 10197, 1, 504];
/// `ripemd160WithRSA` (1.3.36.3.3.1.2).
pub const OID_RIPEMD160_WITH_RSA: &[u64] = &[1, 3, 36, 3, 3, 1, 2];
/// `sha256WithRSAEncryption` (1.2.840.113549.1.1.11).
pub const OID_SHA256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];
/// `sha384WithRSAEncryption` (1.2.840.113549.1.1.12).
pub const OID_SHA384_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 12];
/// `sha512WithRSAEncryption` (1.2.840.113549.1.1.13).
pub const OID_SHA512_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 13];
/// `sha224WithRSAEncryption` (1.2.840.113549.1.1.14).
pub const OID_SHA224_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 14];
/// `sha512-224WithRSAEncryption` (1.2.840.113549.1.1.15).
pub const OID_SHA512_224_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 15];
/// `sha512-256WithRSAEncryption` (1.2.840.113549.1.1.16).
pub const OID_SHA512_256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 16];
/// `id-ecPublicKey` (1.2.840.10045.2.1).
pub const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
/// `ecdsa-with-SHA1` (1.2.840.10045.4.1).
pub const OID_ECDSA_WITH_SHA1: &[u64] = &[1, 2, 840, 10045, 4, 1];
/// `ecdsa-with-SHA224` (1.2.840.10045.4.3.1).
pub const OID_ECDSA_WITH_SHA224: &[u64] = &[1, 2, 840, 10045, 4, 3, 1];
/// `ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
pub const OID_ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
/// `ecdsa-with-SHA384` (1.2.840.10045.4.3.3).
pub const OID_ECDSA_WITH_SHA384: &[u64] = &[1, 2, 840, 10045, 4, 3, 3];
/// `ecdsa-with-SHA512` (1.2.840.10045.4.3.4).
pub const OID_ECDSA_WITH_SHA512: &[u64] = &[1, 2, 840, 10045, 4, 3, 4];
/// `id-dsa` (1.2.840.10040.4.1).
pub const OID_DSA: &[u64] = &[1, 2, 840, 10040, 4, 1];
/// `dsa-with-sha1` (1.2.840.10040.4.3).
pub const OID_DSA_WITH_SHA1: &[u64] = &[1, 2, 840, 10040, 4, 3];
/// `id-ed25519` (1.3.101.112).
pub const OID_ED25519: &[u64] = &[1, 3, 101, 112];
/// `id-ed448` (1.3.101.113).
pub const OID_ED448: &[u64] = &[1, 3, 101, 113];
/// `id-X25519` (1.3.101.110).
pub const OID_X25519: &[u64] = &[1, 3, 101, 110];
/// `id-X448` (1.3.101.111).
pub const OID_X448: &[u64] = &[1, 3, 101, 111];
/// `sm2` (curve and key algorithm, 1.2.156.10197.1.301).
pub const OID_SM2: &[u64] = &[1, 2, 156, 10197, 1, 301];
/// `sm2-with-sm3` (1.2.156.10197.1.501).
pub const OID_SM2_WITH_SM3: &[u64] = &[1, 2, 156, 10197, 1, 501];
/// `ml-dsa-44` (2.16.840.1.101.3.4.3.17).
pub const OID_ML_DSA_44: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 17];
/// `ml-dsa-65` (2.16.840.1.101.3.4.3.18).
pub const OID_ML_DSA_65: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 18];
/// `ml-dsa-87` (2.16.840.1.101.3.4.3.19).
pub const OID_ML_DSA_87: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 19];
/// `slh-dsa-sha2-128s` (2.16.840.1.101.3.4.3.20).
pub const OID_SLH_DSA_SHA2_128S: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 20];
/// `slh-dsa-sha2-128f` (2.16.840.1.101.3.4.3.21).
pub const OID_SLH_DSA_SHA2_128F: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 21];
/// `slh-dsa-sha2-192s` (2.16.840.1.101.3.4.3.22).
pub const OID_SLH_DSA_SHA2_192S: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 22];
/// `slh-dsa-sha2-192f` (2.16.840.1.101.3.4.3.23).
pub const OID_SLH_DSA_SHA2_192F: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 23];
/// `slh-dsa-sha2-256s` (2.16.840.1.101.3.4.3.24).
pub const OID_SLH_DSA_SHA2_256S: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 24];
/// `slh-dsa-sha2-256f` (2.16.840.1.101.3.4.3.25).
pub const OID_SLH_DSA_SHA2_256F: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 25];
/// `slh-dsa-shake-128s` (2.16.840.1.101.3.4.3.26).
pub const OID_SLH_DSA_SHAKE_128S: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 26];
/// `slh-dsa-shake-128f` (2.16.840.1.101.3.4.3.27).
pub const OID_SLH_DSA_SHAKE_128F: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 27];
/// `slh-dsa-shake-192s` (2.16.840.1.101.3.4.3.28).
pub const OID_SLH_DSA_SHAKE_192S: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 28];
/// `slh-dsa-shake-192f` (2.16.840.1.101.3.4.3.29).
pub const OID_SLH_DSA_SHAKE_192F: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 29];
/// `slh-dsa-shake-256s` (2.16.840.1.101.3.4.3.30).
pub const OID_SLH_DSA_SHAKE_256S: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 30];
/// `slh-dsa-shake-256f` (2.16.840.1.101.3.4.3.31).
pub const OID_SLH_DSA_SHAKE_256F: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 31];
/// `dhpublicnumber` (1.2.840.10046.2.1).
pub const OID_DH_PUBLIC_NUMBER: &[u64] = &[1, 2, 840, 10046, 2, 1];

/// SHA-2 with RSA PKCS#1 v1.5 (2.16.840.1.101.3.4.3.13..16).
pub const OID_SHA3_224_WITH_RSA: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 13];
/// SHA3-256 with RSA (2.16.840.1.101.3.4.3.14).
pub const OID_SHA3_256_WITH_RSA: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 14];
/// SHA3-384 with RSA (2.16.840.1.101.3.4.3.15).
pub const OID_SHA3_384_WITH_RSA: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 15];
/// SHA3-512 with RSA (2.16.840.1.101.3.4.3.16).
pub const OID_SHA3_512_WITH_RSA: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 16];
/// ECDSA with SHA3-224 (2.16.840.1.101.3.4.3.9).
pub const OID_ECDSA_WITH_SHA3_224: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 9];
/// ECDSA with SHA3-256 (2.16.840.1.101.3.4.3.10).
pub const OID_ECDSA_WITH_SHA3_256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 10];
/// ECDSA with SHA3-384 (2.16.840.1.101.3.4.3.11).
pub const OID_ECDSA_WITH_SHA3_384: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 11];
/// ECDSA with SHA3-512 (2.16.840.1.101.3.4.3.12).
pub const OID_ECDSA_WITH_SHA3_512: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 12];
/// DSA with SHA224 (2.16.840.1.101.3.4.3.1).
pub const OID_DSA_WITH_SHA224: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 1];
/// DSA with SHA256 (2.16.840.1.101.3.4.3.2).
pub const OID_DSA_WITH_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 2];
/// DSA with SHA384 (2.16.840.1.101.3.4.3.3).
pub const OID_DSA_WITH_SHA384: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 3];
/// DSA with SHA512 (2.16.840.1.101.3.4.3.4).
pub const OID_DSA_WITH_SHA512: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 4];
/// DSA with SHA3-224 (2.16.840.1.101.3.4.3.5).
pub const OID_DSA_WITH_SHA3_224: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 5];
/// DSA with SHA3-256 (2.16.840.1.101.3.4.3.6).
pub const OID_DSA_WITH_SHA3_256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 6];
/// DSA with SHA3-384 (2.16.840.1.101.3.4.3.7).
pub const OID_DSA_WITH_SHA3_384: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 7];
/// DSA with SHA3-512 (2.16.840.1.101.3.4.3.8).
pub const OID_DSA_WITH_SHA3_512: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 8];

// ---------------------------------------------------------------------------
// Named curves
// ---------------------------------------------------------------------------

/// `prime256v1` / `secp256r1` (1.2.840.10045.3.1.7).
pub const OID_SECP256R1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
/// `secp384r1` (1.3.132.0.34).
pub const OID_SECP384R1: &[u64] = &[1, 3, 132, 0, 34];
/// `secp521r1` (1.3.132.0.35).
pub const OID_SECP521R1: &[u64] = &[1, 3, 132, 0, 35];
/// `secp256k1` (1.3.132.0.10).
pub const OID_SECP256K1: &[u64] = &[1, 3, 132, 0, 10];

// ---------------------------------------------------------------------------
// Distinguished-name attributes
// ---------------------------------------------------------------------------

/// `commonName` (2.5.4.3).
pub const OID_AT_COMMON_NAME: &[u64] = &[2, 5, 4, 3];
/// `surname` (2.5.4.4).
pub const OID_AT_SURNAME: &[u64] = &[2, 5, 4, 4];
/// `serialNumber` (2.5.4.5).
pub const OID_AT_SERIAL_NUMBER: &[u64] = &[2, 5, 4, 5];
/// `countryName` (2.5.4.6).
pub const OID_AT_COUNTRY: &[u64] = &[2, 5, 4, 6];
/// `localityName` (2.5.4.7).
pub const OID_AT_LOCALITY: &[u64] = &[2, 5, 4, 7];
/// `stateOrProvinceName` (2.5.4.8).
pub const OID_AT_STATE: &[u64] = &[2, 5, 4, 8];
/// `streetAddress` (2.5.4.9).
pub const OID_AT_STREET: &[u64] = &[2, 5, 4, 9];
/// `organizationName` (2.5.4.10).
pub const OID_AT_ORGANIZATION: &[u64] = &[2, 5, 4, 10];
/// `organizationalUnitName` (2.5.4.11).
pub const OID_AT_ORGANIZATIONAL_UNIT: &[u64] = &[2, 5, 4, 11];
/// `title` (2.5.4.12).
pub const OID_AT_TITLE: &[u64] = &[2, 5, 4, 12];
/// `givenName` (2.5.4.42).
pub const OID_AT_GIVEN_NAME: &[u64] = &[2, 5, 4, 42];
/// `initials` (2.5.4.43).
pub const OID_AT_INITIALS: &[u64] = &[2, 5, 4, 43];
/// `dnQualifier` (2.5.4.46).
pub const OID_AT_DN_QUALIFIER: &[u64] = &[2, 5, 4, 46];
/// `emailAddress` (1.2.840.113549.1.9.1).
pub const OID_AT_EMAIL_ADDRESS: &[u64] = &[1, 2, 840, 113549, 1, 9, 1];
/// `domainComponent` (0.9.2342.19200300.100.1.25).
pub const OID_AT_DOMAIN_COMPONENT: &[u64] = &[0, 9, 2342, 19200300, 100, 1, 25];
/// `userId` (0.9.2342.19200300.100.1.1).
pub const OID_AT_USER_ID: &[u64] = &[0, 9, 2342, 19200300, 100, 1, 1];

// ---------------------------------------------------------------------------
// X.509 extensions and access descriptors
// ---------------------------------------------------------------------------

/// `subjectDirectoryAttributes` (2.5.29.9).
pub const OID_SUBJECT_DIRECTORY_ATTRIBUTES: &[u64] = &[2, 5, 29, 9];
/// `subjectKeyIdentifier` (2.5.29.14).
pub const OID_SUBJECT_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 14];
/// `keyUsage` (2.5.29.15).
pub const OID_KEY_USAGE: &[u64] = &[2, 5, 29, 15];
/// `subjectAltName` (2.5.29.17).
pub const OID_SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];
/// `issuerAltName` (2.5.29.18).
pub const OID_ISSUER_ALT_NAME: &[u64] = &[2, 5, 29, 18];
/// `basicConstraints` (2.5.29.19).
pub const OID_BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
/// `cRLNumber` (2.5.29.20).
pub const OID_CRL_NUMBER: &[u64] = &[2, 5, 29, 20];
/// `reasonCode` (2.5.29.21).
pub const OID_REASON_CODE: &[u64] = &[2, 5, 29, 21];
/// `invalidityDate` (2.5.29.24).
pub const OID_INVALIDITY_DATE: &[u64] = &[2, 5, 29, 24];
/// `deltaCRLIndicator` (2.5.29.27).
pub const OID_DELTA_CRL_INDICATOR: &[u64] = &[2, 5, 29, 27];
/// `issuingDistributionPoint` (2.5.29.28).
pub const OID_ISSUING_DISTRIBUTION_POINT: &[u64] = &[2, 5, 29, 28];
/// `certificateIssuer` (2.5.29.29).
pub const OID_CERTIFICATE_ISSUER: &[u64] = &[2, 5, 29, 29];
/// `nameConstraints` (2.5.29.30).
pub const OID_NAME_CONSTRAINTS: &[u64] = &[2, 5, 29, 30];
/// `crlDistributionPoints` (2.5.29.31).
pub const OID_CRL_DISTRIBUTION_POINTS: &[u64] = &[2, 5, 29, 31];
/// `certificatePolicies` (2.5.29.32).
pub const OID_CERTIFICATE_POLICIES: &[u64] = &[2, 5, 29, 32];
/// `policyMappings` (2.5.29.33).
pub const OID_POLICY_MAPPINGS: &[u64] = &[2, 5, 29, 33];
/// `authorityKeyIdentifier` (2.5.29.35).
pub const OID_AUTHORITY_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 35];
/// `policyConstraints` (2.5.29.36).
pub const OID_POLICY_CONSTRAINTS: &[u64] = &[2, 5, 29, 36];
/// `extKeyUsage` (2.5.29.37).
pub const OID_EXTENDED_KEY_USAGE: &[u64] = &[2, 5, 29, 37];
/// `freshestCRL` (2.5.29.46).
pub const OID_FRESHEST_CRL: &[u64] = &[2, 5, 29, 46];
/// `inhibitAnyPolicy` (2.5.29.54).
pub const OID_INHIBIT_ANY_POLICY: &[u64] = &[2, 5, 29, 54];
/// `noRevAvail` (2.5.29.56).
pub const OID_NO_REV_AVAIL: &[u64] = &[2, 5, 29, 56];
/// `authorityInfoAccess` (1.3.6.1.5.5.7.1.1).
pub const OID_AUTHORITY_INFO_ACCESS: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 1];
/// `subjectInfoAccess` (1.3.6.1.5.5.7.1.11).
pub const OID_SUBJECT_INFO_ACCESS: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 11];
/// `OCSP` access method (1.3.6.1.5.5.7.48.1).
pub const OID_AD_OCSP: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1];
/// `caIssuers` access method (1.3.6.1.5.5.7.48.2).
pub const OID_AD_CA_ISSUERS: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 2];
/// `timeStamping` access method (1.3.6.1.5.5.7.48.3).
pub const OID_AD_TIME_STAMPING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 3];
/// `caRepository` access method (1.3.6.1.5.5.7.48.5).
pub const OID_AD_CA_REPOSITORY: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 5];
/// `tlsfeature` (1.3.6.1.5.5.7.1.24).
pub const OID_TLS_FEATURE: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 24];
/// `OCSP no-check` (1.3.6.1.5.5.7.48.1.5).
pub const OID_OCSP_NOCHECK: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 5];
/// `id-qt-cps` policy qualifier (1.3.6.1.5.5.7.2.1).
pub const OID_QT_CPS: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 2, 1];
/// `id-qt-unotice` policy qualifier (1.3.6.1.5.5.7.2.2).
pub const OID_QT_UNOTICE: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 2, 2];

// ---------------------------------------------------------------------------
// Extended key usage purposes
// ---------------------------------------------------------------------------

/// `anyExtendedKeyUsage` (2.5.29.37.0).
pub const OID_ANY_EXTENDED_KEY_USAGE: &[u64] = &[2, 5, 29, 37, 0];
/// `serverAuth` (1.3.6.1.5.5.7.3.1).
pub const OID_KP_SERVER_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 1];
/// `clientAuth` (1.3.6.1.5.5.7.3.2).
pub const OID_KP_CLIENT_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 2];
/// `codeSigning` (1.3.6.1.5.5.7.3.3).
pub const OID_KP_CODE_SIGNING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 3];
/// `emailProtection` (1.3.6.1.5.5.7.3.4).
pub const OID_KP_EMAIL_PROTECTION: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 4];
/// `timeStamping` (1.3.6.1.5.5.7.3.8).
pub const OID_KP_TIME_STAMPING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 8];
/// `OCSPSigning` (1.3.6.1.5.5.7.3.9).
pub const OID_KP_OCSP_SIGNING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 9];

// ---------------------------------------------------------------------------
// PKCS#7 / CMS
// ---------------------------------------------------------------------------

/// `id-data` (1.2.840.113549.1.7.1).
pub const OID_PKCS7_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
/// `id-signedData` (1.2.840.113549.1.7.2).
pub const OID_PKCS7_SIGNED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 2];
/// `id-envelopedData` (1.2.840.113549.1.7.3).
pub const OID_PKCS7_ENVELOPED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 3];
/// `id-digestedData` (1.2.840.113549.1.7.5).
pub const OID_PKCS7_DIGESTED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 5];
/// `id-encryptedData` (1.2.840.113549.1.7.6).
pub const OID_PKCS7_ENCRYPTED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 6];
/// `contentType` (1.2.840.113549.1.9.3).
pub const OID_PKCS9_CONTENT_TYPE: &[u64] = &[1, 2, 840, 113549, 1, 9, 3];
/// `messageDigest` (1.2.840.113549.1.9.4).
pub const OID_PKCS9_MESSAGE_DIGEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 4];
/// `signingTime` (1.2.840.113549.1.9.5).
pub const OID_PKCS9_SIGNING_TIME: &[u64] = &[1, 2, 840, 113549, 1, 9, 5];
/// `counterSignature` (1.2.840.113549.1.9.6).
pub const OID_PKCS9_COUNTER_SIGNATURE: &[u64] = &[1, 2, 840, 113549, 1, 9, 6];
/// `extensionRequest` (1.2.840.113549.1.9.14).
pub const OID_PKCS9_EXTENSION_REQUEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 14];
/// `smimeCapabilities` (1.2.840.113549.1.9.15).
pub const OID_PKCS9_SMIME_CAPABILITIES: &[u64] = &[1, 2, 840, 113549, 1, 9, 15];
/// `friendlyName` (1.2.840.113549.1.9.20).
pub const OID_PKCS9_FRIENDLY_NAME: &[u64] = &[1, 2, 840, 113549, 1, 9, 20];
/// `localKeyId` (1.2.840.113549.1.9.21).
pub const OID_PKCS9_LOCAL_KEY_ID: &[u64] = &[1, 2, 840, 113549, 1, 9, 21];

// ---------------------------------------------------------------------------
// PKCS#8 / PKCS#12 / PBE
// ---------------------------------------------------------------------------

/// `PBKDF2` (1.2.840.113549.1.5.12).
pub const OID_PBKDF2: &[u64] = &[1, 2, 840, 113549, 1, 5, 12];
/// `PBES2` (1.2.840.113549.1.5.13).
pub const OID_PBES2: &[u64] = &[1, 2, 840, 113549, 1, 5, 13];
/// `pbeWithSHA1And40BitRC4` (1.2.840.113549.1.12.1.1).
pub const OID_PBE_SHA1_40BIT_RC4: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 1];
/// `pbeWithSHA1And128BitRC4` (1.2.840.113549.1.12.1.2).
pub const OID_PBE_SHA1_128BIT_RC4: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 2];
/// `pbeWithSHA1And3-KeyTripleDES-CBC` (1.2.840.113549.1.12.1.3).
pub const OID_PBE_SHA1_3DES: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 3];
/// `pbeWithSHA1And2-KeyTripleDES-CBC` (1.2.840.113549.1.12.1.4).
pub const OID_PBE_SHA1_2DES: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 4];
/// `pbeWithSHA1And40BitRC2-CBC` (1.2.840.113549.1.12.1.6).
pub const OID_PBE_SHA1_40BIT_RC2: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 6];
/// `hmacWithSHA1` (1.2.840.113549.2.7).
pub const OID_HMAC_SHA1: &[u64] = &[1, 2, 840, 113549, 2, 7];
/// `hmacWithSHA256` (1.2.840.113549.2.9).
pub const OID_HMAC_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];
/// `hmacWithSHA384` (1.2.840.113549.2.10).
pub const OID_HMAC_SHA384: &[u64] = &[1, 2, 840, 113549, 2, 10];
/// `hmacWithSHA512` (1.2.840.113549.2.11).
pub const OID_HMAC_SHA512: &[u64] = &[1, 2, 840, 113549, 2, 11];
/// `aes-128-cbc` (2.16.840.1.101.3.4.1.2).
pub const OID_AES_128_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 2];
/// `aes-192-cbc` (2.16.840.1.101.3.4.1.22).
pub const OID_AES_192_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 22];
/// `aes-256-cbc` (2.16.840.1.101.3.4.1.42).
pub const OID_AES_256_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];
/// `des-ede3-cbc` (1.2.840.113549.3.7).
pub const OID_DES_EDE3_CBC: &[u64] = &[1, 2, 840, 113549, 3, 7];
/// `rc2-cbc` (1.2.840.113549.3.2).
pub const OID_RC2_CBC: &[u64] = &[1, 2, 840, 113549, 3, 2];
/// `pkcs8ShroudedKeyBag` (1.2.840.113549.1.12.10.1.2).
pub const OID_PKCS12_SHROUDED_KEY_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 2];
/// `certBag` (1.2.840.113549.1.12.10.1.3).
pub const OID_PKCS12_CERT_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 3];
/// `crlBag` (1.2.840.113549.1.12.10.1.4).
pub const OID_PKCS12_CRL_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 4];
/// `secretBag` (1.2.840.113549.1.12.10.1.5).
pub const OID_PKCS12_SECRET_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 5];
/// `safeContentsBag` (1.2.840.113549.1.12.10.1.6).
pub const OID_PKCS12_SAFE_CONTENTS_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 6];
/// `id-keyBag` (1.2.840.113549.1.12.10.1.1).
pub const OID_PKCS12_KEY_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 1];
/// `x509Certificate` (1.2.840.113549.1.9.22.1).
pub const OID_X509_CERTIFICATE: &[u64] = &[1, 2, 840, 113549, 1, 9, 22, 1];
/// `sdsiCertificate` (1.2.840.113549.1.9.22.2).
pub const OID_SDSI_CERTIFICATE: &[u64] = &[1, 2, 840, 113549, 1, 9, 22, 2];
/// `x509CRL` (1.2.840.113549.1.9.23.1).
pub const OID_X509_CRL: &[u64] = &[1, 2, 840, 113549, 1, 9, 23, 1];

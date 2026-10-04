//! Password-based encryption (PBES2 and the legacy PKCS#12 PBE schemes) and
//! PKCS#5 PBKDF2.
//!
//! This powers `EncryptedPrivateKeyInfo` (PKCS#8 encrypted keys) and PKCS#12
//! shrouded key bags.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use crate::asn1::der::{self, Reader};
use crate::asn1::oid::{self, ObjectIdentifier};
use crate::block::aes::Aes;
use crate::block::des::TripleDes;
use crate::block::rc2::Rc2;
use crate::error::{CryptoError, CryptoResult};
use crate::kdf::pkcs12kdf;
use crate::modes::cbc::{CbcDecryptor, CbcEncryptor};
use crate::modes::BlockMode;
use crate::rng::Rng;
use crate::stream::rc4::Rc4;
use crate::stream::StreamCipher;

use super::algorithm::{AlgorithmIdentifier, Hash};
use super::keys::{EncryptedPrivateKeyInfo, PrivateKeyInfo};

/// PBKDF2 (RFC 8018) with a runtime-chosen HMAC.
pub fn pbkdf2(
    hash: Hash,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> CryptoResult<()> {
    if iterations == 0 {
        return Err(CryptoError::InvalidParameterStr("pbkdf2: zero iterations"));
    }
    let hlen = hash.output_len();
    for (block, chunk) in out.chunks_mut(hlen).enumerate() {
        let index = (block as u32 + 1).to_be_bytes();
        let mut salt_block = salt.to_vec();
        salt_block.extend_from_slice(&index);
        let mut u = hash.hmac(password, &salt_block)?;
        let mut t = u.clone();
        for _ in 1..iterations {
            u = hash.hmac(password, &u)?;
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= b;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
    Ok(())
}

/// The content encryption scheme of a PBES2 structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pbes2Cipher {
    /// AES-128-CBC.
    Aes128Cbc {
        /// Initialization vector.
        iv: Vec<u8>,
    },
    /// AES-192-CBC.
    Aes192Cbc {
        /// Initialization vector.
        iv: Vec<u8>,
    },
    /// AES-256-CBC.
    Aes256Cbc {
        /// Initialization vector.
        iv: Vec<u8>,
    },
    /// 3-key Triple DES CBC.
    DesEde3Cbc {
        /// Initialization vector.
        iv: Vec<u8>,
    },
}

impl Pbes2Cipher {
    /// Key length in bytes.
    pub fn key_len(&self) -> usize {
        match self {
            Pbes2Cipher::Aes128Cbc { .. } => 16,
            Pbes2Cipher::Aes192Cbc { .. } => 24,
            Pbes2Cipher::Aes256Cbc { .. } => 32,
            Pbes2Cipher::DesEde3Cbc { .. } => 24,
        }
    }

    fn iv(&self) -> &[u8] {
        match self {
            Pbes2Cipher::Aes128Cbc { iv }
            | Pbes2Cipher::Aes192Cbc { iv }
            | Pbes2Cipher::Aes256Cbc { iv }
            | Pbes2Cipher::DesEde3Cbc { iv } => iv,
        }
    }

    fn block_size(&self) -> usize {
        match self {
            Pbes2Cipher::DesEde3Cbc { .. } => 8,
            _ => 16,
        }
    }

    fn oid(&self) -> &'static [u64] {
        match self {
            Pbes2Cipher::Aes128Cbc { .. } => oid::OID_AES_128_CBC,
            Pbes2Cipher::Aes192Cbc { .. } => oid::OID_AES_192_CBC,
            Pbes2Cipher::Aes256Cbc { .. } => oid::OID_AES_256_CBC,
            Pbes2Cipher::DesEde3Cbc { .. } => oid::OID_DES_EDE3_CBC,
        }
    }

    fn encrypt(&self, key: &[u8], data: &mut [u8]) -> CryptoResult<()> {
        let iv = self.iv();
        match self {
            Pbes2Cipher::Aes128Cbc { .. }
            | Pbes2Cipher::Aes192Cbc { .. }
            | Pbes2Cipher::Aes256Cbc { .. } => {
                let cipher = Aes::new(key)?;
                let mut mode = cipher.to_cbc_enc(iv);
                mode.encrypt(data);
            }
            Pbes2Cipher::DesEde3Cbc { .. } => {
                let cipher = TripleDes::new(key)?;
                let mut mode = cipher.to_cbc_enc(iv);
                mode.encrypt(data);
            }
        }
        Ok(())
    }

    fn decrypt(&self, key: &[u8], data: &mut [u8]) -> CryptoResult<()> {
        let iv = self.iv();
        match self {
            Pbes2Cipher::Aes128Cbc { .. }
            | Pbes2Cipher::Aes192Cbc { .. }
            | Pbes2Cipher::Aes256Cbc { .. } => {
                let cipher = Aes::new(key)?;
                let mut mode = cipher.to_cbc_dec(iv);
                mode.encrypt(data);
            }
            Pbes2Cipher::DesEde3Cbc { .. } => {
                let cipher = TripleDes::new(key)?;
                let mut mode = cipher.to_cbc_dec(iv);
                mode.encrypt(data);
            }
        }
        Ok(())
    }
}

/// A parsed PBES2 parameter structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pbes2 {
    /// PBKDF2 salt.
    pub salt: Vec<u8>,
    /// PBKDF2 iteration count.
    pub iterations: u32,
    /// Explicit key length, when the parameters carry one.
    pub key_length: Option<usize>,
    /// PBKDF2 PRF digest.
    pub prf: Hash,
    /// Content encryption scheme.
    pub cipher: Pbes2Cipher,
}

/// MGF1-independent helper: the OID of `hmacWith<digest>` for PBKDF2 PRFs.
fn prf_to_hash(alg: &AlgorithmIdentifier) -> CryptoResult<Hash> {
    let hash = match alg.oid.arcs() {
        arcs if arcs == oid::OID_HMAC_SHA1 => Hash::Sha1,
        arcs if arcs == oid::OID_HMAC_SHA256 => Hash::Sha256,
        arcs if arcs == oid::OID_HMAC_SHA384 => Hash::Sha384,
        arcs if arcs == oid::OID_HMAC_SHA512 => Hash::Sha512,
        _ => {
            return Err(CryptoError::UnsupportedOperation(
                "unsupported PBKDF2 PRF".to_string(),
            ))
        }
    };
    Ok(hash)
}

/// The `hmacWith<digest>` OID for a digest.
fn hash_to_prf_oid(hash: Hash) -> &'static [u64] {
    match hash {
        Hash::Sha1 => oid::OID_HMAC_SHA1,
        Hash::Sha256 => oid::OID_HMAC_SHA256,
        Hash::Sha384 => oid::OID_HMAC_SHA384,
        Hash::Sha512 => oid::OID_HMAC_SHA512,
        _ => oid::OID_HMAC_SHA256,
    }
}

impl Pbes2 {
    /// Parse a PBES2 `AlgorithmIdentifier`.
    pub fn parse(alg: &AlgorithmIdentifier) -> CryptoResult<Self> {
        let params = alg
            .parameters
            .as_deref()
            .ok_or(CryptoError::StrError("pkcs: PBES2 parameters missing"))?;
        let mut reader = Reader::new(params);
        let mut seq = reader.read_sequence()?;
        let kdf = AlgorithmIdentifier::parse(&mut seq)?;
        if !kdf.oid.matches(oid::OID_PBKDF2) {
            return Err(CryptoError::UnsupportedOperation(
                "unsupported PBES2 key derivation function".to_string(),
            ));
        }
        let kdf_params = kdf
            .parameters
            .as_deref()
            .ok_or(CryptoError::StrError("pkcs: PBKDF2 parameters missing"))?;
        let mut kdf_reader = Reader::new(kdf_params);
        let mut kdf_seq = kdf_reader.read_sequence()?;
        let salt = kdf_seq.read_octet_string()?.to_vec();
        let iterations = u32::try_from(kdf_seq.read_integer_i64()?)
            .map_err(|_| CryptoError::StrError("pkcs: invalid PBKDF2 iterations"))?;
        let key_length = if !kdf_seq.is_empty() && kdf_seq.peek_tag()? == der::INTEGER {
            Some(
                usize::try_from(kdf_seq.read_integer_i64()?)
                    .map_err(|_| CryptoError::StrError("pkcs: invalid PBKDF2 key length"))?,
            )
        } else {
            None
        };
        let prf = if !kdf_seq.is_empty() {
            prf_to_hash(&AlgorithmIdentifier::parse(&mut kdf_seq)?)?
        } else {
            Hash::Sha1
        };
        let encryption = AlgorithmIdentifier::parse(&mut seq)?;
        let cipher = Self::parse_cipher(&encryption)?;
        seq.expect_end()?;
        Ok(Pbes2 {
            salt,
            iterations,
            key_length,
            prf,
            cipher,
        })
    }

    fn parse_cipher(encryption: &AlgorithmIdentifier) -> CryptoResult<Pbes2Cipher> {
        let params = encryption
            .parameters
            .as_deref()
            .ok_or(CryptoError::StrError(
                "pkcs: missing PBES2 cipher parameters",
            ))?;
        let mut reader = Reader::new(params);
        let iv = reader.read_octet_string()?.to_vec();
        let cipher = if encryption.oid.matches(oid::OID_AES_128_CBC) {
            Pbes2Cipher::Aes128Cbc { iv }
        } else if encryption.oid.matches(oid::OID_AES_192_CBC) {
            Pbes2Cipher::Aes192Cbc { iv }
        } else if encryption.oid.matches(oid::OID_AES_256_CBC) {
            Pbes2Cipher::Aes256Cbc { iv }
        } else if encryption.oid.matches(oid::OID_DES_EDE3_CBC) {
            Pbes2Cipher::DesEde3Cbc { iv }
        } else {
            return Err(CryptoError::UnsupportedOperation(
                "unsupported PBES2 cipher".to_string(),
            ));
        };
        if cipher.iv().len() != cipher.block_size() {
            return Err(CryptoError::StrError("pkcs: invalid PBES2 IV size"));
        }
        Ok(cipher)
    }

    /// Build the matching `AlgorithmIdentifier`.
    pub fn to_algorithm(&self) -> AlgorithmIdentifier {
        let prf = AlgorithmIdentifier::with_null(
            ObjectIdentifier::new(hash_to_prf_oid(self.prf)).expect("static oid"),
        );
        let mut kdf_params = der::octet_string(&self.salt);
        kdf_params.extend_from_slice(&der::integer(&(self.iterations as u64).to_be_bytes()));
        if let Some(key_length) = self.key_length {
            kdf_params.extend_from_slice(&der::integer(&(key_length as u64).to_be_bytes()));
        }
        kdf_params.extend_from_slice(&prf.encode());
        let kdf = AlgorithmIdentifier::new(
            ObjectIdentifier::new(oid::OID_PBKDF2).expect("static oid"),
            Some(der::sequence(&kdf_params)),
        );
        let encryption = AlgorithmIdentifier::new(
            ObjectIdentifier::new(self.cipher.oid()).expect("static oid"),
            Some(der::octet_string(self.cipher.iv())),
        );
        let mut params = kdf.encode();
        params.extend_from_slice(&encryption.encode());
        AlgorithmIdentifier::new(
            ObjectIdentifier::new(oid::OID_PBES2).expect("static oid"),
            Some(der::sequence(&params)),
        )
    }

    fn derive_key(&self, password: &[u8]) -> CryptoResult<Vec<u8>> {
        let key_len = self.key_length.unwrap_or_else(|| self.cipher.key_len());
        if key_len != self.cipher.key_len() {
            return Err(CryptoError::UnsupportedOperation(
                "PBES2 key length differs from the cipher key size".to_string(),
            ));
        }
        let mut key = vec![0u8; key_len];
        pbkdf2(self.prf, password, &self.salt, self.iterations, &mut key)?;
        Ok(key)
    }

    /// Decrypt (and PKCS#7-unpad) `data`.
    pub fn decrypt(&self, data: &[u8], password: &[u8]) -> CryptoResult<Vec<u8>> {
        let key = self.derive_key(password)?;
        if data.is_empty() || !data.len().is_multiple_of(self.cipher.block_size()) {
            return Err(CryptoError::StrError(
                "pkcs: invalid PBES2 ciphertext length",
            ));
        }
        let mut buffer = data.to_vec();
        self.cipher.decrypt(&key, &mut buffer)?;
        pkcs7_unpad(&mut buffer, self.cipher.block_size())
    }

    /// PKCS#7-pad and encrypt `data`.
    pub fn encrypt(&self, data: &[u8], password: &[u8]) -> CryptoResult<Vec<u8>> {
        let key = self.derive_key(password)?;
        let mut buffer = pkcs7_pad(data, self.cipher.block_size());
        self.cipher.encrypt(&key, &mut buffer)?;
        Ok(buffer)
    }
}

/// A parsed legacy PKCS#12 PBE `AlgorithmIdentifier`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyPbe {
    /// Salt (including the RC2 effective-bits octet when present).
    pub salt: Vec<u8>,
    /// Iteration count.
    pub iterations: u32,
    /// The cipher family.
    pub kind: LegacyPbeKind,
}

/// Legacy PKCS#12 PBE schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyPbeKind {
    /// `pbeWithSHA1And40BitRC4`.
    Rc4_40,
    /// `pbeWithSHA1And128BitRC4`.
    Rc4_128,
    /// `pbeWithSHA1And3-KeyTripleDES-CBC`.
    DesEde3,
    /// `pbeWithSHA1And2-KeyTripleDES-CBC`.
    DesEde2,
    /// `pbeWithSHA1And40BitRC2-CBC`.
    Rc2_40,
}

impl LegacyPbe {
    /// Parse a legacy PKCS#12 PBE `AlgorithmIdentifier`.
    pub fn parse(alg: &AlgorithmIdentifier) -> CryptoResult<Self> {
        let kind = if alg.oid.matches(oid::OID_PBE_SHA1_40BIT_RC4) {
            LegacyPbeKind::Rc4_40
        } else if alg.oid.matches(oid::OID_PBE_SHA1_128BIT_RC4) {
            LegacyPbeKind::Rc4_128
        } else if alg.oid.matches(oid::OID_PBE_SHA1_3DES) {
            LegacyPbeKind::DesEde3
        } else if alg.oid.matches(oid::OID_PBE_SHA1_2DES) {
            LegacyPbeKind::DesEde2
        } else if alg.oid.matches(oid::OID_PBE_SHA1_40BIT_RC2) {
            LegacyPbeKind::Rc2_40
        } else {
            return Err(CryptoError::UnsupportedOperation(
                "unsupported PKCS#12 PBE scheme".to_string(),
            ));
        };
        let params = alg
            .parameters
            .as_deref()
            .ok_or(CryptoError::StrError("pkcs: PBE parameters missing"))?;
        let mut reader = Reader::new(params);
        let mut seq = reader.read_sequence()?;
        let salt = seq.read_octet_string()?.to_vec();
        let iterations = u32::try_from(seq.read_integer_i64()?)
            .map_err(|_| CryptoError::StrError("pkcs: invalid PBE iterations"))?;
        Ok(LegacyPbe {
            salt,
            iterations,
            kind,
        })
    }

    /// Encode as an `AlgorithmIdentifier`.
    pub fn to_algorithm(&self) -> AlgorithmIdentifier {
        let oid = match self.kind {
            LegacyPbeKind::Rc4_40 => oid::OID_PBE_SHA1_40BIT_RC4,
            LegacyPbeKind::Rc4_128 => oid::OID_PBE_SHA1_128BIT_RC4,
            LegacyPbeKind::DesEde3 => oid::OID_PBE_SHA1_3DES,
            LegacyPbeKind::DesEde2 => oid::OID_PBE_SHA1_2DES,
            LegacyPbeKind::Rc2_40 => oid::OID_PBE_SHA1_40BIT_RC2,
        };
        let mut params = der::octet_string(&self.salt);
        params.extend_from_slice(&der::integer(&(self.iterations as u64).to_be_bytes()));
        AlgorithmIdentifier::new(
            ObjectIdentifier::new(oid).expect("static oid"),
            Some(der::sequence(&params)),
        )
    }

    /// Decrypt (and PKCS#7-unpad) `data`.
    pub fn decrypt(&self, data: &[u8], password: &[u8]) -> CryptoResult<Vec<u8>> {
        let bmp = pkcs12_password(password);
        let mut out = data.to_vec();
        match self.kind {
            LegacyPbeKind::Rc4_40 | LegacyPbeKind::Rc4_128 => {
                let key_len = if self.kind == LegacyPbeKind::Rc4_40 {
                    5
                } else {
                    16
                };
                let key = pkcs12kdf::derive(
                    Hash::Sha1.factory(),
                    &bmp,
                    &self.salt,
                    1,
                    self.iterations as u64,
                    key_len,
                )?;
                let mut rc4 = Rc4::new(&key)?;
                rc4.xor_key_stream(&mut out)?;
            }
            LegacyPbeKind::DesEde3 | LegacyPbeKind::DesEde2 => {
                let mut key = pkcs12kdf::derive(
                    Hash::Sha1.factory(),
                    &bmp,
                    &self.salt,
                    1,
                    self.iterations as u64,
                    24,
                )?;
                if self.kind == LegacyPbeKind::DesEde2 {
                    // 2-key 3DES: K3 = K1.
                    let k1: [u8; 8] = key[0..8].try_into().expect("8 bytes");
                    key[16..24].copy_from_slice(&k1);
                }
                let iv = pkcs12kdf::derive(
                    Hash::Sha1.factory(),
                    &bmp,
                    &self.salt,
                    2,
                    self.iterations as u64,
                    8,
                )?;
                let cipher = TripleDes::new(&key)?;
                let mut mode = cipher.to_cbc_dec(&iv);
                mode.encrypt(&mut out);
                out = pkcs7_unpad(&mut out, 8)?;
            }
            LegacyPbeKind::Rc2_40 => {
                let key = pkcs12kdf::derive(
                    Hash::Sha1.factory(),
                    &bmp,
                    &self.salt,
                    1,
                    self.iterations as u64,
                    5,
                )?;
                let iv = pkcs12kdf::derive(
                    Hash::Sha1.factory(),
                    &bmp,
                    &self.salt,
                    2,
                    self.iterations as u64,
                    8,
                )?;
                let cipher = Rc2::new(&key, Some(40))?;
                let mut mode = cipher.to_cbc_dec(&iv);
                mode.encrypt(&mut out);
                out = pkcs7_unpad(&mut out, 8)?;
            }
        }
        Ok(out)
    }

    /// PKCS#7-pad and encrypt `data`.
    pub fn encrypt(&self, data: &[u8], password: &[u8]) -> CryptoResult<Vec<u8>> {
        let bmp = pkcs12_password(password);
        match self.kind {
            LegacyPbeKind::Rc4_40 | LegacyPbeKind::Rc4_128 => {
                let key_len = if self.kind == LegacyPbeKind::Rc4_40 {
                    5
                } else {
                    16
                };
                let key = pkcs12kdf::derive(
                    Hash::Sha1.factory(),
                    &bmp,
                    &self.salt,
                    1,
                    self.iterations as u64,
                    key_len,
                )?;
                let mut out = data.to_vec();
                let mut rc4 = Rc4::new(&key)?;
                rc4.xor_key_stream(&mut out)?;
                Ok(out)
            }
            LegacyPbeKind::DesEde3 | LegacyPbeKind::DesEde2 => {
                let mut key = pkcs12kdf::derive(
                    Hash::Sha1.factory(),
                    &bmp,
                    &self.salt,
                    1,
                    self.iterations as u64,
                    24,
                )?;
                if self.kind == LegacyPbeKind::DesEde2 {
                    let k1: [u8; 8] = key[0..8].try_into().expect("8 bytes");
                    key[16..24].copy_from_slice(&k1);
                }
                let iv = pkcs12kdf::derive(
                    Hash::Sha1.factory(),
                    &bmp,
                    &self.salt,
                    2,
                    self.iterations as u64,
                    8,
                )?;
                let mut out = pkcs7_pad(data, 8);
                let cipher = TripleDes::new(&key)?;
                let mut mode = cipher.to_cbc_enc(&iv);
                mode.encrypt(&mut out);
                Ok(out)
            }
            LegacyPbeKind::Rc2_40 => {
                let key = pkcs12kdf::derive(
                    Hash::Sha1.factory(),
                    &bmp,
                    &self.salt,
                    1,
                    self.iterations as u64,
                    5,
                )?;
                let iv = pkcs12kdf::derive(
                    Hash::Sha1.factory(),
                    &bmp,
                    &self.salt,
                    2,
                    self.iterations as u64,
                    8,
                )?;
                let mut out = pkcs7_pad(data, 8);
                let cipher = Rc2::new(&key, Some(40))?;
                let mut mode = cipher.to_cbc_enc(&iv);
                mode.encrypt(&mut out);
                Ok(out)
            }
        }
    }
}

/// Decrypt an `EncryptedPrivateKeyInfo` with a password.
pub fn decrypt_private_key(
    info: &EncryptedPrivateKeyInfo,
    password: &[u8],
) -> CryptoResult<PrivateKeyInfo> {
    let plaintext = if info.algorithm.oid.matches(oid::OID_PBES2) {
        Pbes2::parse(&info.algorithm)?.decrypt(&info.encrypted_data, password)?
    } else {
        LegacyPbe::parse(&info.algorithm)?.decrypt(&info.encrypted_data, password)?
    };
    PrivateKeyInfo::parse(&plaintext)
}

/// Encrypt a PKCS#8 `PrivateKeyInfo` DER with PBES2 (AES-256-CBC,
/// PBKDF2-HMAC-SHA256 by default).
pub fn encrypt_private_key(
    private_key_info: &[u8],
    password: &[u8],
    cipher: Pbes2Cipher,
    iterations: u32,
    rng: &mut impl Rng,
) -> CryptoResult<EncryptedPrivateKeyInfo> {
    let mut salt = vec![0u8; 16];
    rng.fill_bytes(&mut salt);
    let mut iv = vec![0u8; cipher.block_size()];
    rng.fill_bytes(&mut iv);
    let cipher = match cipher {
        Pbes2Cipher::Aes128Cbc { .. } => Pbes2Cipher::Aes128Cbc { iv },
        Pbes2Cipher::Aes192Cbc { .. } => Pbes2Cipher::Aes192Cbc { iv },
        Pbes2Cipher::Aes256Cbc { .. } => Pbes2Cipher::Aes256Cbc { iv },
        Pbes2Cipher::DesEde3Cbc { .. } => Pbes2Cipher::DesEde3Cbc { iv },
    };
    let pbes2 = Pbes2 {
        salt,
        iterations,
        key_length: None,
        prf: Hash::Sha256,
        cipher,
    };
    let encrypted_data = pbes2.encrypt(private_key_info, password)?;
    Ok(EncryptedPrivateKeyInfo {
        algorithm: pbes2.to_algorithm(),
        encrypted_data,
    })
}

/// Convert a password to the PKCS#12 BMPString encoding (UTF-16BE plus a
/// terminating NUL).
pub fn pkcs12_password(password: &[u8]) -> Vec<u8> {
    // An empty password stays empty: OpenSSL skips the BMPString conversion
    // when the password length is zero.
    if password.is_empty() {
        return Vec::new();
    }
    let text = core::str::from_utf8(password).unwrap_or("");
    let mut out = Vec::with_capacity(text.len() * 2 + 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// PKCS#7 padding.
pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad = block_size - (data.len() % block_size);
    let mut out = data.to_vec();
    out.extend(core::iter::repeat_n(pad as u8, pad));
    out
}

/// PKCS#7 unpadding.
pub fn pkcs7_unpad(data: &mut Vec<u8>, block_size: usize) -> CryptoResult<Vec<u8>> {
    let pad = *data
        .last()
        .ok_or(CryptoError::StrError("pkcs: empty plaintext"))? as usize;
    if pad == 0 || pad > block_size || pad > data.len() {
        return Err(CryptoError::StrError("pkcs: invalid padding"));
    }
    if data[data.len() - pad..].iter().any(|&b| b as usize != pad) {
        return Err(CryptoError::StrError("pkcs: invalid padding"));
    }
    data.truncate(data.len() - pad);
    Ok(core::mem::take(data))
}

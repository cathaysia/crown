//! Content-encryption ciphers, AES key wrap and the PWRI key wrapping.
//!
//! The wire representation ([`ContentCipher`]) carries the IV or GCM nonce,
//! while [`Cipher`] is the bare algorithm choice used by the builders.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use crate::aead::gcm::Gcm;
use crate::aead::Aead;
use crate::asn1::der::{self, Reader};
use crate::asn1::oid::{
    ObjectIdentifier, OID_AES_128_CBC, OID_AES_192_CBC, OID_AES_256_CBC, OID_DES_EDE3_CBC,
};
use crate::block::aes::Aes;
use crate::block::des::TripleDes;
use crate::block::BlockCipher;
use crate::error::{CryptoError, CryptoResult};
use crate::modes::cbc::{CbcDecryptor, CbcEncryptor};
use crate::modes::kw;
use crate::modes::BlockMode;
use crate::rng::Rng;
use crate::x509::algorithm::AlgorithmIdentifier;

use super::{
    oid_of, OID_AES_128_GCM, OID_AES_128_WRAP, OID_AES_192_GCM, OID_AES_192_WRAP, OID_AES_256_GCM,
    OID_AES_256_WRAP,
};

/// A content-encryption algorithm without key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// AES-128 in CBC mode with PKCS#7 padding.
    Aes128Cbc,
    /// AES-192 in CBC mode with PKCS#7 padding.
    Aes192Cbc,
    /// AES-256 in CBC mode with PKCS#7 padding.
    Aes256Cbc,
    /// AES-128 in GCM mode (16-byte tag appended to the ciphertext).
    Aes128Gcm,
    /// AES-192 in GCM mode.
    Aes192Gcm,
    /// AES-256 in GCM mode.
    Aes256Gcm,
    /// Three-key Triple DES in CBC mode with PKCS#7 padding.
    DesEde3Cbc,
}

impl Cipher {
    /// Content-encryption key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Cipher::Aes128Cbc | Cipher::Aes128Gcm => 16,
            Cipher::Aes192Cbc | Cipher::Aes192Gcm => 24,
            Cipher::Aes256Cbc | Cipher::Aes256Gcm => 32,
            Cipher::DesEde3Cbc => 24,
        }
    }

    /// Whether this is an AEAD cipher.
    pub fn is_aead(self) -> bool {
        matches!(
            self,
            Cipher::Aes128Gcm | Cipher::Aes192Gcm | Cipher::Aes256Gcm
        )
    }

    /// The algorithm OID.
    pub fn oid(self) -> &'static [u64] {
        match self {
            Cipher::Aes128Cbc => OID_AES_128_CBC,
            Cipher::Aes192Cbc => OID_AES_192_CBC,
            Cipher::Aes256Cbc => OID_AES_256_CBC,
            Cipher::Aes128Gcm => OID_AES_128_GCM,
            Cipher::Aes192Gcm => OID_AES_192_GCM,
            Cipher::Aes256Gcm => OID_AES_256_GCM,
            Cipher::DesEde3Cbc => OID_DES_EDE3_CBC,
        }
    }

    /// Look up a cipher by OID.
    pub fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        if oid.matches(OID_AES_128_CBC) {
            Some(Cipher::Aes128Cbc)
        } else if oid.matches(OID_AES_192_CBC) {
            Some(Cipher::Aes192Cbc)
        } else if oid.matches(OID_AES_256_CBC) {
            Some(Cipher::Aes256Cbc)
        } else if oid.matches(OID_AES_128_GCM) {
            Some(Cipher::Aes128Gcm)
        } else if oid.matches(OID_AES_192_GCM) {
            Some(Cipher::Aes192Gcm)
        } else if oid.matches(OID_AES_256_GCM) {
            Some(Cipher::Aes256Gcm)
        } else if oid.matches(OID_DES_EDE3_CBC) {
            Some(Cipher::DesEde3Cbc)
        } else {
            None
        }
    }

    /// Instantiate the cipher with a random IV or nonce.
    pub fn new_content_cipher(self, rng: &mut impl Rng) -> ContentCipher {
        match self {
            Cipher::Aes128Cbc => ContentCipher::Aes128Cbc {
                iv: random_bytes(16, rng),
            },
            Cipher::Aes192Cbc => ContentCipher::Aes192Cbc {
                iv: random_bytes(16, rng),
            },
            Cipher::Aes256Cbc => ContentCipher::Aes256Cbc {
                iv: random_bytes(16, rng),
            },
            Cipher::Aes128Gcm => ContentCipher::Aes128Gcm {
                nonce: random_bytes(12, rng),
                tag_len: 16,
            },
            Cipher::Aes192Gcm => ContentCipher::Aes192Gcm {
                nonce: random_bytes(12, rng),
                tag_len: 16,
            },
            Cipher::Aes256Gcm => ContentCipher::Aes256Gcm {
                nonce: random_bytes(12, rng),
                tag_len: 16,
            },
            Cipher::DesEde3Cbc => ContentCipher::DesEde3Cbc {
                iv: random_bytes(8, rng),
            },
        }
    }
}

fn random_bytes(len: usize, rng: &mut impl Rng) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rng.fill_bytes(&mut out);
    out
}

/// `EncryptedContentInfo.contentEncryptionAlgorithm`: the cipher plus its
/// IV or GCM parameters, as it appears on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentCipher {
    /// AES-128-CBC with an OCTET STRING IV parameter.
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
    /// AES-128-GCM with `GCMParameters`.
    Aes128Gcm {
        /// Nonce.
        nonce: Vec<u8>,
        /// Authentication tag length in bytes.
        tag_len: usize,
    },
    /// AES-192-GCM.
    Aes192Gcm {
        /// Nonce.
        nonce: Vec<u8>,
        /// Authentication tag length in bytes.
        tag_len: usize,
    },
    /// AES-256-GCM.
    Aes256Gcm {
        /// Nonce.
        nonce: Vec<u8>,
        /// Authentication tag length in bytes.
        tag_len: usize,
    },
    /// DES-EDE3-CBC with an 8-byte IV parameter.
    DesEde3Cbc {
        /// Initialization vector.
        iv: Vec<u8>,
    },
}

impl ContentCipher {
    /// The bare algorithm choice.
    pub fn cipher(&self) -> Cipher {
        match self {
            ContentCipher::Aes128Cbc { .. } => Cipher::Aes128Cbc,
            ContentCipher::Aes192Cbc { .. } => Cipher::Aes192Cbc,
            ContentCipher::Aes256Cbc { .. } => Cipher::Aes256Cbc,
            ContentCipher::Aes128Gcm { .. } => Cipher::Aes128Gcm,
            ContentCipher::Aes192Gcm { .. } => Cipher::Aes192Gcm,
            ContentCipher::Aes256Gcm { .. } => Cipher::Aes256Gcm,
            ContentCipher::DesEde3Cbc { .. } => Cipher::DesEde3Cbc,
        }
    }

    /// Content-encryption key length in bytes.
    pub fn key_len(&self) -> usize {
        self.cipher().key_len()
    }

    /// Whether this is an AEAD cipher.
    pub fn is_aead(&self) -> bool {
        self.cipher().is_aead()
    }

    /// The detached authentication tag length, for AEAD ciphers.
    pub fn tag_len(&self) -> Option<usize> {
        match self {
            ContentCipher::Aes128Gcm { tag_len, .. }
            | ContentCipher::Aes192Gcm { tag_len, .. }
            | ContentCipher::Aes256Gcm { tag_len, .. } => Some(*tag_len),
            _ => None,
        }
    }

    /// Parse the `contentEncryptionAlgorithm` field.
    pub fn parse(alg: &AlgorithmIdentifier) -> CryptoResult<Self> {
        let cipher = Cipher::from_oid(&alg.oid).ok_or_else(|| {
            CryptoError::UnsupportedOperation(alloc::format!(
                "cms: unsupported content cipher {}",
                alg.oid
            ))
        })?;
        match cipher {
            Cipher::Aes128Cbc | Cipher::Aes192Cbc | Cipher::Aes256Cbc | Cipher::DesEde3Cbc => {
                let params = alg
                    .parameters
                    .as_deref()
                    .ok_or(CryptoError::StrError("cms: missing cipher parameters"))?;
                let mut reader = Reader::new(params);
                let iv = reader.read_octet_string()?.to_vec();
                reader.expect_end()?;
                let expected = if cipher == Cipher::DesEde3Cbc { 8 } else { 16 };
                if iv.len() != expected {
                    return Err(CryptoError::StrError("cms: invalid cipher IV"));
                }
                Ok(match cipher {
                    Cipher::Aes128Cbc => ContentCipher::Aes128Cbc { iv },
                    Cipher::Aes192Cbc => ContentCipher::Aes192Cbc { iv },
                    Cipher::Aes256Cbc => ContentCipher::Aes256Cbc { iv },
                    _ => ContentCipher::DesEde3Cbc { iv },
                })
            }
            Cipher::Aes128Gcm | Cipher::Aes192Gcm | Cipher::Aes256Gcm => {
                let (nonce, tag_len) = parse_gcm_parameters(alg.parameters.as_deref())?;
                Ok(match cipher {
                    Cipher::Aes128Gcm => ContentCipher::Aes128Gcm { nonce, tag_len },
                    Cipher::Aes192Gcm => ContentCipher::Aes192Gcm { nonce, tag_len },
                    _ => ContentCipher::Aes256Gcm { nonce, tag_len },
                })
            }
        }
    }

    /// The `contentEncryptionAlgorithm` for this cipher.
    pub fn to_algorithm(&self) -> AlgorithmIdentifier {
        let oid = oid_of(self.cipher().oid());
        match self {
            ContentCipher::Aes128Cbc { iv }
            | ContentCipher::Aes192Cbc { iv }
            | ContentCipher::Aes256Cbc { iv }
            | ContentCipher::DesEde3Cbc { iv } => {
                AlgorithmIdentifier::new(oid, Some(der::octet_string(iv)))
            }
            ContentCipher::Aes128Gcm { nonce, tag_len }
            | ContentCipher::Aes192Gcm { nonce, tag_len }
            | ContentCipher::Aes256Gcm { nonce, tag_len } => {
                let mut params = der::octet_string(nonce);
                params.extend_from_slice(&der::integer(&(*tag_len as u64).to_be_bytes()));
                AlgorithmIdentifier::new(oid, Some(der::sequence(&params)))
            }
        }
    }

    /// Encrypt `plaintext` under `key`, padding CBC modes and appending the
    /// GCM tag.
    pub fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        if key.len() != self.key_len() {
            return Err(CryptoError::StrError("cms: invalid content key size"));
        }
        match self {
            ContentCipher::Aes128Cbc { iv }
            | ContentCipher::Aes192Cbc { iv }
            | ContentCipher::Aes256Cbc { iv } => {
                let mut buffer = pkcs7_pad(plaintext, 16);
                cbc_encrypt(key, iv, &mut buffer, false)?;
                Ok(buffer)
            }
            ContentCipher::DesEde3Cbc { iv } => {
                let mut buffer = pkcs7_pad(plaintext, 8);
                cbc_encrypt(key, iv, &mut buffer, true)?;
                Ok(buffer)
            }
            ContentCipher::Aes128Gcm { nonce, .. }
            | ContentCipher::Aes192Gcm { nonce, .. }
            | ContentCipher::Aes256Gcm { nonce, .. } => {
                let aead = Aes::new(key)?.to_gcm()?;
                let mut buffer = plaintext.to_vec();
                let tag = aead.seal_in_place_separate_tag(&mut buffer, nonce, &[])?;
                buffer.extend_from_slice(&tag);
                Ok(buffer)
            }
        }
    }

    /// Decrypt `ciphertext` under `key`, removing CBC padding and verifying
    /// the GCM tag.
    pub fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        if key.len() != self.key_len() {
            return Err(CryptoError::StrError("cms: invalid content key size"));
        }
        match self {
            ContentCipher::Aes128Cbc { iv }
            | ContentCipher::Aes192Cbc { iv }
            | ContentCipher::Aes256Cbc { iv } => {
                let mut buffer = ciphertext.to_vec();
                cbc_decrypt(key, iv, &mut buffer, false)?;
                pkcs7_unpad(buffer, 16)
            }
            ContentCipher::DesEde3Cbc { iv } => {
                let mut buffer = ciphertext.to_vec();
                cbc_decrypt(key, iv, &mut buffer, true)?;
                pkcs7_unpad(buffer, 8)
            }
            ContentCipher::Aes128Gcm { nonce, tag_len }
            | ContentCipher::Aes192Gcm { nonce, tag_len }
            | ContentCipher::Aes256Gcm { nonce, tag_len } => {
                if *tag_len > ciphertext.len() {
                    return Err(CryptoError::StrError("cms: truncated GCM ciphertext"));
                }
                let (data, tag) = ciphertext.split_at(ciphertext.len() - tag_len);
                gcm_open(key, nonce, data, tag, &[])
            }
        }
    }

    /// Verify and decrypt an AEAD ciphertext whose authentication tag is
    /// carried separately (as in RFC 5083's `AuthEnvelopedData`).
    pub(crate) fn decrypt_with_tag(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if key.len() != self.key_len() {
            return Err(CryptoError::StrError("cms: invalid content key size"));
        }
        match self {
            ContentCipher::Aes128Gcm { nonce, .. }
            | ContentCipher::Aes192Gcm { nonce, .. }
            | ContentCipher::Aes256Gcm { nonce, .. } => gcm_open(key, nonce, ciphertext, tag, aad),
            _ => Err(CryptoError::UnsupportedOperation(
                "cms: detached AEAD tag requires a GCM cipher".to_string(),
            )),
        }
    }
}

/// Decode `GCMParameters ::= SEQUENCE { aes-nonce OCTET STRING OPTIONAL,
/// aes-ICVlen INTEGER DEFAULT 12 }`.
fn parse_gcm_parameters(params: Option<&[u8]>) -> CryptoResult<(Vec<u8>, usize)> {
    let params = params.ok_or(CryptoError::StrError("cms: missing GCM parameters"))?;
    let mut reader = Reader::new(params);
    let mut seq = reader.read_sequence()?;
    let nonce = seq.read_octet_string()?.to_vec();
    if nonce.is_empty() {
        return Err(CryptoError::StrError("cms: empty GCM nonce"));
    }
    // The RFC 5084 default is 12, but every OpenSSL-produced message carries
    // an explicit aes-ICVlen of 16; absent means 16 here to match the tag the
    // ciphertext actually appends.
    let tag_len = if seq.is_empty() {
        16
    } else {
        usize::try_from(seq.read_integer_i64()?)
            .map_err(|_| CryptoError::StrError("cms: invalid GCM tag length"))?
    };
    seq.expect_end()?;
    reader.expect_end()?;
    if !(12..=16).contains(&tag_len) {
        return Err(CryptoError::StrError("cms: invalid GCM tag length"));
    }
    Ok((nonce, tag_len))
}

/// GCM open with an explicit tag and associated data, dispatched on the tag
/// length.
fn gcm_open(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    fn open<const N: usize>(
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let aead = Aes::new(key)?.to_gcm_with_params::<12, N>()?;
        let mut buffer = ciphertext.to_vec();
        aead.open_in_place_separate_tag(&mut buffer, tag, nonce, aad)?;
        Ok(buffer)
    }
    match tag.len() {
        12 => open::<12>(key, nonce, ciphertext, tag, aad),
        13 => open::<13>(key, nonce, ciphertext, tag, aad),
        14 => open::<14>(key, nonce, ciphertext, tag, aad),
        15 => open::<15>(key, nonce, ciphertext, tag, aad),
        16 => open::<16>(key, nonce, ciphertext, tag, aad),
        _ => Err(CryptoError::StrError("cms: unsupported GCM tag length")),
    }
}

/// CBC-encrypt `data` in place (no padding).
fn cbc_encrypt(key: &[u8], iv: &[u8], data: &mut [u8], des: bool) -> CryptoResult<()> {
    if des {
        let cipher = TripleDes::new(key)?;
        cipher.to_cbc_enc(iv).encrypt(data);
    } else {
        let cipher = Aes::new(key)?;
        cipher.to_cbc_enc(iv).encrypt(data);
    }
    Ok(())
}

/// CBC-decrypt `data` in place (no unpadding).
fn cbc_decrypt(key: &[u8], iv: &[u8], data: &mut [u8], des: bool) -> CryptoResult<()> {
    if des {
        let cipher = TripleDes::new(key)?;
        cipher.to_cbc_dec(iv).encrypt(data);
    } else {
        let cipher = Aes::new(key)?;
        cipher.to_cbc_dec(iv).encrypt(data);
    }
    Ok(())
}

/// PKCS#7 padding with the CMS error prefix.
pub(crate) fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad = block_size - (data.len() % block_size);
    let mut out = data.to_vec();
    out.extend(core::iter::repeat_n(pad as u8, pad));
    out
}

/// PKCS#7 unpadding with the CMS error prefix.
pub(crate) fn pkcs7_unpad(mut data: Vec<u8>, block_size: usize) -> CryptoResult<Vec<u8>> {
    let pad = *data
        .last()
        .ok_or(CryptoError::StrError("cms: empty ciphertext"))? as usize;
    if pad == 0 || pad > block_size || pad > data.len() {
        return Err(CryptoError::StrError("cms: invalid padding"));
    }
    if data[data.len() - pad..].iter().any(|&b| b as usize != pad) {
        return Err(CryptoError::StrError("cms: invalid padding"));
    }
    data.truncate(data.len() - pad);
    Ok(data)
}

/// An AES key-wrap algorithm (`id-aes128-wrap`, `id-aes192-wrap`,
/// `id-aes256-wrap`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWrapAlgorithm {
    /// `id-aes128-wrap` (RFC 3394 with a 128-bit KEK).
    Aes128,
    /// `id-aes192-wrap`.
    Aes192,
    /// `id-aes256-wrap`.
    Aes256,
}

impl KeyWrapAlgorithm {
    /// KEK length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            KeyWrapAlgorithm::Aes128 => 16,
            KeyWrapAlgorithm::Aes192 => 24,
            KeyWrapAlgorithm::Aes256 => 32,
        }
    }

    /// The OID of the wrap algorithm.
    pub fn oid(self) -> &'static [u64] {
        match self {
            KeyWrapAlgorithm::Aes128 => OID_AES_128_WRAP,
            KeyWrapAlgorithm::Aes192 => OID_AES_192_WRAP,
            KeyWrapAlgorithm::Aes256 => OID_AES_256_WRAP,
        }
    }

    /// Pick the wrap algorithm for a KEK of `len` bytes.
    pub fn from_key_len(len: usize) -> CryptoResult<Self> {
        match len {
            16 => Ok(KeyWrapAlgorithm::Aes128),
            24 => Ok(KeyWrapAlgorithm::Aes192),
            32 => Ok(KeyWrapAlgorithm::Aes256),
            _ => Err(CryptoError::UnsupportedOperation(alloc::format!(
                "cms: unsupported AES key wrap key size {len}"
            ))),
        }
    }

    /// Parse a `KeyWrapAlgorithm` `AlgorithmIdentifier` (parameters are
    /// ignored: RFC 3394 has none).
    pub fn parse(alg: &AlgorithmIdentifier) -> CryptoResult<Self> {
        if alg.oid.matches(OID_AES_128_WRAP) {
            Ok(KeyWrapAlgorithm::Aes128)
        } else if alg.oid.matches(OID_AES_192_WRAP) {
            Ok(KeyWrapAlgorithm::Aes192)
        } else if alg.oid.matches(OID_AES_256_WRAP) {
            Ok(KeyWrapAlgorithm::Aes256)
        } else {
            Err(CryptoError::UnsupportedOperation(alloc::format!(
                "cms: unsupported key wrap algorithm {}",
                alg.oid
            )))
        }
    }

    /// The `AlgorithmIdentifier` for this wrap algorithm.
    pub fn to_identifier(self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::new(oid_of(self.oid()), None)
    }

    /// RFC 3394 key wrap.
    pub fn wrap(self, kek: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        if kek.len() != self.key_len() {
            return Err(CryptoError::StrError("cms: invalid KEK size"));
        }
        kw::key_wrap(&Aes::new(kek)?, key)
    }

    /// RFC 3394 key unwrap.
    pub fn unwrap(self, kek: &[u8], wrapped: &[u8]) -> CryptoResult<Vec<u8>> {
        if kek.len() != self.key_len() {
            return Err(CryptoError::StrError("cms: invalid KEK size"));
        }
        kw::key_unwrap(&Aes::new(kek)?, wrapped)
    }
}

/// The password-recipient KEK cipher: a CBC cipher used with the RFC 3217
/// double-encryption wrapping scheme that RFC 5652's `id-alg-PWRI-KEK`
/// specifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KekCipher {
    Aes128,
    Aes192,
    Aes256,
    DesEde3,
}

impl KekCipher {
    /// The PBKDF2-derived KEK cipher matching a content cipher.
    pub(crate) fn for_content(cipher: Cipher) -> Self {
        match cipher {
            Cipher::Aes128Cbc | Cipher::Aes128Gcm => KekCipher::Aes128,
            Cipher::Aes192Cbc | Cipher::Aes192Gcm => KekCipher::Aes192,
            Cipher::Aes256Cbc | Cipher::Aes256Gcm => KekCipher::Aes256,
            Cipher::DesEde3Cbc => KekCipher::DesEde3,
        }
    }

    pub(crate) fn key_len(self) -> usize {
        match self {
            KekCipher::Aes128 => 16,
            KekCipher::Aes192 => 24,
            KekCipher::Aes256 => 32,
            KekCipher::DesEde3 => 24,
        }
    }

    pub(crate) fn block_size(self) -> usize {
        match self {
            KekCipher::DesEde3 => 8,
            _ => 16,
        }
    }

    pub(crate) fn oid(self) -> &'static [u64] {
        match self {
            KekCipher::Aes128 => OID_AES_128_CBC,
            KekCipher::Aes192 => OID_AES_192_CBC,
            KekCipher::Aes256 => OID_AES_256_CBC,
            KekCipher::DesEde3 => OID_DES_EDE3_CBC,
        }
    }

    fn des(self) -> bool {
        self == KekCipher::DesEde3
    }

    /// Parse the inner `keyEncryptionAlgorithm` of a PWRI recipient,
    /// returning the cipher and its IV.
    pub(crate) fn parse(alg: &AlgorithmIdentifier) -> CryptoResult<(Self, Vec<u8>)> {
        let cipher = if alg.oid.matches(OID_AES_128_CBC) {
            KekCipher::Aes128
        } else if alg.oid.matches(OID_AES_192_CBC) {
            KekCipher::Aes192
        } else if alg.oid.matches(OID_AES_256_CBC) {
            KekCipher::Aes256
        } else if alg.oid.matches(OID_DES_EDE3_CBC) {
            KekCipher::DesEde3
        } else {
            return Err(CryptoError::UnsupportedOperation(alloc::format!(
                "cms: unsupported PWRI key encryption algorithm {}",
                alg.oid
            )));
        };
        let params = alg
            .parameters
            .as_deref()
            .ok_or(CryptoError::StrError("cms: missing PWRI cipher parameters"))?;
        let mut reader = Reader::new(params);
        let iv = reader.read_octet_string()?.to_vec();
        reader.expect_end()?;
        if iv.len() != cipher.block_size() {
            return Err(CryptoError::StrError("cms: invalid PWRI cipher IV"));
        }
        Ok((cipher, iv))
    }

    pub(crate) fn to_identifier(self, iv: &[u8]) -> AlgorithmIdentifier {
        AlgorithmIdentifier::new(oid_of(self.oid()), Some(der::octet_string(iv)))
    }

    fn crypt(&self, key: &[u8], iv: &[u8], data: &mut [u8], encrypt: bool) -> CryptoResult<()> {
        if encrypt {
            cbc_encrypt(key, iv, data, self.des())
        } else {
            cbc_decrypt(key, iv, data, self.des())
        }
    }

    /// RFC 3217-style wrap: a four-octet header, the CEK and random padding
    /// are CBC-encrypted twice (the second pass chaining from the last
    /// ciphertext block), matching OpenSSL's `id-alg-PWRI-KEK`.
    pub(crate) fn wrap(
        &self,
        kek: &[u8],
        iv: &[u8],
        cek: &[u8],
        rng: &mut impl Rng,
    ) -> CryptoResult<Vec<u8>> {
        let block_size = self.block_size();
        if cek.len() < 3 || cek.len() > 0xff {
            return Err(CryptoError::StrError("cms: invalid CEK length"));
        }
        let mut len = (cek.len() + 4).div_ceil(block_size) * block_size;
        if len < 2 * block_size {
            len = 2 * block_size;
        }
        let mut buffer = vec![0u8; len];
        buffer[0] = cek.len() as u8;
        for i in 0..3 {
            buffer[1 + i] = cek[i] ^ 0xff;
        }
        buffer[4..4 + cek.len()].copy_from_slice(cek);
        rng.fill_bytes(&mut buffer[4 + cek.len()..]);

        self.crypt(kek, iv, &mut buffer, true)?;
        let last = buffer[len - block_size..].to_vec();
        self.crypt(kek, &last, &mut buffer, true)?;
        Ok(buffer)
    }

    /// Reverse of [`Self::wrap`], checking the RFC 3217 header.
    pub(crate) fn unwrap(&self, kek: &[u8], iv: &[u8], wrapped: &[u8]) -> CryptoResult<Vec<u8>> {
        let block_size = self.block_size();
        if wrapped.len() < 2 * block_size || !wrapped.len().is_multiple_of(block_size) {
            return Err(CryptoError::AuthenticationFailed);
        }
        // C1 (the first pass ciphertext) needs the IV that the second pass
        // used: the last block of C1. CBC decryption recovers that from the
        // final two ciphertext blocks.
        let mut last = wrapped[wrapped.len() - block_size..].to_vec();
        let previous = &wrapped[wrapped.len() - 2 * block_size..wrapped.len() - block_size];
        self.decrypt_block(kek, &mut last)?;
        for (byte, &prev) in last.iter_mut().zip(previous.iter()) {
            *byte ^= prev;
        }
        let mut buffer = wrapped.to_vec();
        self.crypt(kek, &last, &mut buffer, false)?;
        self.crypt(kek, iv, &mut buffer, false)?;

        if ((buffer[1] ^ buffer[4]) & (buffer[2] ^ buffer[5]) & (buffer[3] ^ buffer[6])) != 0xff {
            return Err(CryptoError::AuthenticationFailed);
        }
        let cek_len = buffer[0] as usize;
        if 4 + cek_len > buffer.len() {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(buffer[4..4 + cek_len].to_vec())
    }

    fn decrypt_block(&self, key: &[u8], block: &mut [u8]) -> CryptoResult<()> {
        if self.des() {
            TripleDes::new(key)?.decrypt_block(block);
        } else {
            Aes::new(key)?.decrypt_block(block);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRng(u64);

    impl Rng for TestRng {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            for byte in out.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (self.0 >> 33) as u8;
            }
        }
    }

    #[test]
    fn content_cipher_round_trip() {
        let mut rng = TestRng(7);
        for cipher in [
            Cipher::Aes128Cbc,
            Cipher::Aes192Cbc,
            Cipher::Aes256Cbc,
            Cipher::Aes128Gcm,
            Cipher::Aes192Gcm,
            Cipher::Aes256Gcm,
            Cipher::DesEde3Cbc,
        ] {
            let wire = cipher.new_content_cipher(&mut rng);
            let parsed = ContentCipher::parse(&wire.to_algorithm()).unwrap();
            assert_eq!(parsed, wire, "{cipher:?}");
            let key = vec![0x42u8; cipher.key_len()];
            let plaintext = b"crown cms content cipher round trip";
            let ciphertext = wire.encrypt(&key, plaintext).unwrap();
            assert_eq!(wire.decrypt(&key, &ciphertext).unwrap(), plaintext);
        }
    }

    #[test]
    fn gcm_tag_is_appended() {
        let mut rng = TestRng(11);
        let wire = Cipher::Aes256Gcm.new_content_cipher(&mut rng);
        let key = [0u8; 32];
        let ciphertext = wire.encrypt(&key, b"abc").unwrap();
        assert_eq!(ciphertext.len(), 3 + 16);
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 1;
        assert!(wire.decrypt(&key, &tampered).is_err());
    }

    #[test]
    fn key_wrap_round_trip() {
        for (algorithm, key) in [
            (KeyWrapAlgorithm::Aes128, vec![0x11u8; 32]),
            (KeyWrapAlgorithm::Aes192, vec![0x11u8; 24]),
            (KeyWrapAlgorithm::Aes256, vec![0x11u8; 32]),
        ] {
            let kek = vec![0x22u8; algorithm.key_len()];
            let wrapped = algorithm.wrap(&kek, &key).unwrap();
            assert_eq!(wrapped.len(), key.len() + 8);
            assert_eq!(algorithm.unwrap(&kek, &wrapped).unwrap(), key);
            assert_eq!(
                KeyWrapAlgorithm::parse(&algorithm.to_identifier()).unwrap(),
                algorithm
            );
            let mut tampered = wrapped;
            tampered[5] ^= 1;
            assert!(algorithm.unwrap(&kek, &tampered).is_err());
        }
    }

    #[test]
    fn pwri_kek_wrap_round_trip() {
        let mut rng = TestRng(3);
        for cipher in [
            KekCipher::Aes128,
            KekCipher::Aes192,
            KekCipher::Aes256,
            KekCipher::DesEde3,
        ] {
            let kek = vec![0x33u8; cipher.key_len()];
            let iv = vec![0x44u8; cipher.block_size()];
            let cek = vec![0x55u8; 32];
            let wrapped = cipher.wrap(&kek, &iv, &cek, &mut rng).unwrap();
            assert!(wrapped.len() >= 2 * cipher.block_size());
            assert_eq!(cipher.unwrap(&kek, &iv, &wrapped).unwrap(), cek);
            let mut tampered = wrapped;
            tampered[0] ^= 0xff;
            assert!(cipher.unwrap(&kek, &iv, &tampered).is_err());
        }
    }
}

//! PBES2: Password-Based Encryption Scheme 2 (PKCS #5 v2.1 / RFC 8018 §6.2).
//!
//! Key and IV are derived together from the password via the selected KDF:
//! `dk = KDF(pass, salt)` of length `key_len + iv_len`, then
//! `key = dk[..key_len]`, `iv = dk[key_len..key_len+iv_len]`.
//! The IV is prepended to the ciphertext: output = `iv || CBC(pt || pkcs7_pad)`.

use crate::block::aes::Aes;
use crate::block::des::TripleDes;
use crate::block::BlockCipher;
use crate::error::{CryptoError, CryptoResult};
use crate::hash::sha1::new as new_sha1;
use crate::hash::sha256::new256;
use crate::hash::sha512::{new384, new512};
use crate::modes::cbc::{CbcDecryptor, CbcEncryptor};
use crate::modes::BlockMode;
use crate::padding::Pkcs7;
use crate::padding::Padding;
use crate::password_hash::pbkdf2;

/// Hash algorithm identifiers usable with the PBES2 KDFs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashId {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

/// Supported PBES2 ciphers (PKCS #5 v2.1 encryptionScheme).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pbes2Cipher {
    Aes128Cbc,
    Aes256Cbc,
    DesEde3Cbc,
}

impl Pbes2Cipher {
    fn key_len(self) -> usize {
        match self {
            Pbes2Cipher::Aes128Cbc => 16,
            Pbes2Cipher::Aes256Cbc => 32,
            Pbes2Cipher::DesEde3Cbc => 24,
        }
    }

    fn block_size(self) -> usize {
        match self {
            Pbes2Cipher::Aes128Cbc | Pbes2Cipher::Aes256Cbc => 16,
            Pbes2Cipher::DesEde3Cbc => 8,
        }
    }
}

/// Supported PBES2 key derivation functions.
/// PBKDF2 is the PKCS #5 required scheme; HKDF is the PKCS #5 v2.1 optional one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pbes2Kdf {
    Pbkdf2 { hash: HashId, iterations: u32 },
    Hkdf { hash: HashId },
}

fn pbkdf2_derive(
    pass: &[u8],
    salt: &[u8],
    iterations: u32,
    hash: HashId,
    out_len: usize,
) -> Vec<u8> {
    match hash {
        HashId::Sha1 => pbkdf2::key::<20, _, _>(pass, salt, iterations, out_len, new_sha1),
        HashId::Sha256 => pbkdf2::key::<32, _, _>(pass, salt, iterations, out_len, new256),
        HashId::Sha384 => pbkdf2::key::<48, _, _>(pass, salt, iterations, out_len, new384),
        HashId::Sha512 => pbkdf2::key::<64, _, _>(pass, salt, iterations, out_len, new512),
    }
}

/// Derive `key_len + iv_len` bytes and split into (key, iv).
fn derive_key_iv(
    pass: &[u8],
    salt: &[u8],
    kdf: &Pbes2Kdf,
    cipher: Pbes2Cipher,
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let key_len = cipher.key_len();
    let iv_len = cipher.block_size();
    let total = key_len + iv_len;

    let dk = match kdf {
        Pbes2Kdf::Pbkdf2 { hash, iterations } => {
            if *iterations == 0 {
                return Err(CryptoError::InvalidParameterStr("iterations must be > 0"));
            }
            pbkdf2_derive(pass, salt, *iterations, *hash, total)
        }
        Pbes2Kdf::Hkdf { .. } => {
            return Err(CryptoError::InvalidParameterStr(
                "HKDF PBES2 is not implemented; use Pbkdf2",
            ));
        }
    };

    Ok((dk[..key_len].to_vec(), dk[key_len..total].to_vec()))
}

fn pkcs7_pad(pt: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (pt.len() % block_size);
    let mut out = pt.to_vec();
    out.resize(pt.len() + pad_len, 0);
    // Pkcs7::pad fills the last pad_len bytes with pad_len
    let len = pt.len();
    Pkcs7.pad(&mut out, len);
    out
}

fn pkcs7_unpad(buf: &[u8]) -> CryptoResult<Vec<u8>> {
    // Unpad the whole buffer; Pkcs7::unpad expects a single block-ish slice
    // but our impl validates the trailing pad bytes across the whole buffer.
    if buf.is_empty() {
        return Err(CryptoError::UnpadError);
    }
    let n = *buf.last().unwrap();
    if n == 0 || n as usize > buf.len() {
        return Err(CryptoError::UnpadError);
    }
    let s = buf.len() - n as usize;
    if buf[s..].iter().any(|&v| v != n) {
        return Err(CryptoError::UnpadError);
    }
    Ok(buf[..s].to_vec())
}

fn cbc_encrypt(key: &[u8], iv: &[u8], cipher: Pbes2Cipher, buf: &mut [u8]) {
    match cipher {
        Pbes2Cipher::Aes128Cbc | Pbes2Cipher::Aes256Cbc => {
            let aes = Aes::new(key).expect("AES key size checked");
            let mut enc = aes.to_cbc_enc(iv);
            enc.encrypt(buf);
        }
        Pbes2Cipher::DesEde3Cbc => {
            let tdes = TripleDes::new(key).expect("3DES key size checked");
            let mut enc = tdes.to_cbc_enc(iv);
            enc.encrypt(buf);
        }
    }
}

fn cbc_decrypt(key: &[u8], iv: &[u8], cipher: Pbes2Cipher, buf: &mut [u8]) {
    // Note: CBC decrypters implement the Go BlockMode convention where the
    // processing entry point is `encrypt()`; `decrypt()` is unreachable.
    match cipher {
        Pbes2Cipher::Aes128Cbc | Pbes2Cipher::Aes256Cbc => {
            let aes = Aes::new(key).expect("AES key size checked");
            let mut dec = aes.to_cbc_dec(iv);
            dec.encrypt(buf);
        }
        Pbes2Cipher::DesEde3Cbc => {
            let tdes = TripleDes::new(key).expect("3DES key size checked");
            let mut dec = tdes.to_cbc_dec(iv);
            dec.encrypt(buf);
        }
    }
}

/// Encrypt `pt` under `pass`/`salt` with the given KDF and cipher.
///
/// Returns `iv || ciphertext` (IV is the last `block_size` bytes of the KDF
/// output, prepended to the CBC of PKCS#7-padded plaintext).
pub fn pbes2_encrypt(
    pass: &[u8],
    salt: &[u8],
    kdf: &Pbes2Kdf,
    cipher: Pbes2Cipher,
    pt: &[u8],
) -> CryptoResult<Vec<u8>> {
    let (key, iv) = derive_key_iv(pass, salt, kdf, cipher)?;
    let mut buf = pkcs7_pad(pt, cipher.block_size());
    cbc_encrypt(&key, &iv, cipher, &mut buf);

    let mut out = iv.clone();
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Decrypt `ct = iv || ciphertext` produced by [`pbes2_encrypt`].
pub fn pbes2_decrypt(
    pass: &[u8],
    salt: &[u8],
    kdf: &Pbes2Kdf,
    cipher: Pbes2Cipher,
    ct: &[u8],
) -> CryptoResult<Vec<u8>> {
    let iv_len = cipher.block_size();
    if ct.len() < iv_len + iv_len {
        // need at least IV + one ciphertext block
        return Err(CryptoError::InvalidLength);
    }
    if (ct.len() - iv_len) % iv_len != 0 {
        return Err(CryptoError::InvalidLength);
    }

    let (key, _) = derive_key_iv(pass, salt, kdf, cipher)?;
    let iv = &ct[..iv_len];
    let mut buf = ct[iv_len..].to_vec();
    cbc_decrypt(&key, iv, cipher, &mut buf);
    pkcs7_unpad(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kdf_sha256(iter: u32) -> Pbes2Kdf {
        Pbes2Kdf::Pbkdf2 {
            hash: HashId::Sha256,
            iterations: iter,
        }
    }

    #[test]
    fn roundtrip_aes128_cbc() {
        let pass = b"correct horse battery staple";
        let salt = [0x11u8; 8];
        let pt = b"attack at dawn";
        let ct = pbes2_encrypt(pass, &salt, &kdf_sha256(1000), Pbes2Cipher::Aes128Cbc, pt).unwrap();
        assert!(ct.len() > 16);
        let got = pbes2_decrypt(pass, &salt, &kdf_sha256(1000), Pbes2Cipher::Aes128Cbc, &ct).unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn roundtrip_aes256_cbc() {
        let pass = b"password";
        let salt = [0x22u8; 16];
        let pt = b"hello world, this is a longer plaintext for AES-256-CBC!!";
        let ct = pbes2_encrypt(pass, &salt, &kdf_sha256(500), Pbes2Cipher::Aes256Cbc, pt).unwrap();
        let got = pbes2_decrypt(pass, &salt, &kdf_sha256(500), Pbes2Cipher::Aes256Cbc, &ct).unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn roundtrip_des_ede3_cbc() {
        let pass = b"3des-pass";
        let salt = [0x33u8; 8];
        let pt = b"short";
        let ct = pbes2_encrypt(pass, &salt, &kdf_sha256(200), Pbes2Cipher::DesEde3Cbc, pt).unwrap();
        let got = pbes2_decrypt(pass, &salt, &kdf_sha256(200), Pbes2Cipher::DesEde3Cbc, &ct).unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn roundtrip_sha1_kdf() {
        let pass = b"pw";
        let salt = b"salt1234";
        let pt = b"payload";
        let kdf = Pbes2Kdf::Pbkdf2 {
            hash: HashId::Sha1,
            iterations: 100,
        };
        let ct = pbes2_encrypt(pass, salt, &kdf, Pbes2Cipher::Aes128Cbc, pt).unwrap();
        let got = pbes2_decrypt(pass, salt, &kdf, Pbes2Cipher::Aes128Cbc, &ct).unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn wrong_password_fails() {
        let salt = [0x44u8; 8];
        let pt = b"secret data";
        let ct = pbes2_encrypt(b"right", &salt, &kdf_sha256(50), Pbes2Cipher::Aes128Cbc, pt).unwrap();
        assert!(pbes2_decrypt(b"wrong", &salt, &kdf_sha256(50), Pbes2Cipher::Aes128Cbc, &ct).is_err());
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let salt = [0x55u8; 8];
        let ct = pbes2_encrypt(b"p", &salt, &kdf_sha256(10), Pbes2Cipher::Aes128Cbc, b"").unwrap();
        let got = pbes2_decrypt(b"p", &salt, &kdf_sha256(10), Pbes2Cipher::Aes128Cbc, &ct).unwrap();
        assert_eq!(got, b"");
    }

    #[test]
    fn pbkdf2_matches_password_hash_kat() {
        // Cross-check: our derived key/iv split is exactly the PBKDF2 output.
        let pass = b"password";
        let salt = b"salt";
        let kdf = Pbes2Kdf::Pbkdf2 {
            hash: HashId::Sha256,
            iterations: 2,
        };
        let (key, iv) = derive_key_iv(pass, salt, &kdf, Pbes2Cipher::Aes128Cbc).unwrap();
        let full = pbkdf2_derive(pass, salt, 2, HashId::Sha256, 32);
        assert_eq!(key, &full[..16]);
        assert_eq!(iv, &full[16..32]);
    }

    #[test]
    fn hkdf_unsupported() {
        let kdf = Pbes2Kdf::Hkdf {
            hash: HashId::Sha256,
        };
        assert!(pbes2_encrypt(b"p", b"s", &kdf, Pbes2Cipher::Aes128Cbc, b"x").is_err());
    }
}

//! Module md5_sha1 implements the MD5+SHA1 composite hash used by legacy
//! TLS RSA/DSA signature schemes (e.g. the TLS 1.0/1.1
//! `MD5-SHA1` combination digest, OpenSSL `EVP_md5_sha1`).
//!
//! The digest of a message `M` is defined as `MD5(M) || SHA1(M)` — 16 bytes
//! of MD5 followed by 20 bytes of SHA-1, for a total of 32 bytes. Both
//! member hashes consume the full message independently.
//!
//! # WARNING
//!
//! MD5 is cryptographically broken and this combination only exists for
//! compatibility with legacy protocols. It MUST NOT be used outside of
//! verifying or producing legacy TLS signature inputs.

#[cfg(test)]
mod tests;

use bytes::BufMut;
#[cfg(feature = "marshal")]
use crown_derive::Marshal;

use crate::{
    core::CoreWrite,
    error::CryptoResult,
    hash::{
        md5::{self, Md5},
        sha1::{self, Sha1},
        Hash, HashUser,
    },
};

/// The size of the combined MD5-SHA1 digest in bytes.
pub const SIZE: usize = 36;
/// The block size shared by both member hashes, in bytes.
pub const BLOCK_SIZE: usize = 64;

#[derive(Clone)]
#[cfg_attr(feature = "marshal", derive(Marshal))]
#[cfg_attr(feature = "marshal", marshal(magic = b"md5s"))]
pub struct Md5Sha1 {
    md5: Md5,
    sha1: Sha1,
}

impl CoreWrite for Md5Sha1 {
    fn write(&mut self, p: &[u8]) -> CryptoResult<usize> {
        let md5 = self.md5.write(p)?;
        let sha1 = self.sha1.write(p)?;
        debug_assert_eq!(md5, sha1);
        Ok(md5)
    }

    fn flush(&mut self) -> CryptoResult<()> {
        self.md5.flush()?;
        self.sha1.flush()?;
        Ok(())
    }
}

impl HashUser for Md5Sha1 {
    fn reset(&mut self) {
        self.md5.reset();
        self.sha1.reset();
    }

    fn size(&self) -> usize {
        SIZE
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }
}

impl Hash<36> for Md5Sha1 {
    fn sum(&mut self) -> [u8; 36] {
        let md5 = self.md5.sum();
        let sha1 = self.sha1.sum();

        let mut result = [0u8; 36];
        {
            let mut result = result.as_mut_slice();
            result.put_slice(&md5);
            result.put_slice(&sha1);
        }
        result
    }
}

/// Create a new [Hash] computing the MD5+SHA1 composite digest.
pub fn new_md5_sha1() -> Md5Sha1 {
    Md5Sha1 {
        md5: md5::new_md5(),
        sha1: sha1::new(),
    }
}

/// Compute the MD5+SHA1 composite digest of the input.
pub fn sum_md5_sha1(input: &[u8]) -> [u8; 36] {
    let mut h = new_md5_sha1();
    h.write_all(input).unwrap();
    h.sum()
}

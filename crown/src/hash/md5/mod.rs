//! Module md5 implements the MD5 hash algorithm as defined in RFC 1321.
//!
//! MD5 is a widely-used cryptographic hash algorithm that produces a
//! 128-bit hash value. It is commonly used for checksums, data
//! integrity verification, and fingerprinting non-critical data.
//!
//! # WARNING
//!
//! MD5 is cryptographically broken and should **not be used for secure
//! applications**. Instead, use a secure hash like SHA-256
//! (from [sha256](crate::hash::sha256::Sha256))
//!

mod block;
use block::block;

#[cfg(feature = "cuda")]
pub mod cuda;

use bytes::BufMut;
use crown_derive::Marshal;

use crate::{
    core::CoreWrite,
    error::CryptoResult,
    hash::{Hash, HashUser},
    utils::erase_ownership,
};

#[cfg(test)]
mod tests;

const INIT0: u32 = 0x67452301;
const INIT1: u32 = 0xEFCDAB89;
const INIT2: u32 = 0x98BADCFE;
const INIT3: u32 = 0x10325476;

#[derive(Clone, Marshal)]
pub struct Md5 {
    s: [u32; 4],
    x: [u8; Md5::BLOCK_SIZE],
    nx: usize,
    len: u64,
}

impl Md5 {
    pub(crate) const SIZE: usize = 16;
    pub(crate) const BLOCK_SIZE: usize = 64;

    fn check_sum(&mut self) -> [u8; Md5::SIZE] {
        let mut tmp = [0u8; 1 + 63 + 8];
        tmp[0] = 0x80;

        let pad = (55u64.wrapping_sub(self.len)) % 64;
        le_put_u64(&mut tmp[1 + pad as usize..], self.len << 3);
        self.write_all(&tmp[..1 + pad as usize + 8]).unwrap();

        if self.nx != 0 {
            panic!("d.nx != 0");
        }

        let mut digest = [0u8; Md5::SIZE];
        {
            let mut digest = digest.as_mut_slice();
            digest.put_u32_le(self.s[0]);
            digest.put_u32_le(self.s[1]);
            digest.put_u32_le(self.s[2]);
            digest.put_u32_le(self.s[3]);
        }
        digest
    }
}

impl CoreWrite for Md5 {
    fn write(&mut self, mut p: &[u8]) -> CryptoResult<usize> {
        let nn = p.len();
        self.len += nn as u64;

        if self.nx > 0 {
            let n = (Md5::BLOCK_SIZE - self.nx).min(p.len());
            self.x[self.nx..self.nx + n].copy_from_slice(&p[..n]);
            self.nx += n;
            if self.nx == Md5::BLOCK_SIZE {
                let x = unsafe { erase_ownership(&self.x) };
                block(self, x);
                self.nx = 0;
            }
            p = &p[n..];
        }

        if p.len() >= Md5::BLOCK_SIZE {
            let n = p.len() & !(Md5::BLOCK_SIZE - 1);
            block(self, &p[..n]);
            p = &p[n..];
        }

        if !p.is_empty() {
            self.nx = p.len();
            self.x[..self.nx].copy_from_slice(p);
        }

        Ok(nn)
    }

    fn flush(&mut self) -> CryptoResult<()> {
        Ok(())
    }
}

impl HashUser for Md5 {
    fn reset(&mut self) {
        self.s[0] = INIT0;
        self.s[1] = INIT1;
        self.s[2] = INIT2;
        self.s[3] = INIT3;
        self.nx = 0;
        self.len = 0;
    }

    fn size(&self) -> usize {
        Md5::SIZE
    }

    fn block_size(&self) -> usize {
        Md5::BLOCK_SIZE
    }
}

impl Hash<16> for Md5 {
    fn sum(&mut self) -> [u8; 16] {
        let mut d0 = self.clone();
        d0.check_sum()
    }
}

fn le_put_u64(b: &mut [u8], v: u64) {
    let bytes = v.to_le_bytes();
    b[0..8].copy_from_slice(&bytes);
}

/// Create a new [Hash] computing the Md5 checksum.
///
/// The Hash also implements [crate::mac::hmac::Marshalable] to marshal
/// and unmarshal the internal state of the hash.
pub fn new_md5() -> Md5 {
    let mut d = Md5 {
        s: [0; 4],
        x: [0; Md5::BLOCK_SIZE],
        nx: 0,
        len: 0,
    };
    d.reset();
    d
}

/// Compute the Md5 checksum of the input.
pub fn sum_md5(data: &[u8]) -> [u8; Md5::SIZE] {
    let mut d = new_md5();
    d.write_all(data).unwrap();
    d.check_sum()
}

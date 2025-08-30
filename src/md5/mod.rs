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
//! (from [sha256](crate::sha256::Sha256))
//!

mod md5block;

#[cfg(feature = "cuda")]
pub mod cuda;

mod md5_generic;
use std::io::Write;

use bytes::{Buf, BufMut};
use md5_generic::*;

use crate::{
    error::{CryptoError, CryptoResult},
    hash::{Hash, HashUser},
    hmac::Marshalable,
};

#[cfg(test)]
mod tests;

const INIT0: u32 = 0x67452301;
const INIT1: u32 = 0xEFCDAB89;
const INIT2: u32 = 0x98BADCFE;
const INIT3: u32 = 0x10325476;

const MAGIC: &[u8] = b"md5\x01";
const MARSHALED_SIZE: usize = MAGIC.len() + 4 * 4 + Md5::BLOCK_SIZE + 8;

#[derive(Clone)]
pub struct Md5 {
    s: [u32; 4],
    x: [u8; Md5::BLOCK_SIZE],
    nx: usize,
    len: u64,
}

impl Md5 {
    pub(crate) const SIZE: usize = 16;
    pub(crate) const BLOCK_SIZE: usize = 64;

    fn append_binary(&self, mut b: &mut [u8]) -> CryptoResult<()> {
        b.put_slice(MAGIC);
        b.put_u32(self.s[0]);
        b.put_u32(self.s[1]);
        b.put_u32(self.s[2]);
        b.put_u32(self.s[3]);
        b.put_slice(&self.x[..self.nx]);
        b.put_bytes(0, self.x.len() - self.nx);
        b.put_u64(self.len);
        Ok(())
    }

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

impl Write for Md5 {
    fn write(&mut self, p: &[u8]) -> std::io::Result<usize> {
        let nn = p.len();
        self.len += nn as u64;
        let mut p = p;

        if self.nx > 0 {
            let n = (Md5::BLOCK_SIZE - self.nx).min(p.len());
            self.x[self.nx..self.nx + n].copy_from_slice(&p[..n]);
            self.nx += n;
            if self.nx == Md5::BLOCK_SIZE {
                let x_copy = self.x;
                block(self, &x_copy);
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

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Marshalable for Md5 {
    fn marshal_binary(&self) -> CryptoResult<Vec<u8>> {
        let mut ret = vec![0u8; MARSHALED_SIZE];
        self.append_binary(&mut ret)?;
        Ok(ret)
    }

    fn unmarshal_binary(&mut self, b: &[u8]) -> CryptoResult<()> {
        if b.len() < MAGIC.len() || &b[..MAGIC.len()] != MAGIC {
            return Err(CryptoError::InvalidHashIdentifier);
        }
        if b.len() != MARSHALED_SIZE {
            return Err(CryptoError::InvalidHashState);
        }

        let mut b = &b[MAGIC.len()..];

        self.s[0] = b.get_u32();
        self.s[1] = b.get_u32();
        self.s[2] = b.get_u32();
        self.s[3] = b.get_u32();

        let copied = b.len().min(self.x.len());
        b.copy_to_slice(&mut self.x[..copied]);

        self.len = b.get_u64();
        self.nx = (self.len % Md5::BLOCK_SIZE as u64) as usize;

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
/// The Hash also implements [Marshalable] to marshal and unmarshal the internal state of the hash.
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

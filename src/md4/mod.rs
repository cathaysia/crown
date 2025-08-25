//! Module md4 implements the MD4 hash algorithm as defined in RFC 1320.
//!
//! MD4 is a widely-used cryptographic hash algorithm that produces a
//! 128-bit hash value. It is commonly used for checksums, data
//! integrity verification, and fingerprinting non-critical data.
//!
//! # WARNING
//!
//! Deprecated: MD4 is cryptographically broken and should only be used
//! where compatibility with legacy systems, not security, is the goal. Instead,
//! use a secure hash like SHA-256 (from [sha256](crate::sha256::Sha256)).

mod block;

#[cfg(test)]
mod tests;

use bytes::{Buf, BufMut};

use crate::{
    error::{CryptoError, CryptoResult},
    hash::{Hash, HashUser},
    hmac::Marshalable,
};
use std::io::{self, Write};

const CHUNK: usize = 64;
const INIT0: u32 = 0x67452301;
const INIT1: u32 = 0xEFCDAB89;
const INIT2: u32 = 0x98BADCFE;
const INIT3: u32 = 0x10325476;

const MAGIC: &[u8] = b"md4\x01";
const MARSHALED_SIZE: usize = MAGIC.len() + 4 * 4 + Md4::BLOCK_SIZE + 8;

#[derive(Clone)]
pub struct Md4 {
    s: [u32; 4],
    x: [u8; CHUNK],
    nx: usize,
    len: u64,
}

impl Md4 {
    /// The blocksize of MD4 in bytes.
    const BLOCK_SIZE: usize = 64;
    /// The size of an MD4 checksum in bytes.
    const SIZE: usize = 16;

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
}

impl Write for Md4 {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        let nn = p.len();
        self.len += nn as u64;
        let mut p = p;

        if self.nx > 0 {
            let n = std::cmp::min(p.len(), CHUNK - self.nx);
            self.x[self.nx..self.nx + n].copy_from_slice(&p[..n]);
            self.nx += n;
            if self.nx == CHUNK {
                let src = unsafe {
                    let ptr = self.x.as_ptr();
                    std::slice::from_raw_parts(ptr, self.x.len())
                };
                block::block(self, src);
                self.nx = 0;
            }
            p = &p[n..];
        }

        let n = block::block(self, p);
        p = &p[n..];

        if !p.is_empty() {
            self.nx = p.len();
            self.x[..self.nx].copy_from_slice(p);
        }

        Ok(nn)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl HashUser for Md4 {
    fn reset(&mut self) {
        self.s[0] = INIT0;
        self.s[1] = INIT1;
        self.s[2] = INIT2;
        self.s[3] = INIT3;
        self.nx = 0;
        self.len = 0;
    }

    fn size(&self) -> usize {
        Self::SIZE
    }

    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }
}

impl Hash<16> for Md4 {
    fn sum(&mut self) -> [u8; 16] {
        // Make a copy of self, so that caller can keep writing and summing.
        let mut d = self.clone();

        // Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
        let len = d.len;
        let mut tmp = [0u8; 64];
        tmp[0] = 0x80;

        if len % 64 < 56 {
            let _ = d.write(&tmp[0..(56 - (len % 64) as usize)]);
        } else {
            let _ = d.write(&tmp[0..(64 + 56 - (len % 64) as usize)]);
        }

        // Length in bits.
        let len_bits = len << 3;
        (0..8).for_each(|i| {
            tmp[i] = (len_bits >> (8 * i)) as u8;
        });
        let _ = d.write(&tmp[0..8]);

        if d.nx != 0 {
            panic!("d.nx != 0");
        }

        let mut result = [0u8; 16];
        {
            let mut result = result.as_mut_slice();
            result.put_u32_le(d.s[0]);
            result.put_u32_le(d.s[1]);
            result.put_u32_le(d.s[2]);
            result.put_u32_le(d.s[3]);
        }
        result
    }
}

impl Marshalable for Md4 {
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
        self.nx = (self.len % Md4::BLOCK_SIZE as u64) as usize;

        Ok(())
    }
}

/// Create a new [Hash] computing the Md4 checksum.
///
/// The Hash also implements [Marshalable] to marshal and unmarshal the internal state of the hash.
pub fn new_md4() -> Md4 {
    let mut d = Md4 {
        s: [0; 4],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
    };
    d.reset();
    d
}

/// Compute the Md4 checksum of the input.
pub fn sum_md4(input: &[u8]) -> [u8; 16] {
    let mut h = new_md4();
    h.write_all(input).unwrap();
    h.sum()
}

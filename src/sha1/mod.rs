//! Module sha1 implements the SHA-1 hash algorithm as defined in RFC 3174.
//!
//! SHA-1 is cryptographically broken and should not be used for secure
//! applications.
mod block;

mod generic;
use bytes::BufMut;
use generic::*;

#[cfg(test)]
mod tests;

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
const INIT4: u32 = 0xC3D2E1F0;

const MAGIC: &[u8] = b"sha\x01";
const MARSHALED_SIZE: usize = MAGIC.len() + 5 * 4 + CHUNK + 8;

// digest represents the partial evaluation of a checksum.
#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    x: [u8; CHUNK],
    nx: usize,
    len: u64,
}

impl Sha1 {
    pub const SIZE: usize = 20;
    pub const BLOCK_SIZE: usize = 64;

    fn append_binary(&self, b: &mut Vec<u8>) {
        b.put_slice(MAGIC);
        b.put_u32(self.h[0]);
        b.put_u32(self.h[1]);
        b.put_u32(self.h[2]);
        b.put_u32(self.h[3]);
        b.put_u32(self.h[4]);
        b.put_slice(&self.x[..self.nx]);
        b.put_bytes(0, CHUNK - self.nx);
        b.put_u64(self.len);
    }

    fn check_sum(&mut self) -> [u8; Sha1::SIZE] {
        let len = self.len;

        // Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
        let mut tmp = [0u8; 64 + 8];
        tmp[0] = 0x80;

        let t = if len % 64 < 56 {
            56 - len % 64
        } else {
            64 + 56 - len % 64
        };

        // Length in bits.
        let len_bits = len << 3;
        let padlen = &mut tmp[..t as usize + 8];
        padlen[t as usize..].copy_from_slice(&len_bits.to_be_bytes());

        self.write_all(padlen).unwrap();

        if self.nx != 0 {
            panic!("d.nx != 0");
        }

        let mut digest = [0u8; Sha1::SIZE];
        {
            let mut digest = &mut digest as &mut [u8];
            digest.put_u32(self.h[0]);
            digest.put_u32(self.h[1]);
            digest.put_u32(self.h[2]);
            digest.put_u32(self.h[3]);
            digest.put_u32(self.h[4]);
        }

        digest
    }

    /// computes the same result of [Self::sum] but in constant time.
    pub fn constant_time_sum(&self, input: &[u8]) -> Vec<u8> {
        let mut d0 = self.clone();
        let hash = d0.const_sum();
        let mut result = Vec::from(input);
        result.extend_from_slice(&hash);
        result
    }

    fn const_sum(&mut self) -> [u8; Sha1::SIZE] {
        let mut length = [0u8; 8];
        let l = self.len << 3;
        (0..8).for_each(|i| {
            length[i] = (l >> (56 - 8 * i)) as u8;
        });

        let nx = self.nx as u8;
        let t = nx.wrapping_sub(56);
        let mask1b = ((t as i8) >> 7) as u8;

        let mut separator = 0x80u8;
        for i in 0..CHUNK {
            let mask = (((i as u8).wrapping_sub(nx) as i8) >> 7) as u8;

            self.x[i] = (!mask & separator) | (mask & self.x[i]);
            separator &= mask;

            if i >= 56 {
                self.x[i] |= mask1b & length[i - 56];
            }
        }

        {
            let x = self.x;
            block(self, &x);
        }

        let mut digest = [0u8; Sha1::SIZE];
        for (i, &s) in self.h.iter().enumerate() {
            digest[i * 4] = mask1b & (s >> 24) as u8;
            digest[i * 4 + 1] = mask1b & (s >> 16) as u8;
            digest[i * 4 + 2] = mask1b & (s >> 8) as u8;
            digest[i * 4 + 3] = mask1b & s as u8;
        }

        for i in 0..CHUNK {
            if i < 56 {
                self.x[i] = separator;
                separator = 0;
            } else {
                self.x[i] = length[i - 56];
            }
        }

        {
            let x = self.x;
            block(self, &x);
        }
        for (i, &s) in self.h.iter().enumerate() {
            digest[i * 4] |= !mask1b & (s >> 24) as u8;
            digest[i * 4 + 1] |= !mask1b & (s >> 16) as u8;
            digest[i * 4 + 2] |= !mask1b & (s >> 8) as u8;
            digest[i * 4 + 3] |= !mask1b & s as u8;
        }

        digest
    }
}

impl Write for Sha1 {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        let nn = p.len();
        self.len += nn as u64;
        let mut p = p;

        if self.nx > 0 {
            let n = std::cmp::min(CHUNK - self.nx, p.len());
            self.x[self.nx..self.nx + n].copy_from_slice(&p[..n]);
            self.nx += n;
            if self.nx == CHUNK {
                {
                    let x = self.x;
                    block(self, &x);
                }
                self.nx = 0;
            }
            p = &p[n..];
        }

        if p.len() >= CHUNK {
            let n = p.len() & !(CHUNK - 1);
            block(self, &p[..n]);
            p = &p[n..];
        }

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

impl HashUser for Sha1 {
    fn reset(&mut self) {
        self.h[0] = INIT0;
        self.h[1] = INIT1;
        self.h[2] = INIT2;
        self.h[3] = INIT3;
        self.h[4] = INIT4;
        self.nx = 0;
        self.len = 0;
    }

    fn size(&self) -> usize {
        Sha1::SIZE
    }

    fn block_size(&self) -> usize {
        Sha1::BLOCK_SIZE
    }
}

impl Hash<20> for Sha1 {
    fn sum(&mut self) -> [u8; 20] {
        let mut d0 = self.clone();
        d0.check_sum()
    }
}

impl Marshalable for Sha1 {
    fn marshal_binary(&self) -> CryptoResult<Vec<u8>> {
        let mut b = Vec::with_capacity(MARSHALED_SIZE);
        self.append_binary(&mut b);
        Ok(b)
    }
    fn unmarshal_binary(&mut self, b: &[u8]) -> CryptoResult<()> {
        if b.len() < MAGIC.len() || &b[..MAGIC.len()] != MAGIC {
            return Err(CryptoError::InvalidHashIdentifier);
        }
        if b.len() != MARSHALED_SIZE {
            return Err(CryptoError::InvalidHashState);
        }

        let mut offset = MAGIC.len();

        self.h[0] = u32::from_be_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]]);
        offset += 4;
        self.h[1] = u32::from_be_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]]);
        offset += 4;
        self.h[2] = u32::from_be_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]]);
        offset += 4;
        self.h[3] = u32::from_be_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]]);
        offset += 4;
        self.h[4] = u32::from_be_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]]);
        offset += 4;

        self.x.copy_from_slice(&b[offset..offset + CHUNK]);
        offset += CHUNK;

        self.len = u64::from_be_bytes([
            b[offset],
            b[offset + 1],
            b[offset + 2],
            b[offset + 3],
            b[offset + 4],
            b[offset + 5],
            b[offset + 6],
            b[offset + 7],
        ]);

        self.nx = (self.len % CHUNK as u64) as usize;
        Ok(())
    }
}

pub fn sum(data: &[u8]) -> [u8; Sha1::SIZE] {
    let mut d = new();
    d.write_all(data).unwrap();
    d.check_sum()
}

pub fn new() -> Sha1 {
    let mut d = Sha1 {
        h: [0; 5],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
    };
    d.reset();
    d
}

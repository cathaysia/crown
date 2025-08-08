mod md5block;
// mod arch;
// use arch::*;

mod md5_generic;
use std::io::Write;

use md5_generic::*;

use crate::{
    error::{CryptoError, CryptoResult},
    hash::Hash,
    hmac::Marshalable,
};

#[cfg(test)]
mod tests;

pub const SIZE: usize = 16;
pub const BLOCK_SIZE: usize = 64;

const MAX_ASM_ITERS: usize = 1024;
const MAX_ASM_SIZE: usize = BLOCK_SIZE * MAX_ASM_ITERS;

const INIT0: u32 = 0x67452301;
const INIT1: u32 = 0xEFCDAB89;
const INIT2: u32 = 0x98BADCFE;
const INIT3: u32 = 0x10325476;

const MAGIC: &[u8] = b"md5\x01";
const MARSHALED_SIZE: usize = MAGIC.len() + 4 * 4 + BLOCK_SIZE + 8;

#[derive(Debug, Clone)]
pub struct Md5 {
    s: [u32; 4],
    x: [u8; BLOCK_SIZE],
    nx: usize,
    len: u64,
}

impl Default for Md5 {
    fn default() -> Self {
        Md5::new()
    }
}

impl Md5 {
    pub fn new() -> Self {
        let mut d = Md5 {
            s: [0; 4],
            x: [0; BLOCK_SIZE],
            nx: 0,
            len: 0,
        };
        d.reset();
        d
    }

    pub fn append_binary(&self, mut b: Vec<u8>) -> CryptoResult<Vec<u8>> {
        b.extend_from_slice(MAGIC);
        be_append_u32(&mut b, self.s[0]);
        be_append_u32(&mut b, self.s[1]);
        be_append_u32(&mut b, self.s[2]);
        be_append_u32(&mut b, self.s[3]);
        b.extend_from_slice(&self.x[..self.nx]);
        b.extend_from_slice(&vec![0; self.x.len() - self.nx]);
        be_append_u64(&mut b, self.len);
        Ok(b)
    }

    pub fn check_sum(&mut self) -> [u8; SIZE] {
        let mut tmp = [0u8; 1 + 63 + 8];
        tmp[0] = 0x80;

        let pad = (55u64.wrapping_sub(self.len)) % 64;
        le_put_u64(&mut tmp[1 + pad as usize..], self.len << 3);
        self.write_all(&tmp[..1 + pad as usize + 8]).unwrap();

        if self.nx != 0 {
            panic!("d.nx != 0");
        }

        let mut digest = [0u8; SIZE];
        le_put_u32(&mut digest[0..], self.s[0]);
        le_put_u32(&mut digest[4..], self.s[1]);
        le_put_u32(&mut digest[8..], self.s[2]);
        le_put_u32(&mut digest[12..], self.s[3]);
        digest
    }
}

impl Write for Md5 {
    fn write(&mut self, p: &[u8]) -> std::io::Result<usize> {
        let nn = p.len();
        self.len += nn as u64;
        let mut p = p;

        if self.nx > 0 {
            let n = (BLOCK_SIZE - self.nx).min(p.len());
            self.x[self.nx..self.nx + n].copy_from_slice(&p[..n]);
            self.nx += n;
            if self.nx == BLOCK_SIZE {
                let x_copy = self.x;
                if HAVE_ASM {
                    block(self, &x_copy);
                } else {
                    block_generic(self, &x_copy);
                }
                self.nx = 0;
            }
            p = &p[n..];
        }

        if p.len() >= BLOCK_SIZE {
            let n = p.len() & !(BLOCK_SIZE - 1);
            if HAVE_ASM {
                let mut remaining = n;
                let mut offset = 0;
                while remaining > MAX_ASM_SIZE {
                    block(self, &p[offset..offset + MAX_ASM_SIZE]);
                    offset += MAX_ASM_SIZE;
                    remaining -= MAX_ASM_SIZE;
                }
                block(self, &p[offset..offset + remaining]);
            } else {
                block_generic(self, &p[..n]);
            }
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
        self.append_binary(Vec::with_capacity(MARSHALED_SIZE))
    }

    fn unmarshal_binary(&mut self, b: &[u8]) -> CryptoResult<()> {
        if b.len() < MAGIC.len() || &b[..MAGIC.len()] != MAGIC {
            return Err(CryptoError::InvalidHashIdentifier);
        }
        if b.len() != MARSHALED_SIZE {
            return Err(CryptoError::InvalidHashState);
        }

        let mut b = &b[MAGIC.len()..];
        let (remaining, s0) = consume_u32(b);
        b = remaining;
        let (remaining, s1) = consume_u32(b);
        b = remaining;
        let (remaining, s2) = consume_u32(b);
        b = remaining;
        let (remaining, s3) = consume_u32(b);
        b = remaining;

        self.s[0] = s0;
        self.s[1] = s1;
        self.s[2] = s2;
        self.s[3] = s3;

        let copied = b.len().min(self.x.len());
        self.x[..copied].copy_from_slice(&b[..copied]);
        b = &b[copied..];

        let (_, len) = consume_u64(b);
        self.len = len;
        self.nx = (self.len % BLOCK_SIZE as u64) as usize;

        Ok(())
    }
}

impl Hash for Md5 {
    fn reset(&mut self) {
        self.s[0] = INIT0;
        self.s[1] = INIT1;
        self.s[2] = INIT2;
        self.s[3] = INIT3;
        self.nx = 0;
        self.len = 0;
    }

    fn size(&self) -> usize {
        SIZE
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn sum(&mut self, input: &[u8]) -> Vec<u8> {
        let mut d0 = self.clone();
        let hash = d0.check_sum();
        let mut result = Vec::with_capacity(input.len() + SIZE);
        result.extend_from_slice(input);
        result.extend_from_slice(&hash);
        result
    }
}

fn be_append_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_be_bytes());
}

fn be_append_u64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_be_bytes());
}

fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be_u64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn le_put_u32(b: &mut [u8], v: u32) {
    let bytes = v.to_le_bytes();
    b[0..4].copy_from_slice(&bytes);
}

fn le_put_u64(b: &mut [u8], v: u64) {
    let bytes = v.to_le_bytes();
    b[0..8].copy_from_slice(&bytes);
}

fn consume_u32(b: &[u8]) -> (&[u8], u32) {
    (&b[4..], be_u32(&b[0..4]))
}

fn consume_u64(b: &[u8]) -> (&[u8], u64) {
    (&b[8..], be_u64(&b[0..8]))
}

fn block_generic(d: &mut Md5, p: &[u8]) {
    md5block::block_generic(d, p);
}

pub fn sum(data: &[u8]) -> [u8; SIZE] {
    let mut d = Md5::new();
    d.write_all(data).unwrap();
    d.check_sum()
}

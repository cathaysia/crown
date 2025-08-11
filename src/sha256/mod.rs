//! Module sha256 implements the SHA224 and SHA256 hash algorithms as defined
//! in FIPS 180-4.

use std::io::Write;

use crate::{
    error::{CryptoError, CryptoResult},
    hash::Hash,
    hmac::Marshalable,
};

#[cfg(test)]
mod tests;

mod generic;

// The size of a SHA-256 checksum in bytes.
const SIZE: usize = 32;

// The size of a SHA-224 checksum in bytes.
const SIZE224: usize = 28;

// The block size of SHA-256 and SHA-224 in bytes.
const BLOCK_SIZE: usize = 64;

// The maximum number of bytes that can be passed to block(). The limit exists
// because implementations that rely on assembly routines are not preemptible.
const MAX_ASM_ITERS: usize = 1024;
const MAX_ASM_SIZE: usize = BLOCK_SIZE * MAX_ASM_ITERS; // 64KiB

const CHUNK: usize = 64;
const INIT0: u32 = 0x6A09E667;
const INIT1: u32 = 0xBB67AE85;
const INIT2: u32 = 0x3C6EF372;
const INIT3: u32 = 0xA54FF53A;
const INIT4: u32 = 0x510E527F;
const INIT5: u32 = 0x9B05688C;
const INIT6: u32 = 0x1F83D9AB;
const INIT7: u32 = 0x5BE0CD19;
const INIT0_224: u32 = 0xC1059ED8;
const INIT1_224: u32 = 0x367CD507;
const INIT2_224: u32 = 0x3070DD17;
const INIT3_224: u32 = 0xF70E5939;
const INIT4_224: u32 = 0xFFC00B31;
const INIT5_224: u32 = 0x68581511;
const INIT6_224: u32 = 0x64F98FA7;
const INIT7_224: u32 = 0xBEFA4FA4;

// Digest is a SHA-224 or SHA-256 hash implementation.
#[derive(Clone)]
pub struct Sha256 {
    h: [u32; 8],
    x: [u8; CHUNK],
    nx: usize,
    len: u64,
    is224: bool, // mark if this digest is SHA-224
}

const MAGIC224: &[u8] = b"sha\x02";
const MAGIC256: &[u8] = b"sha\x03";
const MARSHALED_SIZE: usize = 4 + 8 * 4 + CHUNK + 8;

impl Sha256 {
    fn append_binary(&self, b: &mut Vec<u8>) {
        if self.is224 {
            b.extend_from_slice(MAGIC224);
        } else {
            b.extend_from_slice(MAGIC256);
        }
        b.extend_from_slice(&self.h[0].to_be_bytes());
        b.extend_from_slice(&self.h[1].to_be_bytes());
        b.extend_from_slice(&self.h[2].to_be_bytes());
        b.extend_from_slice(&self.h[3].to_be_bytes());
        b.extend_from_slice(&self.h[4].to_be_bytes());
        b.extend_from_slice(&self.h[5].to_be_bytes());
        b.extend_from_slice(&self.h[6].to_be_bytes());
        b.extend_from_slice(&self.h[7].to_be_bytes());
        b.extend_from_slice(&self.x[..self.nx]);
        b.extend_from_slice(&vec![0; CHUNK - self.nx]);
        b.extend_from_slice(&self.len.to_be_bytes());
    }

    fn check_sum(&mut self) -> [u8; SIZE] {
        let len = self.len;
        // Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
        let mut tmp = [0u8; 64 + 8]; // padding + length buffer
        tmp[0] = 0x80;
        let t = if len % 64 < 56 {
            56 - len % 64
        } else {
            64 + 56 - len % 64
        };

        // Length in bits.
        let len_bits = len << 3;
        let padlen = &mut tmp[..t as usize + 8];
        padlen[t as usize..t as usize + 8].copy_from_slice(&len_bits.to_be_bytes());
        self.write_all(padlen).unwrap();

        if self.nx != 0 {
            panic!("nx != 0");
        }

        let mut digest = [0u8; SIZE];
        digest[0..4].copy_from_slice(&self.h[0].to_be_bytes());
        digest[4..8].copy_from_slice(&self.h[1].to_be_bytes());
        digest[8..12].copy_from_slice(&self.h[2].to_be_bytes());
        digest[12..16].copy_from_slice(&self.h[3].to_be_bytes());
        digest[16..20].copy_from_slice(&self.h[4].to_be_bytes());
        digest[20..24].copy_from_slice(&self.h[5].to_be_bytes());
        digest[24..28].copy_from_slice(&self.h[6].to_be_bytes());
        if !self.is224 {
            digest[28..32].copy_from_slice(&self.h[7].to_be_bytes());
        }

        digest
    }
}

impl Marshalable for Sha256 {
    fn marshal_binary(&self) -> CryptoResult<Vec<u8>> {
        let mut b = Vec::with_capacity(MARSHALED_SIZE);
        self.append_binary(&mut b);
        Ok(b)
    }

    fn unmarshal_binary(&mut self, b: &[u8]) -> CryptoResult<()> {
        if b.len() < MAGIC224.len()
            || (self.is224 && &b[..MAGIC224.len()] != MAGIC224)
            || (!self.is224 && &b[..MAGIC256.len()] != MAGIC256)
        {
            return Err(CryptoError::InvalidHashIdentifier);
        }
        if b.len() != MARSHALED_SIZE {
            return Err(CryptoError::InvalidHashState);
        }

        let mut offset = MAGIC224.len();
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
        self.h[5] = u32::from_be_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]]);
        offset += 4;
        self.h[6] = u32::from_be_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]]);
        offset += 4;
        self.h[7] = u32::from_be_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]]);
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

impl Write for Sha256 {
    fn write(&mut self, mut p: &[u8]) -> std::io::Result<usize> {
        let nn = p.len();
        self.len += nn as u64;

        if self.nx > 0 {
            let n = std::cmp::min(CHUNK - self.nx, p.len());
            self.x[self.nx..self.nx + n].copy_from_slice(&p[..n]);
            self.nx += n;
            if self.nx == CHUNK {
                let x_copy = self.x;
                block(self, &x_copy);
                self.nx = 0;
            }
            p = &p[n..];
        }

        if p.len() >= CHUNK {
            let mut n = p.len() & !(CHUNK - 1);
            while n > MAX_ASM_SIZE {
                block(self, &p[..MAX_ASM_SIZE]);
                p = &p[MAX_ASM_SIZE..];
                n -= MAX_ASM_SIZE;
            }
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

impl Hash for Sha256 {
    fn sum(&mut self, input: &[u8]) -> Vec<u8> {
        // Make a copy of self so that caller can keep writing and summing.
        let mut d0 = *self;
        let hash = d0.check_sum();
        let mut result = Vec::from(input);
        if d0.is224 {
            result.extend_from_slice(&hash[..SIZE224]);
        } else {
            result.extend_from_slice(&hash);
        }
        result
    }

    fn size(&self) -> usize {
        if !self.is224 {
            SIZE
        } else {
            SIZE224
        }
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn reset(&mut self) {
        if !self.is224 {
            self.h[0] = INIT0;
            self.h[1] = INIT1;
            self.h[2] = INIT2;
            self.h[3] = INIT3;
            self.h[4] = INIT4;
            self.h[5] = INIT5;
            self.h[6] = INIT6;
            self.h[7] = INIT7;
        } else {
            self.h[0] = INIT0_224;
            self.h[1] = INIT1_224;
            self.h[2] = INIT2_224;
            self.h[3] = INIT3_224;
            self.h[4] = INIT4_224;
            self.h[5] = INIT5_224;
            self.h[6] = INIT6_224;
            self.h[7] = INIT7_224;
        }
        self.nx = 0;
        self.len = 0;
    }
}

impl Copy for Sha256 {}

// New returns a new Digest computing the SHA-256 hash.
pub fn new() -> Sha256 {
    let mut d = Sha256 {
        h: [0; 8],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
        is224: false,
    };
    d.reset();
    d
}

// New224 returns a new Digest computing the SHA-224 hash.
pub fn new224() -> Sha256 {
    let mut d = Sha256 {
        h: [0; 8],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
        is224: true,
    };
    d.reset();
    d
}

fn block(d: &mut Sha256, p: &[u8]) {
    generic::block_generic(d, p);
}

pub fn sum256(data: &[u8]) -> [u8; SIZE] {
    let mut h = new();
    h.write_all(data).unwrap();

    let sum = h.sum(&[]);

    sum.try_into().unwrap()
}

pub fn sum224(data: &[u8]) -> [u8; SIZE224] {
    let mut h = new224();
    h.write_all(data).unwrap();

    let sum = h.sum(&[]);

    sum.try_into().unwrap()
}

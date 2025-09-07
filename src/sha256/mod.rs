//! Module sha256 implements the SHA224 and SHA256 hash algorithms as defined
//! in FIPS 180-4.
//!
//! [SHA-256](crate::sha256) and [SHA-512](crate::sha512) belongs to the
//! [SHA-2](https://en.wikipedia.org/wiki/SHA-2) family of hash functions.

use bytes::BufMut;

use crate::core::CoreWrite;
use crate::error::CryptoError;
use crate::{
    error::CryptoResult,
    hash::{Hash, HashUser},
};

#[cfg(test)]
mod tests;

#[cfg(feature = "cuda")]
pub mod cuda;
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

/// [Sha256] is a SHA-224 or SHA-256 hash implementation.
#[derive(Clone)]
pub struct Sha256<const N: usize, const IS_224: bool> {
    h: [u32; 8],
    x: [u8; CHUNK],
    nx: usize,
    len: u64,
}

const MAGIC224: &[u8] = b"sha\x02";
const MAGIC256: &[u8] = b"sha\x03";
const MARSHALED_SIZE: usize = 4 + 8 * 4 + CHUNK + 8;

impl<const N: usize, const IS_224: bool> Sha256<N, IS_224> {
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
        {
            let mut digest = &mut digest as &mut [u8];
            digest.put_u32(self.h[0]);
            digest.put_u32(self.h[1]);
            digest.put_u32(self.h[2]);
            digest.put_u32(self.h[3]);
            digest.put_u32(self.h[4]);
            digest.put_u32(self.h[5]);
            digest.put_u32(self.h[6]);
            if !IS_224 {
                digest.put_u32(self.h[7]);
            }
        }

        digest
    }
}

impl<const N: usize, const IS_224: bool> crate::hmac::Marshalable for Sha256<N, IS_224> {
    fn marshal_size(&self) -> usize {
        MARSHALED_SIZE
    }

    fn marshal_into(&self, mut out: &mut [u8]) -> CryptoResult<usize> {
        let len = out.len();
        if len < MARSHALED_SIZE {
            return Err(CryptoError::BufferTooSmall);
        }

        if IS_224 {
            out.put_slice(MAGIC224);
        } else {
            out.put_slice(MAGIC256);
        }
        out.put_u32(self.h[0]);
        out.put_u32(self.h[1]);
        out.put_u32(self.h[2]);
        out.put_u32(self.h[3]);
        out.put_u32(self.h[4]);
        out.put_u32(self.h[5]);
        out.put_u32(self.h[6]);
        out.put_u32(self.h[7]);
        out.put_slice(&self.x[..self.nx]);
        out.put_bytes(0, CHUNK - self.nx);
        out.put_slice(&self.len.to_be_bytes());
        Ok(len - out.len())
    }

    fn unmarshal_binary(&mut self, b: &[u8]) -> CryptoResult<()> {
        use crate::error::CryptoError;
        use bytes::Buf;

        if b.len() < MAGIC224.len()
            || (IS_224 && &b[..MAGIC224.len()] != MAGIC224)
            || (!IS_224 && &b[..MAGIC256.len()] != MAGIC256)
        {
            return Err(CryptoError::InvalidHashIdentifier);
        }
        if b.len() != MARSHALED_SIZE {
            return Err(CryptoError::InvalidHashState);
        }

        {
            let mut b = &b[MAGIC224.len()..];
            self.h[0] = b.get_u32();
            self.h[1] = b.get_u32();
            self.h[2] = b.get_u32();
            self.h[3] = b.get_u32();
            self.h[4] = b.get_u32();
            self.h[5] = b.get_u32();
            self.h[6] = b.get_u32();
            self.h[7] = b.get_u32();
            b.copy_to_slice(&mut self.x);
            self.len = b.get_u64();
        }

        self.nx = (self.len % CHUNK as u64) as usize;
        Ok(())
    }
}

impl<const N: usize, const IS_224: bool> CoreWrite for Sha256<N, IS_224> {
    fn write(&mut self, mut p: &[u8]) -> CryptoResult<usize> {
        let nn = p.len();
        self.len += nn as u64;

        if self.nx > 0 {
            let n = core::cmp::min(CHUNK - self.nx, p.len());
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

    fn flush(&mut self) -> CryptoResult<()> {
        Ok(())
    }
}

impl<const N: usize, const IS_224: bool> HashUser for Sha256<N, IS_224> {
    fn size(&self) -> usize {
        if !IS_224 {
            SIZE
        } else {
            SIZE224
        }
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn reset(&mut self) {
        if !IS_224 {
            self.h = [INIT0, INIT1, INIT2, INIT3, INIT4, INIT5, INIT6, INIT7];
        } else {
            self.h = [
                INIT0_224, INIT1_224, INIT2_224, INIT3_224, INIT4_224, INIT5_224, INIT6_224,
                INIT7_224,
            ];
        }
        self.nx = 0;
        self.len = 0;
    }
}

impl<const N: usize, const IS_224: bool> Hash<N> for Sha256<N, IS_224> {
    fn sum(&mut self) -> [u8; N] {
        // Make a copy of self so that caller can keep writing and summing.
        let mut d0 = self.clone();
        let hash = d0.check_sum();

        let mut ret = [0u8; N];
        ret.copy_from_slice(&hash[..N]);
        ret
    }
}

fn block<const N: usize, const IS_224: bool>(d: &mut Sha256<N, IS_224>, p: &[u8]) {
    generic::block_generic(d, p);
}

/// Create a new [Hash] computing the SHA-256 checksum.
///
/// The Hash also implements [Marshalable](crate::hmac::Marshalable)
/// to marshal and unmarshal the internal state of the hash.
pub fn new256() -> Sha256<32, false> {
    let mut d = Sha256 {
        h: [0; 8],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
    };
    d.reset();
    d
}

/// Create a new [Hash] computing the SHA-224 checksum.
///
/// The Hash also implements [Marshalable](crate::hmac::Marshalable)
/// to marshal and unmarshal the internal state of the hash.
pub fn new224() -> Sha256<28, true> {
    let mut d = Sha256 {
        h: [0; 8],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
    };
    d.reset();
    d
}

/// Compute the SHA-256 checksum of the input.
pub fn sum256(data: &[u8]) -> [u8; SIZE] {
    let mut h = new256();
    h.write_all(data).unwrap();

    h.sum()
}

/// Compute the SHA-224 checksum of the input.
pub fn sum224(data: &[u8]) -> [u8; SIZE224] {
    let mut h = new224();
    h.write_all(data).unwrap();

    h.sum()
}

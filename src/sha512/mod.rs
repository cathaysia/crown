//! Package sha512 implements the SHA-384, SHA-512, SHA-512/224, and SHA-512/256
//! hash algorithms as defined in FIPS 180-4.

use std::io::Write;

use crate::{
    error::{CryptoError, CryptoResult},
    hash::{Hash, HashUser},
    hmac::Marshalable,
};

pub(crate) mod block;
pub(crate) mod noasm;

#[cfg(test)]
mod tests;

const CHUNK: usize = 128;

// Initial hash values for SHA-512
const INIT_512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

// Initial hash values for SHA-512/224
const INIT_224: [u64; 8] = [
    0x8c3d37c819544da2,
    0x73e1996689dcd4d6,
    0x1dfab7ae32ff9c82,
    0x679dd514582f9fcf,
    0x0f6d2b697bd44da8,
    0x77e36f7304c48942,
    0x3f9d85a86a1d36c8,
    0x1112e6ad91d692a1,
];

// Initial hash values for SHA-512/256
const INIT_256: [u64; 8] = [
    0x22312194fc2bf72c,
    0x9f555fa3c84c64c2,
    0x2393b86b6f53b151,
    0x963877195940eabd,
    0x96283ee2a88effe3,
    0xbe5e1e2553863992,
    0x2b0199fc2c85b8aa,
    0x0eb72ddc81c52ca2,
];

// Initial hash values for SHA-384
const INIT_384: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

// Magic constants for marshaling
const MAGIC_384: &[u8] = b"sha\x04";
const MAGIC_512_224: &[u8] = b"sha\x05";
const MAGIC_512_256: &[u8] = b"sha\x06";
const MAGIC_512: &[u8] = b"sha\x07";
const MARSHALED_SIZE: usize = 4 + 8 * 8 + CHUNK + 8;

/// SHA-384, SHA-512, SHA-512/224, or SHA-512/256 digest implementation
#[derive(Clone)]
pub struct Sha512<const N: usize> {
    h: [u64; 8],
    x: [u8; CHUNK],
    nx: usize,
    len: u64,
}

impl<const N: usize> Sha512<N> {
    pub const SIZE_512: usize = 64;
    pub const SIZE_224: usize = 28;
    pub const SIZE_256: usize = 32;
    pub const SIZE_384: usize = 48;
    pub const BLOCK_SIZE: usize = 128;

    /// Append the digest state to the provided buffer
    fn append_binary(&self, b: &mut Vec<u8>) {
        match N {
            Self::SIZE_384 => b.extend_from_slice(MAGIC_384),
            Self::SIZE_224 => b.extend_from_slice(MAGIC_512_224),
            Self::SIZE_256 => b.extend_from_slice(MAGIC_512_256),
            Self::SIZE_512 => b.extend_from_slice(MAGIC_512),
            _ => panic!("unknown size"),
        }

        // Append hash state (big-endian)
        for &h in &self.h {
            b.extend_from_slice(&h.to_be_bytes());
        }

        // Append buffer
        b.extend_from_slice(&self.x[..self.nx]);
        b.extend_from_slice(&vec![0u8; CHUNK - self.nx]);

        // Append length
        b.extend_from_slice(&self.len.to_be_bytes());
    }

    fn check_sum(&mut self) -> [u8; 64] {
        // Padding. Add a 1 bit and 0 bits until 112 bytes mod 128.
        let len = self.len;
        let mut tmp = [0u8; 128 + 16]; // padding + length buffer
        tmp[0] = 0x80;

        let t = if len % 128 < 112 {
            112 - len % 128
        } else {
            128 + 112 - len % 128
        };

        // Length in bits
        let len_bits = len << 3;
        let padlen = &mut tmp[..t as usize + 16];

        // Write length as big-endian u64 (upper 64 bits are zero)
        let len_bytes = len_bits.to_be_bytes();
        padlen[t as usize + 8..t as usize + 16].copy_from_slice(&len_bytes);

        self.write_all(padlen).unwrap();

        if self.nx != 0 {
            panic!("d.nx != 0");
        }

        let mut digest = [0u8; 64];
        for (i, &h) in self.h.iter().enumerate() {
            let bytes = h.to_be_bytes();
            digest[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }

        digest
    }
}

impl<const N: usize> Marshalable for Sha512<N> {
    /// Marshal the digest state to binary format
    fn marshal_binary(&self) -> CryptoResult<Vec<u8>> {
        let mut result = Vec::with_capacity(MARSHALED_SIZE);
        self.append_binary(&mut result);
        Ok(result)
    }
    /// Unmarshal digest state from binary format
    fn unmarshal_binary(&mut self, b: &[u8]) -> CryptoResult<()> {
        if b.len() < 4 {
            return Err(CryptoError::InvalidHashIdentifier);
        }

        let valid = match N {
            Self::SIZE_384 => b.starts_with(MAGIC_384),
            Self::SIZE_224 => b.starts_with(MAGIC_512_224),
            Self::SIZE_256 => b.starts_with(MAGIC_512_256),
            Self::SIZE_512 => b.starts_with(MAGIC_512),
            _ => false,
        };

        if !valid {
            return Err(CryptoError::InvalidHashIdentifier);
        }

        if b.len() != MARSHALED_SIZE {
            return Err(CryptoError::InvalidHashState);
        }

        let mut offset = 4;

        // Read hash state
        for i in 0..8 {
            self.h[i] = u64::from_be_bytes([
                b[offset],
                b[offset + 1],
                b[offset + 2],
                b[offset + 3],
                b[offset + 4],
                b[offset + 5],
                b[offset + 6],
                b[offset + 7],
            ]);
            offset += 8;
        }

        // Read buffer
        self.x.copy_from_slice(&b[offset..offset + CHUNK]);
        offset += CHUNK;

        // Read length
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

impl<const N: usize> Write for Sha512<N> {
    /// Write data to the digest
    fn write(&mut self, p: &[u8]) -> std::io::Result<usize> {
        let nn = p.len();
        self.len += nn as u64;
        let mut p = p;

        if self.nx > 0 {
            let n = std::cmp::min(CHUNK - self.nx, p.len());
            self.x[self.nx..self.nx + n].copy_from_slice(&p[..n]);
            self.nx += n;
            if self.nx == CHUNK {
                let x = unsafe {
                    let ptr = self.x.as_ptr();
                    std::slice::from_raw_parts(ptr, self.x.len())
                };
                self.block(x).unwrap();
                self.nx = 0;
            }
            p = &p[n..];
        }

        if p.len() >= CHUNK {
            let n = p.len() & !(CHUNK - 1);
            self.block(&p[..n]).unwrap();

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

impl<const N: usize> HashUser for Sha512<N> {
    /// Get the output size of this digest
    fn size(&self) -> usize {
        N
    }

    /// Get the block size
    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    /// Reset the digest to its initial state
    fn reset(&mut self) {
        match N {
            Self::SIZE_384 => self.h = INIT_384,
            Self::SIZE_224 => self.h = INIT_224,
            Self::SIZE_256 => self.h = INIT_256,
            Self::SIZE_512 => self.h = INIT_512,
            _ => panic!("unknown size"),
        }
        self.nx = 0;
        self.len = 0;
    }
}

impl<const N: usize> Hash<N> for Sha512<N> {
    /// Compute the final hash and append it to the input
    fn sum(&mut self) -> [u8; N] {
        // Make a copy so caller can keep writing and summing
        let mut d0 = self.clone();
        let hash = d0.check_sum();
        let mut result = Vec::with_capacity(N);
        result.extend_from_slice(&hash[..N]);
        result.try_into().unwrap()
    }
}

/// Create a new SHA-512 digest
pub fn new() -> Sha512<64> {
    let mut d = Sha512 {
        h: [0; 8],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
    };
    d.reset();
    d
}

/// Create a new SHA-512/224 digest
pub fn new_512_224() -> Sha512<28> {
    let mut d = Sha512 {
        h: [0; 8],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
    };
    d.reset();
    d
}

/// Create a new SHA-512/256 digest
pub fn new_512_256() -> Sha512<32> {
    let mut d = Sha512 {
        h: [0; 8],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
    };
    d.reset();
    d
}

/// Create a new SHA-384 digest
pub fn new384() -> Sha512<48> {
    let mut d = Sha512 {
        h: [0; 8],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
    };
    d.reset();
    d
}

pub fn sum512(input: &[u8]) -> [u8; 64] {
    let mut d = new();
    d.write_all(input).unwrap();
    d.sum()
}

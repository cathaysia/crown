mod generic;
mod noasm;

#[cfg(test)]
mod tests;

use crate::error::{CryptoError, CryptoResult};
use crate::hash::{Hash, HashUser};
use crate::hmac::Marshalable;
use noasm::hash_blocks;
use std::io::Write;

pub const BLOCK_SIZE: usize = 128;
pub const SIZE: usize = 64;
pub const SIZE384: usize = 48;
pub const SIZE256: usize = 32;

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

pub struct Blake2b<const N: usize> {
    h: [u64; 8],
    c: [u64; 2],
    block: [u8; BLOCK_SIZE],
    offset: usize,
    key: [u8; BLOCK_SIZE],
    key_len: usize,
}

const MAGIC: &[u8] = b"b2b";
const MARSHALED_SIZE: usize = MAGIC.len() + 8 * 8 + 2 * 8 + 1 + BLOCK_SIZE + 1;

impl<const N: usize> Blake2b<N> {
    fn new(key: &[u8]) -> CryptoResult<Blake2b<N>> {
        if !(1..=SIZE).contains(&N) {
            return Err(CryptoError::InvalidParameter(
                "invalid hash size".to_string(),
            ));
        }
        if key.len() > SIZE {
            return Err(CryptoError::InvalidKeySize(key.len()));
        }

        let mut d = Blake2b {
            h: [0u64; 8],
            c: [0u64; 2],
            block: [0u8; BLOCK_SIZE],
            offset: 0,
            key: [0u8; BLOCK_SIZE],
            key_len: key.len(),
        };

        d.key[..key.len()].copy_from_slice(key);
        d.reset();
        Ok(d)
    }
    fn finalize(&self, hash: &mut [u8; SIZE]) {
        let mut block = [0u8; BLOCK_SIZE];
        block[..self.offset].copy_from_slice(&self.block[..self.offset]);
        let remaining = (BLOCK_SIZE - self.offset) as u64;

        let mut c = self.c;
        if c[0] < remaining {
            c[1] = c[1].wrapping_sub(1);
        }
        c[0] = c[0].wrapping_sub(remaining);

        let mut h = self.h;
        hash_blocks(&mut h, &mut c, 0xFFFFFFFFFFFFFFFF, &block);

        for (i, &v) in h.iter().enumerate() {
            let bytes = v.to_le_bytes();
            let start = 8 * i;
            if start < hash.len() {
                let end = (start + 8).min(hash.len());
                hash[start..end].copy_from_slice(&bytes[..end - start]);
            }
        }
    }
}

impl<const N: usize> Marshalable for Blake2b<N> {
    fn marshal_binary(&self) -> CryptoResult<Vec<u8>> {
        if self.key_len != 0 {
            return Err(CryptoError::InvalidParameter(
                "cannot marshal MACs".to_string(),
            ));
        }

        let mut b = Vec::with_capacity(MARSHALED_SIZE);
        b.extend_from_slice(MAGIC);

        for &h in &self.h {
            b.extend_from_slice(&h.to_be_bytes());
        }
        b.extend_from_slice(&self.c[0].to_be_bytes());
        b.extend_from_slice(&self.c[1].to_be_bytes());
        b.push(N as u8);
        b.extend_from_slice(&self.block);
        b.push(self.offset as u8);

        Ok(b)
    }

    fn unmarshal_binary(&mut self, b: &[u8]) -> CryptoResult<()> {
        if b.len() < MAGIC.len() || &b[..MAGIC.len()] != MAGIC {
            return Err(CryptoError::InvalidHashIdentifier);
        }
        if b.len() != MARSHALED_SIZE {
            return Err(CryptoError::InvalidHashState);
        }

        let mut b = &b[MAGIC.len()..];

        for h in &mut self.h {
            *h = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            b = &b[8..];
        }

        self.c[0] = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        b = &b[8..];
        self.c[1] = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        b = &b[8..];

        b = &b[1..];

        self.block.copy_from_slice(&b[..BLOCK_SIZE]);
        b = &b[BLOCK_SIZE..];

        self.offset = b[0] as usize;

        Ok(())
    }
}

impl<const N: usize> HashUser for Blake2b<N> {
    fn reset(&mut self) {
        self.h = IV;
        self.h[0] ^= N as u64 | ((self.key_len as u64) << 8) | (1 << 16) | (1 << 24);
        self.offset = 0;
        self.c[0] = 0;
        self.c[1] = 0;
        if self.key_len > 0 {
            self.block = self.key;
            self.offset = BLOCK_SIZE;
        }
    }

    fn size(&self) -> usize {
        N
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }
}

impl<const N: usize> Write for Blake2b<N> {
    fn write(&mut self, p: &[u8]) -> std::io::Result<usize> {
        let n = p.len();
        let mut p = p;

        if self.offset > 0 {
            let remaining = BLOCK_SIZE - self.offset;
            if n <= remaining {
                let len = p.len();
                self.block[self.offset..self.offset + len].copy_from_slice(p);
                self.offset += len;
                return Ok(n);
            }
            self.block[self.offset..].copy_from_slice(&p[..remaining]);
            hash_blocks(&mut self.h, &mut self.c, 0, &self.block);
            self.offset = 0;
            p = &p[remaining..];
        }

        if p.len() > BLOCK_SIZE {
            let mut nn = p.len() & !(BLOCK_SIZE - 1);
            if p.len() == nn {
                nn -= BLOCK_SIZE;
            }
            hash_blocks(&mut self.h, &mut self.c, 0, &p[..nn]);
            p = &p[nn..];
        }

        if !p.is_empty() {
            let len = p.len();
            self.block[..len].copy_from_slice(p);
            self.offset += len;
        }

        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<const N: usize> Hash<N> for Blake2b<N> {
    fn sum(&mut self) -> [u8; N] {
        let mut hash = [0u8; SIZE];
        self.finalize(&mut hash);

        let mut ret = [0u8; N];
        ret.copy_from_slice(&hash[..N]);
        ret
    }
}

/// Compute the blake2b checksum of the input.
pub fn sum_var(sum: &mut [u8; SIZE], hash_size: usize, data: &[u8]) {
    let mut h = IV;
    h[0] ^= hash_size as u64 | (1 << 16) | (1 << 24);
    let mut c = [0u64; 2];

    let mut data = data;
    if data.len() > BLOCK_SIZE {
        let mut n = data.len() & !(BLOCK_SIZE - 1);
        if data.len() == n {
            n -= BLOCK_SIZE;
        }
        hash_blocks(&mut h, &mut c, 0, &data[..n]);
        data = &data[n..];
    }

    let mut block = [0u8; BLOCK_SIZE];
    let offset = {
        let len = data.len().min(BLOCK_SIZE);
        block[..len].copy_from_slice(&data[..len]);
        len
    };

    let remaining = (BLOCK_SIZE - offset) as u64;
    if c[0] < remaining {
        c[1] = c[1].wrapping_sub(1);
    }
    c[0] = c[0].wrapping_sub(remaining);

    hash_blocks(&mut h, &mut c, 0xFFFFFFFFFFFFFFFF, &block);

    for (i, &v) in h.iter().enumerate().take((hash_size + 7) / 8) {
        let bytes = v.to_le_bytes();
        let start = 8 * i;
        let end = (start + 8).min(sum.len());
        if start < sum.len() {
            sum[start..end].copy_from_slice(&bytes[..end - start]);
        }
    }
}

macro_rules! impl_new_for {
    ($name:ident, $len:expr, $x:literal) => {
        paste::paste! {
            #[doc =
                "Create a new [Hash] computing the " $x " checksum.\n\n"
                "The Hash also implements [Marshalable] to marshal and unmarshal the internal state of the hash."
            ]
            pub fn $name(key: &[u8]) -> CryptoResult<Blake2b<$len>> {
                Blake2b::new(key)
            }
        }
    };
}

impl_new_for!(new512, 64, "Blake2b");
impl_new_for!(new384, 48, "Blake2b");
impl_new_for!(new256, 32, "Blake2b");

macro_rules! impl_sum_for {
    ($name:ident, $fn:expr, $len:expr, $x:literal) => {
        paste::paste! {
            #[doc = "Compute the " $x " checksum of the input."]
            pub fn $name(data: &[u8]) -> [u8; $len] {
                let mut sum = [0u8; SIZE];
                sum_var(&mut sum, SIZE, data);

                let mut x = [0u8; $len];
                x.copy_from_slice(&sum[..$len]);
                x
            }
        }
    };
}

impl_sum_for!(sum512, new512, SIZE, "BLAKE2B-512");
impl_sum_for!(sum384, new384, SIZE384, "BLAKE2B-384");
impl_sum_for!(sum256, new256, SIZE256, "BLAKE2B-256");

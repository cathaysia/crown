use crate::{hash::HashVariable, utils::copy};

use super::*;

/// BLAKE2b hash implementation with variable-length output.
///
/// This struct provides a BLAKE2b hasher that can generate checksums of
/// variable length between 1 and 64 bytes. It implements the [HashVariable]
/// trait and supports keying for MAC (Message Authentication Code) generation.
pub struct Blake2bVariable {
    h: [u64; 8],
    c: [u64; 2],
    block: [u8; BLOCK_SIZE],
    offset: usize,
    hash_size: usize,
    key: [u8; BLOCK_SIZE],
    key_len: usize,
}

const MAGIC: &[u8] = b"b2b";
const MARSHALED_SIZE: usize = MAGIC.len() + 8 * 8 + 2 * 8 + 1 + BLOCK_SIZE + 1;
impl Blake2bVariable {
    /// Create a [HashVariable] hasher allow generate checksum between [0, 64].
    ///
    /// # Arguments
    ///
    /// * `hash_size` - The size of the hash output in bytes, must be between 1 and 64 inclusive
    /// * `key` - Optional key for keyed hashing, if provided must not exceed 64 bytes
    pub fn new(key: Option<&[u8]>, hash_size: usize) -> CryptoResult<Blake2bVariable> {
        let key = key.unwrap_or(&[]);

        if !(1..=SIZE).contains(&hash_size) {
            return Err(CryptoError::InvalidHashSize(hash_size));
        }
        if key.len() > SIZE {
            return Err(CryptoError::InvalidKeySize(key.len()));
        }

        let mut d = Blake2bVariable {
            h: [0u64; 8],
            c: [0u64; 2],
            block: [0u8; BLOCK_SIZE],
            offset: 0,
            key: [0u8; BLOCK_SIZE],
            key_len: key.len(),
            hash_size,
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

impl HashVariable for Blake2bVariable {
    fn sum(&mut self, sum: &mut [u8]) -> usize {
        let mut hash = [0u8; SIZE];
        self.finalize(&mut hash);

        copy(sum, &hash[..self.hash_size])
    }
}

#[cfg(feature = "alloc")]
impl crate::hmac::Marshalable for Blake2bVariable {
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
        b.push(self.hash_size as u8);
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

        self.hash_size = b[0] as usize;
        b = &b[1..];

        self.block.copy_from_slice(&b[..BLOCK_SIZE]);
        b = &b[BLOCK_SIZE..];

        self.offset = b[0] as usize;

        Ok(())
    }
}

impl HashUser for Blake2bVariable {
    fn reset(&mut self) {
        self.h = IV;
        self.h[0] ^= self.hash_size as u64 | ((self.key_len as u64) << 8) | (1 << 16) | (1 << 24);
        self.offset = 0;
        self.c[0] = 0;
        self.c[1] = 0;
        if self.key_len > 0 {
            self.block = self.key;
            self.offset = BLOCK_SIZE;
        }
    }

    fn size(&self) -> usize {
        self.hash_size
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }
}

impl CoreWrite for Blake2bVariable {
    fn write(&mut self, p: &[u8]) -> CryptoResult<usize> {
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

    fn flush(&mut self) -> CryptoResult<()> {
        Ok(())
    }
}

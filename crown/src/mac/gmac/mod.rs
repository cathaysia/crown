//! GMAC implementation according to NIST SP 800-38D.
//!
//! GMAC is the GCM authentication transform restricted to message
//! authentication: the message plays the role of the additional
//! authenticated data (AAD), the plaintext is empty, and the tag is
//! `GHASH_H(A) ^ E(K, IV || 0^31 || 1)`.
//!
//! The IV is restricted to the 96-bit form, which is the only mode defined
//! for GMAC itself and covers every practical protocol use.
//!
//! Reference: <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf>

#[cfg(test)]
mod tests;

use crate::block::aes::ghash::GhashTable;
use crate::{block::BlockCipher, error::CryptoResult, utils::subtle::constant_time_eq};

const BLOCK: usize = 16;
const IV_SIZE: usize = 12;

/// GMAC structure computing an authentication tag of all data written to it.
pub struct Gmac<B: BlockCipher> {
    cipher: B,
    /// 96-bit IV; J0 is `IV || 0^31 || 1`.
    iv: [u8; IV_SIZE],
    /// GHASH accumulator (table-driven multiplier over H).
    ghash: GhashTable,
    /// Pending partial block.
    buf: [u8; BLOCK],
    /// Number of valid bytes in `buf`.
    pos: usize,
    /// Total authenticated bits so far.
    bits: u64,
    finalized: bool,
}

impl<B: BlockCipher> Gmac<B> {
    /// The size, in bytes, of the authentication tag.
    pub const TAG_SIZE: usize = BLOCK;

    /// Create a new GMAC instance over the given keyed cipher and 96-bit IV.
    pub fn new(cipher: B, iv: &[u8; IV_SIZE]) -> CryptoResult<Self> {
        if cipher.block_size() != BLOCK {
            return Err(crate::error::CryptoError::InvalidLength);
        }

        let mut h = [0u8; BLOCK];
        cipher.encrypt_block(&mut h);

        Ok(Gmac {
            cipher,
            iv: *iv,
            ghash: GhashTable::new(&h),
            buf: [0u8; BLOCK],
            pos: 0,
            bits: 0,
            finalized: false,
        })
    }

    /// Size returns the number of bytes Sum will return.
    pub const fn size() -> usize {
        BLOCK
    }

    /// The IV size in bytes (96 bits).
    pub const fn iv_size() -> usize {
        IV_SIZE
    }

    fn absorb_block(&mut self, block: &[u8; BLOCK]) {
        self.ghash.absorb_block(block);
    }

    /// Write adds more message data to the running authentication code.
    ///
    /// It must not be called after the first call of Sum or Verify.
    pub fn write(&mut self, mut p: &[u8]) {
        if self.finalized {
            panic!("gmac: write to MAC after Sum or Verify");
        }
        if p.is_empty() {
            return;
        }
        self.bits = self.bits.wrapping_add((p.len() as u64) * 8);

        if self.pos > 0 {
            let n = core::cmp::min(p.len(), BLOCK - self.pos);
            self.buf[self.pos..self.pos + n].copy_from_slice(&p[..n]);
            self.pos += n;
            p = &p[n..];
            if self.pos == BLOCK {
                let block = self.buf;
                self.absorb_block(&block);
                self.pos = 0;
            }
        }

        while p.len() >= BLOCK {
            let mut block = [0u8; BLOCK];
            block.copy_from_slice(&p[..BLOCK]);
            self.absorb_block(&block);
            p = &p[BLOCK..];
        }

        if !p.is_empty() {
            self.buf[..p.len()].copy_from_slice(p);
            self.pos = p.len();
        }
    }

    /// Sum computes the authenticator of all data written to the message
    /// authentication code. The MAC cannot be used afterwards.
    pub fn sum(&mut self) -> [u8; BLOCK] {
        if self.finalized {
            panic!("gmac: Sum called twice");
        }
        self.finalized = true;

        if self.pos > 0 {
            let mut block = self.buf;
            block[self.pos..].fill(0);
            self.absorb_block(&block);
        }

        // Length block: 64-bit bit length of A, then 64-bit bit length of the
        // (empty) ciphertext.
        let mut len_block = [0u8; BLOCK];
        len_block[..8].copy_from_slice(&self.bits.to_be_bytes());
        self.absorb_block(&len_block);

        // Tag = GHASH output ^ E(K, J0).
        let mut tag = [0u8; BLOCK];
        tag[..IV_SIZE].copy_from_slice(&self.iv);
        tag[BLOCK - 1] = 1;
        self.cipher.encrypt_block(&mut tag);
        let mut y = [0u8; BLOCK];
        self.ghash.sum_into(&mut y);
        for (t, y) in tag.iter_mut().zip(y.iter()) {
            *t ^= y;
        }
        tag
    }

    /// Verify returns whether the authenticator of all data written to the
    /// message authentication code matches the expected value, in constant
    /// time. The MAC cannot be used afterwards.
    pub fn verify(&mut self, expected: &[u8]) -> bool {
        let tag = self.sum();
        constant_time_eq(&tag, expected)
    }
}

/// Compute the GMAC of `msg` under the keyed `cipher` and 96-bit `iv`.
pub fn sum<B: BlockCipher>(cipher: B, iv: &[u8; IV_SIZE], msg: &[u8]) -> CryptoResult<[u8; 16]> {
    let mut mac = Gmac::new(cipher, iv)?;
    mac.write(msg);
    Ok(mac.sum())
}

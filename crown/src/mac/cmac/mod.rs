//! CMAC implementation according to NIST SP 800-38B (RFC 4493 for AES).
//!
//! CMAC is a CBC-MAC with security against variable-length messages: the last
//! block is masked with a derived subkey (`K1` for a complete block, `K2` for
//! a padded one) before the final encryption, which prevents length-extension
//! and truncation forgeries.
//!
//! The implementation is generic over any [`BlockCipher`]: use `Cmac<Aes, 16>`
//! style instantiation for 128-bit block ciphers and `Cmac<TripleDes, 8>` for
//! 64-bit block ciphers (the subkey doubling polynomial follows the block
//! size, `0x87` for 128 bits and `0x1b` for 64 bits).
//!
//! Reference: <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf>

#[cfg(test)]
mod tests;

use crate::{block::BlockCipher, error::CryptoResult, utils::subtle::constant_time_eq};

/// CMAC structure computing an authentication tag of all data written to it.
pub struct Cmac<T: BlockCipher, const BLOCK_SIZE: usize> {
    cipher: T,
    /// First subkey derived from encrypting the zero block.
    k1: [u8; BLOCK_SIZE],
    /// Second subkey, the doubling of `k1`.
    k2: [u8; BLOCK_SIZE],
    /// Running CBC-MAC value over all complete blocks except the last.
    mac: [u8; BLOCK_SIZE],
    /// Pending block; holds the last complete block or a partial one.
    buf: [u8; BLOCK_SIZE],
    /// Number of valid bytes in `buf`.
    pos: usize,
    finalized: bool,
}

impl<T: BlockCipher, const BLOCK_SIZE: usize> Cmac<T, BLOCK_SIZE> {
    /// The size, in bytes, of the authentication tag (the cipher block size).
    pub const fn tag_size() -> usize {
        BLOCK_SIZE
    }

    /// Size returns the number of bytes Sum will return.
    pub const fn size() -> usize {
        BLOCK_SIZE
    }

    /// The cipher block size in bytes.
    pub const fn block_size() -> usize {
        BLOCK_SIZE
    }

    /// Create a new CMAC instance over the given keyed cipher.
    pub fn new(cipher: T) -> CryptoResult<Self> {
        if cipher.block_size() != BLOCK_SIZE {
            return Err(crate::error::CryptoError::InvalidLength);
        }

        // Subkey generation: L = E(K, 0^n); K1 = doubling(L); K2 = doubling(K1).
        let mut l = [0u8; BLOCK_SIZE];
        cipher.encrypt_block(&mut l);
        let k1 = Self::doubling(&l);
        let k2 = Self::doubling(&k1);

        Ok(Cmac {
            cipher,
            k1,
            k2,
            mac: [0u8; BLOCK_SIZE],
            buf: [0u8; BLOCK_SIZE],
            pos: 0,
            finalized: false,
        })
    }

    /// Doubling in GF(2^n) with the reduction polynomial matching the block
    /// size: x^128 + x^7 + x^2 + x + 1 for 128-bit blocks (0x87) and
    /// x^64 + x^4 + x^3 + x^2 + 1 for 64-bit blocks (0x1b).
    fn doubling(v: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let reduction: u8 = if BLOCK_SIZE == 16 { 0x87 } else { 0x1b };

        let mut out = [0u8; BLOCK_SIZE];
        let msb = v[0] & 0x80 != 0;
        for i in 0..BLOCK_SIZE {
            out[i] = v[i] << 1;
            if i + 1 < BLOCK_SIZE && v[i + 1] & 0x80 != 0 {
                out[i] |= 1;
            }
        }
        if msb {
            out[BLOCK_SIZE - 1] ^= reduction;
        }
        out
    }

    fn xor(dst: &mut [u8; BLOCK_SIZE], src: &[u8; BLOCK_SIZE]) {
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d ^= s;
        }
    }

    /// Write adds more data to the running message authentication code.
    ///
    /// It must not be called after the first call of Sum or Verify.
    pub fn write(&mut self, mut p: &[u8]) {
        if self.finalized {
            panic!("cmac: write to MAC after Sum or Verify");
        }
        if p.is_empty() {
            return;
        }

        // Flush the pending block; it is complete only if more data follows.
        if self.pos == BLOCK_SIZE {
            Self::xor(&mut self.mac, &self.buf);
            self.cipher.encrypt_block(&mut self.mac);
            self.pos = 0;
        }
        let n = core::cmp::min(p.len(), BLOCK_SIZE - self.pos);
        self.buf[self.pos..self.pos + n].copy_from_slice(&p[..n]);
        self.pos += n;
        p = &p[n..];

        while !p.is_empty() {
            // `buf` is a full block and more data follows: it is no longer the
            // last block, so absorb it.
            Self::xor(&mut self.mac, &self.buf);
            self.cipher.encrypt_block(&mut self.mac);

            let n = core::cmp::min(p.len(), BLOCK_SIZE);
            self.buf[..n].copy_from_slice(&p[..n]);
            self.pos = n;
            p = &p[n..];
        }
    }

    /// Sum computes the authenticator of all data written to the message
    /// authentication code. The MAC cannot be used afterwards.
    pub fn sum(&mut self) -> [u8; BLOCK_SIZE] {
        if self.finalized {
            panic!("cmac: Sum called twice");
        }
        self.finalized = true;

        // Last-block mask: complete block uses K1, a padded one uses K2.
        let mut last = self.buf;
        if self.pos == BLOCK_SIZE {
            Self::xor(&mut last, &self.k1);
        } else {
            // The buffer tail is stale from a previous fill; the ISO padding
            // replaces it entirely with 0x80 0x00... .
            last[self.pos..].fill(0);
            last[self.pos] ^= 0x80;
            Self::xor(&mut last, &self.k2);
        }
        Self::xor(&mut self.mac, &last);
        self.cipher.encrypt_block(&mut self.mac);
        self.mac
    }

    /// Verify returns whether the authenticator of all data written to the
    /// message authentication code matches the expected value, in constant
    /// time. The MAC cannot be used afterwards.
    pub fn verify(&mut self, expected: &[u8]) -> bool {
        let mac = self.sum();
        constant_time_eq(&mac, expected)
    }

    /// Reset re-initializes the MAC with the same key for a new message.
    pub fn reset(&mut self) {
        self.mac = [0u8; BLOCK_SIZE];
        self.buf = [0u8; BLOCK_SIZE];
        self.pos = 0;
        self.finalized = false;
    }
}

/// Compute the CMAC of `msg` under the keyed `cipher`.
pub fn sum<T: BlockCipher, const BLOCK_SIZE: usize>(
    cipher: T,
    msg: &[u8],
) -> CryptoResult<[u8; BLOCK_SIZE]> {
    let mut mac = Cmac::<T, BLOCK_SIZE>::new(cipher)?;
    mac.write(msg);
    Ok(mac.sum())
}

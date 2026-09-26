//! AES-SIV (synthetic IV) authenticated encryption, ported from OpenSSL
//! `crypto/modes/siv128.c` and `cipher_aes_siv.c`.
//!
//! SIV (RFC 5297) derives the IV itself from the plaintext and the associated
//! data with CMAC (`S2V`), then encrypts with AES-CTR under the second half
//! of the key. The synthetic IV doubles as the authentication tag, so the
//! nonce does not have to be unique per message — misusing a nonce only
//! leaks equality of (AAD, plaintext) pairs. The RFC 5297 nonce is simply the
//! first associated data item; it is not treated specially here either.
//!
//! The combined key is split in halves: the first half keys CMAC, the second
//! half keys CTR. `aes-128-siv` takes a 32-byte key, `aes-192-siv` a 48-byte
//! key and `aes-256-siv` a 64-byte key. The tag is always 16 bytes and the
//! ciphertext is as long as the plaintext.
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc5297>

#[cfg(test)]
mod tests;

use crate::error::{CryptoError, CryptoResult};
use crate::mac::cmac::Cmac;
use crate::modes::ctr::Ctr;
use crate::stream::StreamCipher;

use crate::block::aes::Aes;

const BLOCK_SIZE: usize = 16;

/// AES-SIV instance holding the CMAC, the CTR key.
pub struct AesSiv {
    k2: Aes,
    mac: Cmac<Aes, BLOCK_SIZE>,
}

impl AesSiv {
    /// The tag (synthetic IV) size in bytes.
    pub const fn tag_size() -> usize {
        BLOCK_SIZE
    }

    /// Create an AES-SIV instance from the combined key (32, 48 or 64 bytes).
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        let half = key.len() / 2;
        match key.len() {
            32 | 48 | 64 => {
                let k1 = Aes::new(&key[..half])?;
                let k2 = Aes::new(&key[half..])?;
                let mac = Cmac::<Aes, BLOCK_SIZE>::new(k1)?;
                Ok(AesSiv { k2, mac })
            }
            len => Err(CryptoError::InvalidKeySize {
                expected: "32 | 48 | 64",
                actual: len,
            }),
        }
    }

    /// Run CMAC-K1 over the concatenation of `parts` from a fresh state.
    fn cmac(&mut self, parts: &[&[u8]]) -> [u8; BLOCK_SIZE] {
        self.mac.reset();
        for part in parts {
            self.mac.write(part);
        }
        self.mac.sum()
    }

    /// S2V over the associated data and the (already CTR-processed on open)
    /// plaintext; returns the synthetic IV. Mirrors `siv128_do_s2v_p`.
    fn s2v(&mut self, aads: &[&[u8]], data: &[u8]) -> [u8; BLOCK_SIZE] {
        let mut d = self.cmac(&[&[0u8; BLOCK_SIZE]]);

        for ad in aads {
            dbl(&mut d);
            let mac = self.cmac(&[ad]);
            for (d, m) in d.iter_mut().zip(mac.iter()) {
                *d ^= m;
            }
        }

        if data.len() >= BLOCK_SIZE {
            // CMAC over everything except the last block, then the last
            // block XORed with the running value.
            let (head, tail) = data.split_at(data.len() - BLOCK_SIZE);
            let mut last = [0u8; BLOCK_SIZE];
            last.copy_from_slice(tail);
            for (l, dd) in last.iter_mut().zip(d.iter()) {
                *l ^= dd;
            }
            self.cmac(&[head, &last])
        } else {
            // Padded short message: 0x80 followed by zeros, XORed with the
            // doubled running value.
            dbl(&mut d);
            let mut block = [0u8; BLOCK_SIZE];
            block[..data.len()].copy_from_slice(data);
            block[data.len()] = 0x80;
            for (b, dd) in block.iter_mut().zip(d.iter()) {
                *b ^= dd;
            }
            self.cmac(&[&block])
        }
    }

    /// CTR-encrypt/decrypt `inout` under the masked counter block.
    fn ctr(&self, q: &[u8; BLOCK_SIZE], inout: &mut [u8]) -> CryptoResult<()> {
        let mut q = *q;
        q[8] &= 0x7f;
        q[12] &= 0x7f;
        self.k2.clone().to_ctr(&q)?.xor_key_stream(inout)
    }

    /// Encrypt `inout` in place and return the 16-byte tag (the SIV). Each
    /// entry of `aads` becomes one S2V associated data item, in order.
    pub fn seal_in_place(
        &mut self,
        inout: &mut [u8],
        aads: &[&[u8]],
    ) -> CryptoResult<[u8; BLOCK_SIZE]> {
        let tag = self.s2v(aads, inout);
        self.ctr(&tag, inout)?;
        Ok(tag)
    }

    /// Decrypt and verify `inout` in place against `tag`. On authentication
    /// failure the buffer is cleared, mirroring OpenSSL's cleanse on error.
    pub fn open_in_place(
        &mut self,
        inout: &mut [u8],
        tag: &[u8],
        aads: &[&[u8]],
    ) -> CryptoResult<()> {
        if tag.len() != BLOCK_SIZE {
            return Err(CryptoError::InvalidTagSize {
                expected: "16",
                actual: tag.len(),
            });
        }
        let mut expected = [0u8; BLOCK_SIZE];
        expected.copy_from_slice(tag);

        self.ctr(&expected, inout)?;
        let computed = self.s2v(aads, inout);

        let mut diff = 0u8;
        for (a, b) in computed.iter().zip(expected.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            inout.fill(0);
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }
}

/// Doubles a 16-byte block interpreted as a big-endian integer, reducing
/// with 0x87 into the least significant end (mirrors `siv128_dbl`; note the
/// byte order is opposite to the XTS doubling).
fn dbl(block: &mut [u8; BLOCK_SIZE]) {
    let mut carry = 0u8;
    for b in block.iter_mut().rev() {
        let bit = *b >> 7;
        *b = (*b << 1) | carry;
        carry = bit;
    }
    if carry != 0 {
        block[BLOCK_SIZE - 1] ^= 0x87;
    }
}

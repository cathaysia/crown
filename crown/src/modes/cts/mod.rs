//! Ciphertext Stealing (CTS), CBC-CS1/CS2/CS3.
//!
//! The three variants follow OpenSSL's `AES-*-CBC-CTS` modes
//! (`providers/implementations/ciphers/cipher_cts.c`):
//!
//! - **CS1** (NIST): for messages that are a multiple of the block size
//!   this is plain CBC. Otherwise the output ends
//!   `.., C(n-1)[0..r], T` — the penultimate block is truncated and the
//!   full stolen block `T` comes last.
//! - **CS2**: like CS1 for full multiples; otherwise like CS3.
//! - **CS3** (Kerberos5, RFC 3962 via RFC 2040 §8): the last two blocks
//!   are always swapped. For full multiples this is plain CBC with the
//!   last two ciphertext blocks exchanged; otherwise the output ends
//!   `.., T, C(n-1)[0..r]`.
//!
//! In all variants the stolen block is
//! `T = E(P_n || 0^.. ⊕ C(n-1))`, where `C(n-1)` is the CBC ciphertext of
//! the last full block. Messages must be at least one block long.

use crate::block::BlockCipher;
use crate::error::{CryptoError, CryptoResult};
use alloc::vec;
use alloc::vec::Vec;

/// CBC ciphertext-stealing variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CtsVariant {
    /// NIST variant; plain CBC for full multiples.
    Cs1,
    /// CS1 for full multiples, CS3 otherwise.
    Cs2,
    /// Kerberos5 variant; last two blocks always exchanged.
    Cs3,
}

/// CBC-CTS mode over an arbitrary block cipher.
pub struct Cts<B: BlockCipher> {
    b: B,
    iv: Vec<u8>,
    variant: CtsVariant,
}

impl<B: BlockCipher> Cts<B> {
    /// Create a CS3 (Kerberos5) instance. `iv` must be exactly one block.
    pub fn new(b: B, iv: &[u8]) -> CryptoResult<Self> {
        Self::with_variant(CtsVariant::Cs3, b, iv)
    }

    /// Create an instance of the given variant. `iv` must be exactly one block.
    pub fn with_variant(variant: CtsVariant, b: B, iv: &[u8]) -> CryptoResult<Self> {
        let bs = b.block_size();
        if iv.len() != bs {
            return Err(CryptoError::InvalidIvSize(iv.len()));
        }
        Ok(Self {
            b,
            iv: iv.to_vec(),
            variant,
        })
    }

    fn block_size(&self) -> usize {
        self.b.block_size()
    }

    /// Encrypt `pt` (length >= block_size) with the selected variant.
    /// The ciphertext length always equals the plaintext length.
    pub fn encrypt(&self, pt: &[u8]) -> CryptoResult<Vec<u8>> {
        let bs = self.block_size();
        if pt.len() < bs {
            return Err(CryptoError::InvalidLength);
        }
        let full = pt.len() / bs;
        let r = pt.len() % bs;
        let full_bytes = full * bs;
        let mut out = pt.to_vec();

        // CBC-encrypt the complete blocks in place → C(1)..C(full).
        self.cbc_encrypt_blocks(&mut out[..full_bytes]);

        if r == 0 {
            // CS1/CS2 are plain CBC; CS3 exchanges the last two blocks.
            if self.variant == CtsVariant::Cs3 && full >= 2 {
                for i in 0..bs {
                    out.swap(full_bytes - 2 * bs + i, full_bytes - bs + i);
                }
            }
            return Ok(out);
        }

        // Stolen block: T = E(P_n || 0^.. ⊕ C(full)).
        let mut t = vec![0u8; bs];
        t[..r].copy_from_slice(&pt[full_bytes..]);
        for i in 0..bs {
            t[i] ^= out[full_bytes - bs + i];
        }
        self.b.encrypt_block(&mut t);

        // The surviving prefix of C(full).
        let c_full_prefix = out[full_bytes - bs..full_bytes - bs + r].to_vec();
        out.truncate(full_bytes - bs);
        match self.variant {
            CtsVariant::Cs1 => {
                out.extend_from_slice(&c_full_prefix);
                out.extend_from_slice(&t);
            }
            CtsVariant::Cs2 | CtsVariant::Cs3 => {
                out.extend_from_slice(&t);
                out.extend_from_slice(&c_full_prefix);
            }
        }
        Ok(out)
    }

    /// Decrypt `ct` (length >= block_size) with the selected variant.
    pub fn decrypt(&self, ct: &[u8]) -> CryptoResult<Vec<u8>> {
        let bs = self.block_size();
        if ct.len() < bs {
            return Err(CryptoError::InvalidLength);
        }
        let full = ct.len() / bs;
        let r = ct.len() % bs;
        let full_bytes = full * bs;

        if r == 0 {
            let mut out = ct.to_vec();
            if self.variant == CtsVariant::Cs3 && full >= 2 {
                for i in 0..bs {
                    out.swap(full_bytes - 2 * bs + i, full_bytes - bs + i);
                }
            }
            self.cbc_decrypt_blocks(&mut out);
            return Ok(out);
        }

        // Locate the full stolen block X (= T) and the partial piece
        // Y (= C(full)[0..r]); their order differs per variant. Both sit
        // after the (full-1) untouched leading blocks.
        let (x, y): (&[u8], &[u8]) = match self.variant {
            CtsVariant::Cs1 => {
                let y_start = full_bytes - bs;
                (
                    &ct[y_start + r..y_start + r + bs],
                    &ct[y_start..y_start + r],
                )
            }
            CtsVariant::Cs2 | CtsVariant::Cs3 => {
                (&ct[full_bytes - bs..full_bytes], &ct[ct.len() - r..])
            }
        };

        // D(T) = P_n' ⊕ C(full), so C(full)[r..] = D(T)[r..].
        let mut dt = x.to_vec();
        self.b.decrypt_block(&mut dt);

        // Rebuild C(full) = Y || D(T)[r..] and the partial plaintext
        // P_n = D(T)[0..r] ⊕ C(full)[0..r].
        let mut c_full = vec![0u8; bs];
        c_full[..r].copy_from_slice(y);
        c_full[r..].copy_from_slice(&dt[r..]);
        let p_last: Vec<u8> = dt[..r].iter().zip(y.iter()).map(|(a, b)| a ^ b).collect();

        // CBC-decrypt C(1)..C(full).
        let mut stream = Vec::with_capacity(full_bytes);
        stream.extend_from_slice(&ct[..full_bytes - bs]);
        stream.extend_from_slice(&c_full);
        self.cbc_decrypt_blocks(&mut stream);
        stream.extend_from_slice(&p_last);
        Ok(stream)
    }

    /// CBC-encrypt `buf` in place (all of it must be block-aligned).
    fn cbc_encrypt_blocks(&self, buf: &mut [u8]) {
        let bs = self.block_size();
        let mut prev = self.iv.clone();
        for chunk in buf.chunks_exact_mut(bs) {
            for i in 0..bs {
                chunk[i] ^= prev[i];
            }
            self.b.encrypt_block(chunk);
            prev.copy_from_slice(chunk);
        }
    }

    /// CBC-decrypt `buf` in place (block-aligned).
    fn cbc_decrypt_blocks(&self, buf: &mut [u8]) {
        let bs = self.block_size();
        let mut prev = self.iv.clone();
        // One scratch block for the ciphertext side, instead of a fresh
        // allocation per block.
        let mut cur = vec![0u8; bs];
        for chunk in buf.chunks_exact_mut(bs) {
            cur.copy_from_slice(chunk);
            self.b.decrypt_block(chunk);
            for i in 0..bs {
                chunk[i] ^= prev[i];
            }
            prev.copy_from_slice(&cur);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::aes::Aes;

    fn aes_cts(data_len: usize) -> (Vec<u8>, Vec<u8>) {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let c = Cts::new(Aes::new(&key).unwrap(), &iv).unwrap();
        let pt: Vec<u8> = (0..data_len as u8).collect();
        let ct = c.encrypt(&pt).unwrap();
        assert_eq!(ct.len(), pt.len());
        let back = c.decrypt(&ct).unwrap();
        assert_eq!(back, pt);
        (pt, ct)
    }

    #[test]
    fn full_block_swap_roundtrip() {
        // 32 bytes = 2 full blocks → last two blocks swapped.
        let (pt, ct) = aes_cts(32);
        assert_eq!(ct.len(), 32);
        assert_ne!(ct, pt);
        let (_, ct2) = aes_cts(32);
        assert_eq!(ct, ct2);
    }

    #[test]
    fn exact_two_blocks_swaps() {
        // 2 blocks exactly: CS3 output is C2||C1 instead of C1||C2.
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let c = Cts::new(Aes::new(&key).unwrap(), &iv).unwrap();
        let pt = [0x00u8; 32];
        let ct = c.encrypt(&pt).unwrap();
        // Plain CBC of two zero blocks: C1 = E(IV), C2 = E(C1). CS3 swaps.
        let mut c1 = [0x22u8; 16];
        Aes::new(&key).unwrap().encrypt_block(&mut c1);
        let mut c2 = c1;
        Aes::new(&key).unwrap().encrypt_block(&mut c2);
        assert_eq!(&ct[..16], &c2[..]);
        assert_eq!(&ct[16..], &c1[..]);
        assert_eq!(c.decrypt(&ct).unwrap(), pt);
    }

    #[test]
    fn partial_final_steals() {
        // 20 bytes = 1 full block + 4 stolen bytes.
        let (pt, ct) = aes_cts(20);
        assert_eq!(pt.len(), 20);
        assert_eq!(ct.len(), 20);
    }

    #[test]
    fn partial_various_lengths() {
        for n in [16, 17, 18, 23, 31, 32, 33, 47, 48, 49, 64, 100] {
            let (_, _) = aes_cts(n);
        }
    }

    #[test]
    fn min_length_required() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let c = Cts::new(Aes::new(&key).unwrap(), &iv).unwrap();
        assert!(c.encrypt(&[]).is_err());
        assert!(c.encrypt(&[0u8; 15]).is_err());
    }

    #[test]
    fn bad_iv_size() {
        let key = [0u8; 16];
        assert!(Cts::new(Aes::new(&key).unwrap(), &[0u8; 8]).is_err());
    }

    /// CS1 leaves full-multiple messages as plain CBC (no swap).
    #[test]
    fn cs1_full_multiple_is_plain_cbc() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let aes = Aes::new(&key).unwrap();
        let c = Cts::with_variant(CtsVariant::Cs1, aes.clone(), &iv).unwrap();
        let pt = [0u8; 32];
        let ct = c.encrypt(&pt).unwrap();
        let mut c1 = iv;
        aes.encrypt_block(&mut c1);
        let mut c2 = c1;
        aes.encrypt_block(&mut c2);
        assert_eq!(&ct[..16], &c1[..]);
        assert_eq!(&ct[16..], &c2[..]);
        assert_eq!(c.decrypt(&ct).unwrap(), pt);
    }
}

#[cfg(test)]
mod vectors {
    include!("vectors.rs");
}

#[cfg(test)]
mod golden_tests {
    use super::vectors::CTS_VECTORS;
    use super::*;
    use crate::block::aes::Aes;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn openssl_cts_golden_vectors() {
        // key = 0x11.., iv = 0x22.. (matching the generated vectors).
        let key: Vec<u8> = (0..16u8).map(|i| 0x11 + i).collect();
        let iv: Vec<u8> = (0..16u8).map(|i| 0x22 + i).collect();
        let aes = Aes::new(&key).unwrap();
        for (name, mode, pt_hex, ct_hex) in CTS_VECTORS {
            let variant = match *mode {
                "CS1" => CtsVariant::Cs1,
                "CS2" => CtsVariant::Cs2,
                _ => CtsVariant::Cs3,
            };
            let c = Cts::with_variant(variant, aes.clone(), &iv).unwrap();
            let pt = hex(pt_hex);
            let expected = hex(ct_hex);
            let ct = c.encrypt(&pt).unwrap();
            assert_eq!(ct, expected, "{name} encrypt");
            let back = c.decrypt(&expected).unwrap();
            assert_eq!(back, pt, "{name} decrypt");
        }
    }
}

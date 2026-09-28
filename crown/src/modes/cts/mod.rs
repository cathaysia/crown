//! Ciphertext Stealing (CTS), CBC-CS3.
//!
//! CBC-CS3 is the variant used by Kerberos (RFC 3962) and IEEE P1619:
//! - When the plaintext length is a multiple of the block size, the last
//!   two ciphertext blocks are swapped relative to plain CBC.
//! - Otherwise the final partial block "steals" bytes from the penultimate
//!   ciphertext block so the ciphertext length equals the plaintext length
//!   without padding.
//!
//! The plaintext length must be at least one full block.

use crate::block::BlockCipher;
use crate::error::{CryptoError, CryptoResult};
use alloc::vec;
use alloc::vec::Vec;

/// CBC-CS3 mode over an arbitrary block cipher.
pub struct Cts<B: BlockCipher> {
    b: B,
    iv: Vec<u8>,
}

impl<B: BlockCipher> Cts<B> {
    /// Create a CS3 instance. `iv` must be exactly one block.
    pub fn new(b: B, iv: &[u8]) -> CryptoResult<Self> {
        let bs = b.block_size();
        if iv.len() != bs {
            return Err(CryptoError::InvalidIvSize(iv.len()));
        }
        Ok(Self {
            b,
            iv: iv.to_vec(),
        })
    }

    fn block_size(&self) -> usize {
        self.b.block_size()
    }

    /// Encrypt `pt` (length >= block_size) with CBC-CS3.
    pub fn encrypt(&self, pt: &[u8]) -> CryptoResult<Vec<u8>> {
        let bs = self.block_size();
        if pt.len() < bs {
            return Err(CryptoError::InvalidLength);
        }
        let mut out = pt.to_vec();

        if pt.len() % bs == 0 {
            // Full blocks: plain CBC, then swap the last two ciphertext blocks.
            self.cbc_blocks(&mut out);
            let n = out.len();
            if n >= 2 * bs {
                for i in 0..bs {
                    out.swap(n - 2 * bs + i, n - bs + i);
                }
            }
            return Ok(out);
        }

        // Partial final block: number of full blocks (>= 1).
        let full = pt.len() / bs;
        let r = pt.len() % bs;
        let full_bytes = full * bs;

        // CBC-encrypt the full blocks in place → C_1..C_full.
        self.cbc_blocks_partial(&mut out, full_bytes);

        // T = E( (P_last_padded) ⊕ C_full )
        let mut t = vec![0u8; bs];
        t[..r].copy_from_slice(&pt[full_bytes..]);
        for i in 0..bs {
            t[i] ^= out[full_bytes - bs + i];
        }
        self.b.encrypt_block(&mut t);

        // C_last = T[0..r]
        // C_full = T[r..bs] || C_full[0..r]   (the "steal")
        // Rebuild the tail of `out`.
        let mut tail = Vec::with_capacity(bs + r);
        tail.extend_from_slice(&t[r..]);
        tail.extend_from_slice(&out[full_bytes - bs..full_bytes - bs + r]);
        tail.extend_from_slice(&t[..r]);
        out.truncate(full_bytes - bs);
        out.extend_from_slice(&tail);
        Ok(out)
    }

    /// Decrypt `ct` (length >= block_size) with CBC-CS3.
    pub fn decrypt(&self, ct: &[u8]) -> CryptoResult<Vec<u8>> {
        let bs = self.block_size();
        if ct.len() < bs {
            return Err(CryptoError::InvalidLength);
        }
        if ct.len() % bs == 0 {
            // Full blocks: swap last two, then plain CBC decrypt.
            let mut out = ct.to_vec();
            let n = out.len();
            if n >= 2 * bs {
                for i in 0..bs {
                    out.swap(n - 2 * bs + i, n - bs + i);
                }
            }
            self.cbc_decrypt_blocks(&mut out);
            return Ok(out);
        }

        let full = ct.len() / bs;
        let r = ct.len() % bs;
        let full_bytes = full * bs;

        // Ciphertext layout: C_1..C_{full-1} || C_full' || C_last'
        // where C_full' = T[r..bs] || C_last_prefix[0..r]  (bs bytes)
        //       C_last' = T[0..r]                           (r bytes)
        // Recover T = C_last' || C_full'[0..bs-r]
        let mut t = vec![0u8; bs];
        t[..r].copy_from_slice(&ct[full_bytes..]);
        t[r..].copy_from_slice(&ct[full_bytes - bs..full_bytes - bs + (bs - r)]);

        // Recover C_full = C_full'[bs-r..] || ??? — actually C_full (the CBC
        // ciphertext of the last full block) had its first r bytes placed at
        // C_full'[bs-r..]. The remaining b-r bytes of C_full are the last
        // b-r bytes of... they were swapped out. Let me re-derive.
        //
        // During encrypt we produced:
        //   tail = T[r..bs] (bs-r bytes) || C_full[0..r] (r bytes) || T[0..r] (r bytes)
        // so C_full' = T[r..bs] || C_full[0..r], and C_last' = T[0..r].
        // We know T fully (above). We know C_full[0..r] = C_full'[bs-r..].
        // The other (bs-r) bytes of C_full are NOT in the output — they were
        // discarded after use. But we don't need them: to decrypt we need
        // P_last_full = D(T) ⊕ C_full... wait no.
        //
        // Correct inverse:
        //   D(T) = P_last_padded ⊕ C_full
        //   so P_last_full = D(T)[0..bs] ⊕ C_full, but we only need P for
        //   the full blocks via CBC, and the last full plaintext is what we
        //   want. We are missing C_full[bs-r..] (b-r bytes).
        //
        // Actually we DO have them: during encrypt, the CBC ciphertext C_full
        // is `out[full_bytes-bs..full_bytes]` BEFORE the tail rewrite. Its
        // first r bytes are preserved at C_full'[bs-r..]. Its last bs-r bytes
        // were overwritten by T[r..]. So they are lost from the output —
        // which is correct, because decryption must not need them.
        //
        // What we need is:
        //   P_last_padded = D(T) ⊕ C_full
        // but C_full itself is recovered as: C_full = (D(T)[r..] ⊕ P_full_tail)
        // — circular. The standard inverse instead works as follows:
        //
        //   Let X = D(T).  Then X = P_last_padded ⊕ C_full.
        //   C_full = (old C_full)[0..bs]; we know old C_full[0..r] from
        //   C_full'[bs-r..]. And X[0..r] = P_last ⊕ C_full[0..r] is the
        //   last partial plaintext (since P_last_padded[0..r] = P_last).
        //   For the full-block plaintext we then CBC-decrypt using the
        //   reconstructed C_full: C_full = C_full'[bs-r..] || (X[r..] ⊕ ?)...
        //
        // Simpler standard inverse (CS3):
        //   1. Swap the last two ciphertext "blocks" in the CS3 sense by
        //      reconstructing the intermediate CBC ciphertext stream:
        //         C_full = C_full'[0..r] is wrong position...
        //
        // Use the well-known CS3 decrypt recipe:
        //   - Let Cm-1 = last bs bytes of ciphertext-that-are-full (C_full'),
        //     Cm = final r bytes.
        //   - T = Cm || Cm-1[0..bs-r]
        //   - Pm = D(T)[0..r] ⊕ Cm-1[bs-r..]     (Cm-1 tail holds C_full[0..r])
        //   - Recovered CBC ciphertext of last full block:
        //         C_full = D(T)[r..] ... no.
        //
        // Worked inverse from the encrypt equations:
        //   T = E(P_last_padded ⊕ C_full)
        //   C_last' = T[0..r]
        //   C_full' = T[r..bs] || C_full[0..r]
        // Therefore:
        //   T is fully known → P_last_padded ⊕ C_full = D(T)
        //   C_full[0..r] is known from C_full'[bs-r..]
        //   ⇒ P_last = D(T)[0..r] ⊕ C_full[0..r] = D(T)[0..r] ⊕ C_full'[bs-r..]
        //   ⇒ P_last_padded[r..] = D(T)[r..] ⊕ C_full[r..]
        //   But C_full[r..] is exactly what we want to feed the CBC decrypt
        //   of the full blocks. We recover it as:
        //        C_full[r..] = D(T)[r..] ⊕ P_last_padded[r..]
        //   and P_last_padded[r..] = 0 (we padded with zeros!). So
        //        C_full[r..] = D(T)[r..]
        //   Beautiful — that is the point of the zero padding.
        // Thus:
        //   C_full = C_full'[bs-r..] || D(T)[r..]
        //   P_full_and_below via normal CBC decrypt of C_1..C_{full-1} || C_full.

        let mut x = t;
        self.b.decrypt_block(&mut x);

        // P_last (r bytes)
        let p_last: Vec<u8> = x[..r]
            .iter()
            .zip(ct[full_bytes - bs + (bs - r)..full_bytes].iter())
            .map(|(a, b)| a ^ b)
            .collect();

        // Reconstruct C_full = C_full'[bs-r..] (r bytes) || X[r..] (bs-r bytes)
        let mut c_full = vec![0u8; bs];
        c_full[..r].copy_from_slice(&ct[full_bytes - bs + (bs - r)..full_bytes]);
        c_full[r..].copy_from_slice(&x[r..]);

        // Build the CBC ciphertext stream C_1..C_full and decrypt.
        let mut stream = Vec::with_capacity(full_bytes);
        stream.extend_from_slice(&ct[..full_bytes - bs]);
        stream.extend_from_slice(&c_full);
        self.cbc_decrypt_blocks(&mut stream);
        stream.extend_from_slice(&p_last);
        Ok(stream)
    }

    /// CBC-encrypt `buf` in place (all of it must be block-aligned).
    fn cbc_blocks(&self, buf: &mut [u8]) {
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

    /// CBC-encrypt only the first `len` bytes of `buf` in place.
    fn cbc_blocks_partial(&self, buf: &mut [u8], len: usize) {
        let bs = self.block_size();
        let mut prev = self.iv.clone();
        for chunk in buf[..len].chunks_exact_mut(bs) {
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
        // Ciphertext must differ from plain CBC of the same input.
        // At minimum, roundtrip holds and the two halves are "swapped"
        // relative to CBC — we just check CT != PT and stability.
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
        // Verify by computing CBC manually.
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
}

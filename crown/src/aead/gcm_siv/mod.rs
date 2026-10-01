//! AES-GCM-SIV (RFC 8452) — nonce misuse-resistant AEAD.
//!
//! Construction summary (AES-128 variant):
//! 1. Derive a per-nonce message-authentication key and message-encryption
//!    key by encrypting `le32(counter) || nonce` with AES and keeping the
//!    first 8 bytes of each block.
//! 2. Compute `POLYVAL(auth_key, pad(AAD) || pad(PT) || len_block)`.
//! 3. XOR the nonce into the first 12 bytes of the POLYVAL output, clear
//!    the top bit of the last byte, and AES-encrypt to get the tag.
//! 4. Encrypt the plaintext with AES-CTR whose initial counter block is
//!    the tag with the top bit of the last byte *set*.

use crate::aead::{Aead, AeadUser};
use crate::block::aes::Aes;
use crate::block::BlockCipher;
use crate::error::{CryptoError, CryptoResult};
use crate::utils::subtle::constant_time_eq;

use alloc::vec::Vec;
/// AES-128-GCM-SIV tag length.
pub const TAG_SIZE: usize = 16;
/// AES-128-GCM-SIV nonce length.
pub const NONCE_SIZE: usize = 12;

/// Reduction polynomial for POLYVAL: x^128 + x^127 + x^126 + x^121 + 1.
const RED: u128 = (1u128 << 127) | (1u128 << 126) | (1u128 << 121) | 1;
/// x^-128 in the POLYVAL field, as a little-endian u128.
/// Bytes `01 00 00 00 00 00 00 00 00 00 00 00 00 00 04 92`.
const X_INV: u128 = u128::from_le_bytes([
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x92,
]);

/// `a *= x` in the POLYVAL field (shift toward bit 127, fold overflow).
#[inline]
fn mul_x(mut a: u128) -> u128 {
    let top = a >> 127;
    a <<= 1;
    if top == 1 {
        a ^= RED;
    }
    a
}

/// `a *= x^k` in the POLYVAL field.
fn mul_x_pow(mut a: u128, k: u32) -> u128 {
    for _ in 0..k {
        a = mul_x(a);
    }
    a
}

/// Precomputed 4-bit multiples of `h` for fast POLYVAL multiplication.
///
/// The table holds `k * h` (scalar k as a 0/1 polynomial), fully reduced.
/// A multiply then consumes 4 bits of the *varying* operand per step
/// (same arrangement as the GHASH product table), replacing the
/// bit-at-a-time loop.
struct Polyval {
    tbl: [u128; 16],
    /// `over16[t]`: reduction terms for the nibble `t` shifted out of a
    /// 4-bit left step (composed from `x^(128 + j) mod f`).
    over16: [u128; 16],
}

impl Polyval {
    fn new(h: u128) -> Self {
        let mut tbl = [0u128; 16];
        tbl[1] = h;
        for k in (2..16).step_by(2) {
            // k = 2m doubles the scalar: poly(k) = poly(m) * x.
            tbl[k] = mul_x(tbl[k / 2]);
            tbl[k + 1] = tbl[k] ^ h;
        }
        let over = [RED, mul_x(RED), mul_x_pow(RED, 2), mul_x_pow(RED, 3)];
        let mut over16 = [0u128; 16];
        for t in 0..16 {
            let mut acc = 0u128;
            for j in 0..4 {
                if (t >> j) & 1 != 0 {
                    acc ^= over[j];
                }
            }
            over16[t] = acc;
        }
        Self { tbl, over16 }
    }

    /// `(a * b) mod f` where the table was built from `b`.
    #[inline]
    fn mul(&self, a: u128) -> u128 {
        let mut z: u128 = 0;
        for i in (0..32).rev() {
            // z = z * x^4, folding the 4 shifted-out bits: bit (124 + j)
            // becomes a term at x^(128 + j). The `a` nibble indexes the
            // product table in the same step.
            let idx = ((a >> (i * 4)) & 0xf) as usize;
            let t = (z >> 124) as usize;
            z = (z << 4) ^ self.over16[t] ^ self.tbl[idx];
        }
        z
    }
}

#[inline]
fn gf_mul(a: u128, b: u128) -> u128 {
    let mut res: u128 = 0;
    let mut a = a;
    for i in 0..128 {
        if (b >> i) & 1 == 1 {
            res ^= a;
        }
        // a = a * x, reduce if x^128 appears
        let top = a >> 127;
        a <<= 1;
        if top == 1 {
            a ^= RED;
        }
    }
    res
}

/// POLYVAL over a sequence of 16-byte blocks.
///
/// `h` must be pre-scaled with `X_INV` (see `polyval_key`), which folds the
/// per-block `* x^-128` into the key so each block costs one multiply.
fn polyval(hp: &Polyval, blocks: &[u8]) -> u128 {
    let mut s: u128 = 0;
    for chunk in blocks.as_chunks::<16>().0 {
        let mut x = [0u8; 16];
        x.copy_from_slice(chunk);
        let x = u128::from_le_bytes(x);
        // S = dot(S + X, H) = (S ⊕ X) * H * x^-128
        s = hp.mul(s ^ x);
    }
    s
}

/// Fold `x^-128` into the POLYVAL key once per message.
fn polyval_key(h: u128) -> Polyval {
    Polyval::new(gf_mul(h, X_INV))
}

/// AES-GCM-SIV (RFC 8452) with AES-128.
pub struct AesGcmSiv {
    key: Aes,
}

impl AesGcmSiv {
    /// Create an AES-128-GCM-SIV instance from a 16-byte key-generating key.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeySize {
                expected: "16",
                actual: key.len(),
            });
        }
        Ok(Self {
            key: Aes::new(key)?,
        })
    }

    /// Derive the per-nonce message-authentication and message-encryption keys.
    fn derive_keys(&self, nonce: &[u8]) -> (u128, Aes) {
        let mut mak = [0u8; 16];
        let mut mek = [0u8; 16];
        for i in 0..4u32 {
            let mut block = [0u8; 16];
            block[..4].copy_from_slice(&i.to_le_bytes());
            block[4..].copy_from_slice(nonce);
            self.key.encrypt_block(&mut block);
            match i {
                0 => mak[..8].copy_from_slice(&block[..8]),
                1 => mak[8..].copy_from_slice(&block[..8]),
                2 => mek[..8].copy_from_slice(&block[..8]),
                _ => mek[8..].copy_from_slice(&block[..8]),
            }
        }
        let h = u128::from_le_bytes(mak);
        (h, Aes::new(&mek).unwrap())
    }

    /// Compute the raw S_s value and the final tag.
    fn compute_tag(&self, h: u128, mek: &Aes, nonce: &[u8], aad: &[u8], pt: &[u8]) -> [u8; 16] {
        // length_block = le64(aad_bits) || le64(pt_bits)
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_le_bytes());
        len_block[8..].copy_from_slice(&((pt.len() as u64) * 8).to_le_bytes());

        // padded aad || padded pt || length_block
        let mut buf =
            Vec::with_capacity(aad.len().div_ceil(16) * 16 + pt.len().div_ceil(16) * 16 + 16);
        buf.extend_from_slice(aad);
        while buf.len() % 16 != 0 {
            buf.push(0);
        }
        buf.extend_from_slice(pt);
        while buf.len() % 16 != 0 {
            buf.push(0);
        }
        buf.extend_from_slice(&len_block);

        let hp = polyval_key(h);
        let s = polyval(&hp, &buf);
        let mut sb = s.to_le_bytes();
        for i in 0..12 {
            sb[i] ^= nonce[i];
        }
        sb[15] &= 0x7f;
        let mut tag = sb;
        mek.encrypt_block(&mut tag);
        tag
    }

    /// AES-CTR with a little-endian 32-bit counter in the first 4 bytes.
    fn ctr_xor(mek: &Aes, icb: &[u8; 16], data: &mut [u8]) {
        let mut block = *icb;
        for chunk in data.chunks_mut(16) {
            let mut ks = block;
            mek.encrypt_block(&mut ks);
            for (i, b) in chunk.iter_mut().enumerate() {
                *b ^= ks[i];
            }
            // increment the first 32 bits as little-endian
            let mut ctr = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
            ctr = ctr.wrapping_add(1);
            block[..4].copy_from_slice(&ctr.to_le_bytes());
        }
    }
}

impl AeadUser for AesGcmSiv {
    fn nonce_size(&self) -> usize {
        NONCE_SIZE
    }
    fn tag_size(&self) -> usize {
        TAG_SIZE
    }
}

impl Aead<16> for AesGcmSiv {
    fn seal_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; 16]> {
        if nonce.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize {
                expected: "12",
                actual: nonce.len(),
            });
        }
        let (h, mek) = self.derive_keys(nonce);
        let tag = self.compute_tag(h, &mek, nonce, additional_data, inout);
        let mut icb = tag;
        icb[15] |= 0x80;
        Self::ctr_xor(&mek, &icb, inout);
        Ok(tag)
    }

    fn open_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize {
                expected: "12",
                actual: nonce.len(),
            });
        }
        if tag.len() != TAG_SIZE {
            return Err(CryptoError::InvalidTagSize {
                expected: "16",
                actual: tag.len(),
            });
        }
        let (h, mek) = self.derive_keys(nonce);
        let mut t = [0u8; 16];
        t.copy_from_slice(tag);
        let mut icb = t;
        icb[15] |= 0x80;
        Self::ctr_xor(&mek, &icb, inout);

        let expected = self.compute_tag(h, &mek, nonce, additional_data, inout);
        if !constant_time_eq(&expected, tag) {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table-driven multiply must agree with the reference
    /// bit-at-a-time multiply on arbitrary operands.
    #[test]
    fn polyval_mul_matches_reference() {
        let mut seed = 0x243f_6a88_85a3_08d3u128;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..200 {
            let a = next();
            let b = next();
            let hp = Polyval::new(b);
            assert_eq!(hp.mul(a), gf_mul(a, b), "a={a:#x} b={b:#x}");
        }
        // Degenerate operands.
        for &(a, b) in &[
            (0, 0),
            (u128::MAX, u128::MAX),
            (1, u128::MAX),
            (u128::MAX, 1),
        ] {
            let hp = Polyval::new(b);
            assert_eq!(hp.mul(a), gf_mul(a, b));
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8452 Appendix C.1 — empty plaintext and AAD.
    #[test]
    fn rfc8452_c1_empty() {
        let key = hex("01000000000000000000000000000000");
        let nonce = hex("030000000000000000000000");
        let c = AesGcmSiv::new(&key).unwrap();
        let mut pt: Vec<u8> = Vec::new();
        let tag = c.seal_in_place_separate_tag(&mut pt, &nonce, &[]).unwrap();
        let expected_tag = hex("dc20e2d83f25705bb49e439eca56de25");
        assert_eq!(&tag[..], &expected_tag[..]);
        // Result is just the tag for an empty message.
        c.open_in_place_separate_tag(&mut pt, &tag, &nonce, &[])
            .unwrap();
    }

    /// RFC 8452 Appendix C.1 — 8-byte plaintext, empty AAD.
    #[test]
    fn rfc8452_c1_8_bytes() {
        let key = hex("01000000000000000000000000000000");
        let nonce = hex("030000000000000000000000");
        let c = AesGcmSiv::new(&key).unwrap();
        let mut pt = hex("0100000000000000");
        let tag = c.seal_in_place_separate_tag(&mut pt, &nonce, &[]).unwrap();
        let expected = hex("b5d839330ac7b786");
        let expected_tag = hex("578782fff6013b815b287c22493a364c");
        assert_eq!(&pt[..], &expected[..]);
        assert_eq!(&tag[..], &expected_tag[..]);
        c.open_in_place_separate_tag(&mut pt, &tag, &nonce, &[])
            .unwrap();
        assert_eq!(&pt[..], &hex("0100000000000000")[..]);
    }

    /// RFC 8452 Appendix C.1 — 8-byte plaintext, 1-byte AAD.
    #[test]
    fn rfc8452_c1_aad() {
        let key = hex("01000000000000000000000000000000");
        let nonce = hex("030000000000000000000000");
        let aad = hex("01");
        let c = AesGcmSiv::new(&key).unwrap();
        let mut pt = hex("0200000000000000");
        let tag = c.seal_in_place_separate_tag(&mut pt, &nonce, &aad).unwrap();
        let expected = hex("1e6daba35669f427");
        let expected_tag = hex("3b0a1a2560969cdf790d99759abd1508");
        assert_eq!(&pt[..], &expected[..]);
        assert_eq!(&tag[..], &expected_tag[..]);
        c.open_in_place_separate_tag(&mut pt, &tag, &nonce, &aad)
            .unwrap();
        assert_eq!(&pt[..], &hex("0200000000000000")[..]);
    }

    #[test]
    fn tampered_tag_rejected() {
        let key = hex("01000000000000000000000000000000");
        let nonce = hex("030000000000000000000000");
        let c = AesGcmSiv::new(&key).unwrap();
        let mut pt = hex("0100000000000000");
        let mut tag = c.seal_in_place_separate_tag(&mut pt, &nonce, &[]).unwrap();
        tag[0] ^= 1;
        assert!(c
            .open_in_place_separate_tag(&mut pt, &tag, &nonce, &[])
            .is_err());
    }

    #[test]
    fn bad_key_size() {
        assert!(AesGcmSiv::new(&[0u8; 15]).is_err());
        assert!(AesGcmSiv::new(&[0u8; 32]).is_err());
    }
}

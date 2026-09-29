//! Ascon-AEAD128 (NIST SP 800-232).
//!
//! 320-bit permutation, rate 64 bits, 12-round initialization/finalization
//! and 6-round data processing. Key 128 bits, nonce 128 bits, tag 128 bits.

use crate::aead::{Aead, AeadUser};
use crate::error::{CryptoError, CryptoResult};
use crate::utils::subtle::constant_time_eq;

use alloc::vec;
use alloc::vec::Vec;
/// Tag length in bytes.
pub const TAG_SIZE: usize = 16;
/// Nonce length in bytes.
pub const NONCE_SIZE: usize = 16;
/// Key length in bytes.
pub const KEY_SIZE: usize = 16;
/// Rate in bytes.
const RATE: usize = 8;

#[inline]
const fn rotr(x: u64, n: u32) -> u64 {
    x.rotate_right(n)
}

/// Ascon core permutation. `rounds` is 12 or 6; the constants are taken
/// from the end of the 12-round constant sequence.
fn ascon_permutation(s: &mut [u64; 5], rounds: usize) {
    for r in (12 - rounds)..12 {
        s[2] ^= 0xf0u64.wrapping_sub(r as u64 * 0x10) + r as u64;
        s[0] ^= s[4];
        s[4] ^= s[3];
        s[2] ^= s[1];
        let t: [u64; 5] = [
            !s[0] & s[1],
            !s[1] & s[2],
            !s[2] & s[3],
            !s[3] & s[4],
            !s[4] & s[0],
        ];
        for i in 0..5 {
            s[i] ^= t[(i + 1) % 5];
        }
        s[1] ^= s[0];
        s[0] ^= s[4];
        s[3] ^= s[2];
        s[2] = !s[2];
        s[0] ^= rotr(s[0], 19) ^ rotr(s[0], 28);
        s[1] ^= rotr(s[1], 61) ^ rotr(s[1], 39);
        s[2] ^= rotr(s[2], 1) ^ rotr(s[2], 6);
        s[3] ^= rotr(s[3], 10) ^ rotr(s[3], 17);
        s[4] ^= rotr(s[4], 7) ^ rotr(s[4], 41);
    }
}

fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[..8].try_into().unwrap())
}

fn pad(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    out.push(0x80);
    while !out.len().is_multiple_of(RATE) {
        out.push(0);
    }
    out
}

/// Ascon-AEAD128 (NIST SP 800-232).
pub struct AsconAead128 {
    key: [u8; 16],
}

impl AsconAead128 {
    /// Create an Ascon-AEAD128 instance from a 16-byte key.
    pub fn new(key: &[u8; 16]) -> Self {
        Self { key: *key }
    }

    fn initialize(&self, nonce: &[u8]) -> [u64; 5] {
        // IV = [k=128, rate*8=64, a=12, b=6, 0, 0, 0, 0] || key || nonce
        let mut buf = [0u8; 40];
        buf[0] = 128;
        buf[1] = (RATE * 8) as u8;
        buf[2] = 12;
        buf[3] = 6;
        buf[8..24].copy_from_slice(&self.key);
        buf[24..40].copy_from_slice(nonce);
        let mut s = [
            be64(&buf[0..8]),
            be64(&buf[8..16]),
            be64(&buf[16..24]),
            be64(&buf[24..32]),
            be64(&buf[32..40]),
        ];
        ascon_permutation(&mut s, 12);
        // XOR key into S[3], S[4]
        s[3] ^= be64(&self.key[0..8]);
        s[4] ^= be64(&self.key[8..16]);
        s
    }

    fn process_aad(&self, s: &mut [u64; 5], aad: &[u8]) {
        if !aad.is_empty() {
            let ap = pad(aad);
            for chunk in ap.as_chunks::<RATE>().0 {
                s[0] ^= be64(chunk);
                ascon_permutation(s, 6);
            }
        }
        s[4] ^= 1;
    }

    fn finalize(&self, s: &mut [u64; 5]) -> [u8; 16] {
        s[1] ^= be64(&self.key[0..8]);
        s[2] ^= be64(&self.key[8..16]);
        // S[3] ^= 0 for a 16-byte key
        ascon_permutation(s, 12);
        s[3] ^= be64(&self.key[0..8]);
        s[4] ^= be64(&self.key[8..16]);
        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&s[3].to_be_bytes());
        tag[8..].copy_from_slice(&s[4].to_be_bytes());
        tag
    }

    fn encrypt_impl(&self, nonce: &[u8], aad: &[u8], pt: &mut [u8]) -> [u8; 16] {
        let mut s = self.initialize(nonce);
        self.process_aad(&mut s, aad);

        // Absorb plaintext in place → ciphertext.
        if pt.is_empty() {
            // Still absorb one padding block.
            s[0] ^= 0x8000_0000_0000_0000;
        } else {
            let pp = pad(pt);
            let nblocks = pp.len() / RATE;
            for (bi, chunk) in pp.as_chunks::<RATE>().0.iter().enumerate() {
                let pblk = be64(chunk);
                let cblk = s[0] ^ pblk;
                if bi + 1 < nblocks {
                    // full block, full output, then permute
                    let off = bi * RATE;
                    pt[off..off + RATE].copy_from_slice(&cblk.to_be_bytes());
                    s[0] ^= pblk;
                    ascon_permutation(&mut s, 6);
                } else {
                    // last block: output only the original remainder
                    let off = bi * RATE;
                    let take = pt.len() - off;
                    pt[off..off + take].copy_from_slice(&cblk.to_be_bytes()[..take]);
                    s[0] ^= pblk;
                    // no permutation after the last block
                }
            }
        }
        self.finalize(&mut s)
    }

    fn decrypt_impl(&self, nonce: &[u8], aad: &[u8], ct: &mut [u8]) -> [u8; 16] {
        let mut s = self.initialize(nonce);
        self.process_aad(&mut s, aad);

        // Mirror the reference: zero-pad the ciphertext to a whole number
        // of blocks. When the ciphertext length is a multiple of the rate
        // this appends one extra all-zero block, which the last-block step
        // turns back into the 10* padding absorb.
        let c_lastlen = ct.len() % RATE;
        let mut c_padded = ct.to_vec();
        c_padded.resize((ct.len() / RATE + 1) * RATE, 0);
        let nblocks = c_padded.len() / RATE;
        let mut pt = vec![0u8; ct.len()];

        // First t-1 blocks: full absorb/permutation cycle.
        for bi in 0..nblocks.saturating_sub(1) {
            let off = bi * RATE;
            let ci = be64(&c_padded[off..off + RATE]);
            let pi = s[0] ^ ci;
            pt[off..off + RATE].copy_from_slice(&pi.to_be_bytes());
            s[0] = ci;
            ascon_permutation(&mut s, 6);
        }

        // Last block: reconstruct the post-absorb state without a permutation.
        let off = (nblocks - 1) * RATE;
        let ci = be64(&c_padded[off..off + RATE]);
        let pblk = s[0] ^ ci;
        if !ct.is_empty() {
            let take = ct.len() - off;
            pt[off..off + take].copy_from_slice(&pblk.to_be_bytes()[..take]);
        }
        let c_padding1: u64 = 0x80u64 << ((RATE - c_lastlen - 1) * 8);
        let c_mask: u64 = u64::MAX >> (c_lastlen * 8);
        s[0] = ci ^ (s[0] & c_mask) ^ c_padding1;

        if !ct.is_empty() {
            ct.copy_from_slice(&pt);
        }
        self.finalize(&mut s)
    }
}

impl AeadUser for AsconAead128 {
    fn nonce_size(&self) -> usize {
        NONCE_SIZE
    }
    fn tag_size(&self) -> usize {
        TAG_SIZE
    }
}

impl Aead<16> for AsconAead128 {
    fn seal_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; 16]> {
        if nonce.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize {
                expected: "16",
                actual: nonce.len(),
            });
        }
        Ok(self.encrypt_impl(nonce, additional_data, inout))
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
                expected: "16",
                actual: nonce.len(),
            });
        }
        if tag.len() != TAG_SIZE {
            return Err(CryptoError::InvalidTagSize {
                expected: "16",
                actual: tag.len(),
            });
        }
        let expected = self.decrypt_impl(nonce, additional_data, inout);
        if !constant_time_eq(&expected, tag) {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // KATs generated against the Ascon v1.2 reference implementation
    // (NIST SP 800-232 Ascon-AEAD128), key = nonce = all zeros.

    /// Empty AAD, empty plaintext.
    #[test]
    fn kat_empty_empty() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let c = AsconAead128::new(&key);
        let mut pt: Vec<u8> = Vec::new();
        let tag = c.seal_in_place_separate_tag(&mut pt, &nonce, &[]).unwrap();
        assert!(pt.is_empty());
        assert_eq!(&tag[..], &hex("42213f50a811d2d1d7e4092aa2a42ba4")[..]);
        c.open_in_place_separate_tag(&mut pt, &tag, &nonce, &[])
            .unwrap();
    }

    /// Empty AAD, 8-byte plaintext.
    #[test]
    fn kat_empty_8pt() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let c = AsconAead128::new(&key);
        let mut pt = hex("0011223344556677");
        let tag = c.seal_in_place_separate_tag(&mut pt, &nonce, &[]).unwrap();
        assert_eq!(&pt[..], &hex("b8ced65849e1478f")[..]);
        assert_eq!(&tag[..], &hex("1bd7041ee5b9f9d4754313e016afcdf5")[..]);
        c.open_in_place_separate_tag(&mut pt, &tag, &nonce, &[])
            .unwrap();
        assert_eq!(&pt[..], &hex("0011223344556677")[..]);
    }

    /// 8-byte AAD + 8-byte plaintext.
    #[test]
    fn kat_8aad_8pt() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let aad = hex("0011223344556677");
        let c = AsconAead128::new(&key);
        let mut pt = hex("0011223344556677");
        let tag = c.seal_in_place_separate_tag(&mut pt, &nonce, &aad).unwrap();
        assert_eq!(&pt[..], &hex("4f3d43d7790affdb")[..]);
        assert_eq!(&tag[..], &hex("03d1c94596220b23edb647adfe43f4a3")[..]);
        c.open_in_place_separate_tag(&mut pt, &tag, &nonce, &aad)
            .unwrap();
        assert_eq!(&pt[..], &hex("0011223344556677")[..]);
    }

    #[test]
    fn tampered_tag_rejected() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let c = AsconAead128::new(&key);
        let mut pt = hex("0011223344556677");
        let mut tag = c.seal_in_place_separate_tag(&mut pt, &nonce, &[]).unwrap();
        tag[0] ^= 1;
        assert!(c
            .open_in_place_separate_tag(&mut pt, &tag, &nonce, &[])
            .is_err());
    }
}

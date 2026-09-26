//! KMAC implementation according to NIST SP 800-185.
//!
//! KMAC is a keyed message authentication code built on cSHAKE:
//!
//! ```text
//! KMAC(K, X, L, S) = cSHAKE(bytepad(encode_string(K), rate) || X || right_encode(L), L, "KMAC", S)
//! ```
//!
//! Only the key is length-encoded, so the message can be streamed; the tag
//! length is appended with `right_encode` right before squeezing. The XOF
//! variants (`KMAC128_XOF`/`KMAC256_XOF`) omit the length encoding and
//! produce an arbitrary number of output bytes.
//!
//! Reference: <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf>

#[cfg(test)]
mod tests;

use alloc::vec::Vec;

use crate::{
    core::{CoreRead, CoreWrite},
    error::CryptoResult,
    hash::sha3::{new_cshake128, new_cshake256, Shake},
    utils::subtle::constant_time_eq,
};

/// KMAC128 tag size recommended by SP 800-185 samples (256 bits).
pub const KMAC128_TAG_SIZE: usize = 32;
/// KMAC256 tag size recommended by SP 800-185 samples (512 bits).
pub const KMAC256_TAG_SIZE: usize = 64;

/// Number of bytes needed to encode `x`, per SP 800-185: the smallest n
/// with 2^(8n) > x (1 for x == 0).
fn encode_len(x: usize) -> usize {
    if x == 0 {
        1
    } else {
        (usize::BITS - x.leading_zeros()).div_ceil(8) as usize
    }
}

/// left_encode(x): the byte encoding n = encode_len(x), followed by x as an
/// n-byte big-endian integer. Per SP 800-185, `len(S)` in encode_string is
/// measured in **bits**.
fn left_encode(x: usize) -> Vec<u8> {
    let n = encode_len(x);

    let mut out = Vec::with_capacity(n + 1);
    out.push(n as u8);
    out.extend_from_slice(&(x as u64).to_be_bytes()[8 - n..]);
    out
}

/// right_encode(x): x as an n-byte big-endian integer, followed by the byte
/// encoding n.
fn right_encode(x: usize) -> Vec<u8> {
    let n = encode_len(x);

    let mut out = Vec::with_capacity(n + 1);
    out.extend_from_slice(&(x as u64).to_be_bytes()[8 - n..]);
    out.push(n as u8);
    out
}

/// bytepad(X, w): prepend left_encode(w) and zero-pad to a multiple of w.
fn bytepad(data: &[u8], w: usize) -> Vec<u8> {
    let prefix = left_encode(w);
    let len = prefix.len() + data.len();
    let pad = (w - len % w) % w;

    let mut out = Vec::with_capacity(len + pad);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(data);
    out.resize(len + pad, 0);
    out
}

/// encode_string(S): left_encode(len(S) in bits) || S.
fn encode_string(s: &[u8]) -> Vec<u8> {
    let mut out = left_encode(s.len() * 8);
    out.extend_from_slice(s);
    out
}

fn absorb_key<const N: usize>(shake: &mut Shake<N>, key: &[u8], rate: usize) {
    let encoded = bytepad(&encode_string(key), rate);
    shake.write_all(&encoded).unwrap();
}

/// KMAC128: cSHAKE128 based KMAC.
pub struct Kmac128 {
    shake: Shake<32>,
    finalized: bool,
}

impl Kmac128 {
    /// The cSHAKE128 rate in bytes (1344 bits).
    const RATE: usize = 168;

    /// Create a new KMAC128 instance with the given key and customization
    /// string `custom` (the SP 800-185 parameter `S`; may be empty).
    pub fn new(key: &[u8], custom: &[u8]) -> CryptoResult<Self> {
        let mut shake = new_cshake128(b"KMAC", custom);
        absorb_key(&mut shake, key, Self::RATE);
        Ok(Kmac128 {
            shake,
            finalized: false,
        })
    }

    /// Write adds more message data to the running MAC.
    pub fn write(&mut self, p: &[u8]) {
        if self.finalized {
            panic!("kmac: write to MAC after Sum or Verify");
        }
        self.shake.write_all(p).unwrap();
    }

    /// Sum computes the tag of all data written, filling `out` entirely.
    /// The output length becomes the KMAC parameter `L` (in bits:
    /// `out.len() * 8`). The MAC cannot be used afterwards.
    pub fn sum(&mut self, out: &mut [u8]) {
        if self.finalized {
            panic!("kmac: Sum called twice");
        }
        self.finalized = true;
        self.shake.write_all(&right_encode(out.len() * 8)).unwrap();
        self.shake.read(out).unwrap();
    }

    /// Verify returns whether the tag matches the expected value, in
    /// constant time. The MAC cannot be used afterwards.
    pub fn verify(&mut self, expected: &[u8]) -> bool {
        let mut tag = alloc::vec![0u8; expected.len()];
        self.sum(&mut tag);
        constant_time_eq(&tag, expected)
    }

    /// XOF sum (KMAC128_XOF): squeeze arbitrary output without appending
    /// the length encoding. The MAC cannot be used afterwards.
    pub fn sum_xof(&mut self, out: &mut [u8]) {
        if self.finalized {
            panic!("kmac: Sum called twice");
        }
        self.finalized = true;
        self.shake.read(out).unwrap();
    }
}

/// KMAC256: cSHAKE256 based KMAC.
pub struct Kmac256 {
    shake: Shake<64>,
    finalized: bool,
}

impl Kmac256 {
    /// The cSHAKE256 rate in bytes (1088 bits).
    const RATE: usize = 136;

    /// Create a new KMAC256 instance with the given key and customization
    /// string `custom` (the SP 800-185 parameter `S`; may be empty).
    pub fn new(key: &[u8], custom: &[u8]) -> CryptoResult<Self> {
        let mut shake = new_cshake256(b"KMAC", custom);
        absorb_key(&mut shake, key, Self::RATE);
        Ok(Kmac256 {
            shake,
            finalized: false,
        })
    }

    /// Write adds more message data to the running MAC.
    pub fn write(&mut self, p: &[u8]) {
        if self.finalized {
            panic!("kmac: write to MAC after Sum or Verify");
        }
        self.shake.write_all(p).unwrap();
    }

    /// Sum computes the tag of all data written, filling `out` entirely.
    /// The output length becomes the KMAC parameter `L` (in bits:
    /// `out.len() * 8`). The MAC cannot be used afterwards.
    pub fn sum(&mut self, out: &mut [u8]) {
        if self.finalized {
            panic!("kmac: Sum called twice");
        }
        self.finalized = true;
        self.shake.write_all(&right_encode(out.len() * 8)).unwrap();
        self.shake.read(out).unwrap();
    }

    /// Verify returns whether the tag matches the expected value, in
    /// constant time. The MAC cannot be used afterwards.
    pub fn verify(&mut self, expected: &[u8]) -> bool {
        let mut tag = alloc::vec![0u8; expected.len()];
        self.sum(&mut tag);
        constant_time_eq(&tag, expected)
    }

    /// XOF sum (KMAC256_XOF): squeeze arbitrary output without appending
    /// the length encoding. The MAC cannot be used afterwards.
    pub fn sum_xof(&mut self, out: &mut [u8]) {
        if self.finalized {
            panic!("kmac: Sum called twice");
        }
        self.finalized = true;
        self.shake.read(out).unwrap();
    }
}

#[cfg(test)]
mod encode_tests {
    use super::*;

    #[test]
    fn left_encode_matches_sp800_185() {
        // From the SP 800-185 sample walkthroughs:
        // left_encode(168) = 01 A8, left_encode(256) = 02 01 00, and the
        // encoding of the empty string is 01 00.
        assert_eq!(left_encode(168), [0x01, 0xa8]);
        assert_eq!(left_encode(256), [0x02, 0x01, 0x00]);
        assert_eq!(left_encode(0), [0x01, 0x00]);
    }

    #[test]
    fn right_encode_matches_sp800_185() {
        assert_eq!(right_encode(256), [0x01, 0x00, 0x02]);
    }

    #[test]
    fn bytepad_matches_sp800_185() {
        // bytepad(encode_string(K), 168) for the 32-byte sample key starts
        // with 01 A8 02 01 00 40 41 ... and totals 168 bytes.
        let key: Vec<u8> = (0x40u8..0x60).collect();
        let padded = bytepad(&encode_string(&key), 168);
        assert_eq!(padded.len(), 168);
        assert_eq!(&padded[..7], &[0x01, 0xa8, 0x02, 0x01, 0x00, 0x40, 0x41]);
    }
}

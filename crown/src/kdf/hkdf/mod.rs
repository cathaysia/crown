//! Package hkdf implements the HMAC-based Extract-and-Expand Key Derivation
//! Function (HKDF) as defined in RFC 5869.
//!
//! HKDF is a cryptographic key derivation function (KDF) with the goal of
//! expanding limited input keying material into one or more cryptographically
//! strong secret keys.

#[cfg(test)]
mod tests;

use crate::{
    core::CoreWrite,
    hash::Hash,
    mac::hmac::{self},
    utils::copy,
};
use std::io::Read;

/// Extract a pseudorandom key from input keying material.
///
/// This is the "extract" step of HKDF as defined in RFC 5869.
/// It takes optional salt and input keying material (IKM) and produces
/// a pseudorandom key (PRK) of fixed length.
pub fn extract<const N: usize, H, F>(hash_fn: F, secret: &[u8], salt: &[u8]) -> [u8; N]
where
    H: Hash<N> + crate::mac::hmac::MaybeMarshalable,
    F: Fn() -> H,
{
    // RFC 5869 sets a missing salt to HashLen zero bytes. As an HMAC key that
    // pads to the same zero block as an empty key, so pass `salt` through.
    let mut extractor = hmac::new(hash_fn, salt);
    extractor
        .write_all(secret)
        .expect("HMAC write should not fail");

    extractor.sum()
}

pub struct Hkdf<const N: usize, H: Hash<N>> {
    expander: H,
    info: Vec<u8>,
    counter: u8,
    /// T(i-1). `prev_len` is 0 until the first block is generated, so the
    /// first HMAC sees T(0) as the empty string (RFC 5869).
    prev: [u8; N],
    prev_len: usize,
    /// Last generated block, with a read cursor for partial consumption.
    buf: [u8; N],
    buf_pos: usize,
    buf_len: usize,
}

impl<const N: usize, H: Hash<N>> Hkdf<N, H> {
    #[inline]
    fn buf_remain(&self) -> usize {
        self.buf_len - self.buf_pos
    }
}

impl<const N: usize, H: Hash<N>> Read for Hkdf<N, H> {
    fn read(&mut self, p: &mut [u8]) -> std::io::Result<usize> {
        let need = p.len();
        let remains = self.buf_remain() + (255 - self.counter + 1) as usize * N;
        if remains < need {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "hkdf: entropy limit reached",
            ));
        }

        let mut n = copy(p, &self.buf[self.buf_pos..self.buf_len]);
        self.buf_pos += n;
        let mut p = &mut p[n..];

        while !p.is_empty() {
            if self.counter > 1 {
                self.expander.reset();
            }
            self.expander
                .write_all(&self.prev[..self.prev_len])
                .expect("HMAC write should not fail");
            self.expander
                .write_all(&self.info)
                .expect("HMAC write should not fail");
            self.expander
                .write_all(&[self.counter])
                .expect("HMAC write should not fail");
            let block = self.expander.sum();
            self.prev = block;
            self.prev_len = N;
            (self.counter, _) = self.counter.overflowing_add(1);

            self.buf = block;
            self.buf_pos = 0;
            self.buf_len = N;
            n = copy(p, &self.buf);
            self.buf_pos += n;
            p = &mut p[n..];
        }

        Ok(need)
    }
}

/// Expand a pseudorandom key to the desired length.
///
/// This is the "expand" step of HKDF as defined in RFC 5869.
/// It takes a pseudorandom key (PRK), optional context info, and desired
/// output length, and produces the output keying material (OKM).
pub fn expand<const N: usize, H, F>(hash_fn: F, pseudorandom_key: &[u8], info: &[u8]) -> impl Read
where
    H: Hash<N> + crate::mac::hmac::MaybeMarshalable,
    F: Fn() -> H,
{
    let expander = crate::mac::hmac::new(hash_fn, pseudorandom_key);
    Hkdf {
        expander,
        info: info.to_vec(),
        counter: 1,
        prev: [0; N],
        prev_len: 0,
        buf: [0; N],
        buf_pos: 0,
        buf_len: 0,
    }
}

// New returns a Reader, from which keys can be read, using the given hash,
// secret, salt and context info. Salt and info can be nil.
pub fn new<const N: usize, F, H>(
    hash_fn: F,
    secret: &[u8],
    salt: &[u8],
    info: &[u8],
) -> impl std::io::Read
where
    H: Hash<N> + crate::mac::hmac::MaybeMarshalable,
    F: Fn() -> H + Copy,
{
    let prk = extract(hash_fn, secret, salt);
    expand(hash_fn, &prk, info)
}

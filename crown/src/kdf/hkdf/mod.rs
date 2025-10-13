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
    hash::{Hash, HashUser},
    mac::hmac::{self, Marshalable},
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
    H: Hash<N> + Marshalable,
    F: Fn() -> H,
{
    let salt = if salt.is_empty() {
        vec![0u8; hash_fn().size()]
    } else {
        salt.to_vec()
    };

    let mut extractor = hmac::new(hash_fn, &salt);
    extractor
        .write_all(secret)
        .expect("HMAC write should not fail");

    extractor.sum()
}

pub struct Hkdf<const N: usize, H: Hash<N>> {
    expander: H,
    size: usize,
    info: Vec<u8>,
    counter: u8,
    prev: Vec<u8>,
    buf: Vec<u8>,
}

impl<const N: usize, H: Hash<N>> Read for Hkdf<N, H> {
    fn read(&mut self, p: &mut [u8]) -> std::io::Result<usize> {
        let need = p.len();
        let remains = self.buf.len() + (255 - self.counter + 1) as usize * self.size;
        if remains < need {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "hkdf: entropy limit reached",
            ));
        }

        let mut n = copy(p, &self.buf);
        let mut p = &mut p[n..];

        while !p.is_empty() {
            if self.counter > 1 {
                self.expander.reset();
            }
            self.expander
                .write_all(&self.prev)
                .expect("HMAC write should not fail");
            self.expander
                .write_all(&self.info)
                .expect("HMAC write should not fail");
            self.expander
                .write_all(&[self.counter])
                .expect("HMAC write should not fail");
            self.prev = self.expander.sum().to_vec();
            (self.counter, _) = self.counter.overflowing_add(1);

            self.buf = self.prev.clone();
            n = copy(p, &self.buf);
            p = &mut p[n..];
        }

        self.buf = self.buf[n..].to_vec();
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
    H: Hash<N> + Marshalable,
    F: Fn() -> H,
{
    let expander = crate::mac::hmac::new(hash_fn, pseudorandom_key);
    Hkdf {
        size: expander.size(),
        expander,
        info: info.to_vec(),
        counter: 1,
        prev: vec![],
        buf: vec![],
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
    H: Hash<N> + Marshalable,
    F: Fn() -> H + Copy,
{
    let prk = extract(hash_fn, secret, salt);
    expand(hash_fn, &prk, info)
}

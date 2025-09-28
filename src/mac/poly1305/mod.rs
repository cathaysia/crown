//! Module poly1305 implements Poly1305 one-time message authentication code as
//! specified in <https://cr.yp.to/mac/poly1305-20050329.pdf>.
//!
//! Poly1305 is a fast, one-time authentication function. It is infeasible for an
//! attacker to generate an authenticator for a message without the key. However, a
//! key must only be used for a single message. Authenticating two different
//! messages with the same key allows an attacker to forge authenticators for other
//! messages with the same key.
//!
//! Poly1305 was originally coupled with AES in order to make Poly1305-AES. AES was
//! used with a fixed key in order to generate one-time keys from an nonce.
//! However, in this package AES isn't used and the one-time key is specified
//! directly.
#[cfg(test)]
mod tests;

mod sum;
pub use sum::*;

#[cfg(not(target_arch = "aarch64"))]
mod no_asm;
#[cfg(not(target_arch = "aarch64"))]
use no_asm::*;

#[cfg(target_arch = "aarch64")]
mod aarch64_mac;
#[cfg(target_arch = "aarch64")]
use aarch64_mac::*;

use crate::utils::subtle::constant_time_eq;

/// TagSize is the size, in bytes, of a poly1305 authenticator.
pub const TAG_SIZE: usize = 16;

/// Sum generates an authenticator for msg using a one-time key and puts the
/// 16-byte result into out. Authenticating two different messages with the same
/// key allows an attacker to forge messages at will.
pub fn sum(out: &mut [u8; TAG_SIZE], msg: &[u8], key: &[u8; 32]) {
    let mut mac = MAC::new(key);
    mac.write(msg);
    mac.sum(out);
}

/// Verify returns true if mac is a valid authenticator for m with the given key.
pub fn verify(mac: &[u8; TAG_SIZE], m: &[u8], key: &[u8; 32]) -> bool {
    let mut tmp = [0u8; TAG_SIZE];
    sum(&mut tmp, m, key);
    constant_time_eq(&tmp, mac)
}

/// MAC is an io.Writer computing an authentication tag
/// of the data written to it.
///
/// MAC cannot be used like common hash.Hash implementations,
/// because using a poly1305 key twice breaks its security.
/// Therefore writing data to a running MAC after calling
/// Sum or Verify causes it to panic.
pub struct MAC {
    mac: Mac,
    finalized: bool,
}

impl MAC {
    /// New returns a new MAC computing an authentication
    /// tag of all data written to it with the given key.
    /// This allows writing the message progressively instead
    /// of passing it as a single slice. Common users should use
    /// the Sum function instead.
    ///
    /// The key must be unique for each message, as authenticating
    /// two different messages with the same key allows an attacker
    /// to forge messages at will.
    pub fn new(key: &[u8; 32]) -> MAC {
        MAC {
            mac: Mac::new(key),
            finalized: false,
        }
    }
    /// Size returns the number of bytes Sum will return.
    pub const fn size() -> usize {
        TAG_SIZE
    }

    /// Write adds more data to the running message authentication code.
    /// It never returns an error.
    ///
    /// It must not be called after the first call of Sum or Verify.
    pub fn write(&mut self, p: &[u8]) {
        if self.finalized {
            panic!("poly1305: write to MAC after Sum or Verify");
        }
        self.mac.write(p);
    }

    /// Sum computes the authenticator of all data written to the
    /// message authentication code.
    pub fn sum(&mut self, out: &mut [u8; TAG_SIZE]) {
        self.mac.sum(out);
        self.finalized = true;
    }

    /// Verify returns whether the authenticator of all data written to
    /// the message authentication code matches the expected value.
    pub fn verify(&mut self, expected: &[u8]) -> bool {
        let mut mac = [0u8; TAG_SIZE];
        self.mac.sum(&mut mac);
        self.finalized = true;
        constant_time_eq(&mac, expected)
    }
}

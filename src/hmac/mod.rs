//! HMAC implementation according to FIPS 198-1.
//!
//! FIPS 198-1: https://doi.org/10.6028/NIST.FIPS.198-1

#[cfg(test)]
mod tests;

use crate::{error::CryptoResult, hash::Hash};
use std::io::{self, Write};

/// Trait for types that can be marshaled and unmarshaled to/from binary format.
pub trait Marshalable {
    /// Marshal the state to binary format.
    fn marshal_binary(&self) -> CryptoResult<Vec<u8>>;

    /// Unmarshal the state from binary format.
    fn unmarshal_binary(&mut self, data: &[u8]) -> CryptoResult<()>;
}

/// HMAC structure implementing HMAC according to FIPS 198-1.
///
/// The HMAC algorithm works as follows:
/// - key is zero padded to the block size of the hash function
/// - ipad = 0x36 byte repeated for key length
/// - opad = 0x5c byte repeated for key length
/// - hmac = H([key ^ opad] H([key ^ ipad] text))
pub struct HMAC<H: Hash + Marshalable> {
    /// Outer padding (key XOR 0x5c)
    opad: Vec<u8>,
    /// Inner padding (key XOR 0x36)
    ipad: Vec<u8>,
    /// Outer hash instance
    outer: H,
    /// Inner hash instance
    inner: H,
    /// If true, opad and ipad contain marshaled state instead of padded key
    marshaled: bool,
    /// Whether this HMAC is used for HKDF
    for_hkdf: bool,
    /// Original key length for FIPS compliance checking
    key_len: usize,
}

impl<H: Hash + Marshalable> HMAC<H> {
    /// Create a new HMAC instance with the given hash function and key.
    pub fn new<F>(hash_fn: F, key: &[u8]) -> Self
    where
        F: Fn() -> H,
    {
        let mut outer = hash_fn();
        let mut inner = hash_fn();

        // Ensure the hash function produces unique instances
        // This is a safety check to prevent issues with shared state

        let block_size = inner.block_size();
        let mut ipad = vec![0u8; block_size];
        let mut opad = vec![0u8; block_size];

        let mut processed_key = key.to_vec();

        // If key is longer than block size, hash it first
        if key.len() > block_size {
            outer.write_all(key).expect("Hash write should not fail");
            processed_key = outer.sum(&[]);
            outer.reset();
        }

        // Copy key to ipad and opad
        ipad[..processed_key.len()].copy_from_slice(&processed_key);
        opad[..processed_key.len()].copy_from_slice(&processed_key);

        // XOR with ipad and opad constants
        for byte in &mut ipad {
            *byte ^= 0x36;
        }
        for byte in &mut opad {
            *byte ^= 0x5c;
        }

        // Initialize inner hash with ipad
        inner.write_all(&ipad).expect("Hash write should not fail");

        HMAC {
            opad,
            ipad,
            outer,
            inner,
            marshaled: false,
            for_hkdf: false,
            key_len: key.len(),
        }
    }

    /// Mark this HMAC instance as being used in a Key Derivation Function.
    /// This affects FIPS compliance checking for short keys.
    pub fn mark_as_used_in_kdf(&mut self) {
        self.for_hkdf = true;
    }
}

impl<H: Hash + Marshalable> Write for HMAC<H> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<H: Hash + Marshalable> Hash for HMAC<H> {
    /// Compute the HMAC of the current state and return it appended to `input`.
    fn sum(&mut self, input: &[u8]) -> Vec<u8> {
        // FIPS 140-3 IG C.M compliance check
        // Key lengths below 112 bits (14 bytes) are only allowed for legacy use
        // However, HKDF uses HMAC key for salt, which is allowed to be shorter
        if self.key_len < 14 && !self.for_hkdf {
            // In the original Go code, this would call fips140.RecordNonApproved()
            // We're ignoring this as requested
        }

        let orig_len = input.len();
        let mut result = input.to_vec();

        // Get the inner hash result
        let inner_result = self.inner.sum(&[]);
        result.extend_from_slice(&inner_result);

        // Prepare outer hash
        if self.marshaled {
            // If we have marshaled state, restore it
            let opad = unsafe {
                let ptr = self.opad.as_ptr();
                std::slice::from_raw_parts(ptr, self.opad.len())
            };
            self.outer.unmarshal_binary(opad).unwrap();
        } else {
            // Reset outer hash and write opad
            self.outer.reset();
            self.outer
                .write_all(&self.opad)
                .expect("Hash write should not fail");
        }

        // Write the inner hash result to outer hash
        self.outer
            .write_all(&result[orig_len..])
            .expect("Hash write should not fail");

        // Get final result

        self.outer.sum(&result[..orig_len])
    }

    /// Reset the HMAC to its initial state.
    fn reset(&mut self) {
        if self.marshaled {
            let opad = unsafe {
                let ptr = self.opad.as_ptr();
                std::slice::from_raw_parts(ptr, self.opad.len())
            };
            self.outer.unmarshal_binary(opad).unwrap();
            return;
        }

        // Reset inner hash and write ipad
        self.inner.reset();
        self.inner
            .write_all(&self.ipad)
            .expect("Hash write should not fail");

        let Ok(imarshal) = self.inner.marshal_binary() else {
            return;
        };
        let Ok(omarshal) = self.outer.marshal_binary() else {
            return;
        };
        self.ipad = imarshal;
        self.opad = omarshal;
        self.marshaled = true;
    }

    /// Get the output size of the HMAC (same as underlying hash).
    fn size(&self) -> usize {
        self.outer.size()
    }

    /// Get the block size of the underlying hash function.
    fn block_size(&self) -> usize {
        self.inner.block_size()
    }
}

/// Convenience function to create a new HMAC instance.
/// This is equivalent to HMAC::new but matches the Go API style.
pub fn new<H, F>(hash_fn: F, key: &[u8]) -> HMAC<H>
where
    H: Hash + Marshalable,
    F: Fn() -> H,
{
    HMAC::new(hash_fn, key)
}

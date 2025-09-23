use tinyvec::ArrayVec;

use crate::{
    core::CoreWrite,
    error::CryptoResult,
    hash::{Hash, HashUser},
    utils::subtle::constant_time_eq,
};

use super::Marshalable;

/// TODO:
/// - add SmallVec with push and etc.
///   alloc memory when feature = "alloc", panic else.
const MAX_MARSHAL_SIZE: usize = 1024;
/// HMAC structure implementing HMAC according to FIPS 198-1.
///
/// The HMAC algorithm works as follows:
/// - key is zero padded to the block size of the hash function
/// - ipad = 0x36 byte repeated for key length
/// - opad = 0x5c byte repeated for key length
/// - hmac = H([key ^ opad] H([key ^ ipad] text))
pub struct HMAC<const N: usize, H: Hash<N> + Marshalable> {
    /// Outer padding (key XOR 0x5c)
    opad: ArrayVec<[u8; MAX_MARSHAL_SIZE]>,
    /// Inner padding (key XOR 0x36)
    ipad: ArrayVec<[u8; MAX_MARSHAL_SIZE]>,
    /// Outer hash instance
    outer: H,
    /// Inner hash instance
    inner: H,
    /// If true, opad and ipad contain marshaled state instead of padded key
    marshaled: bool,
}

pub fn equal(mac1: &[u8], mac2: &[u8]) -> bool {
    constant_time_eq(mac1, mac2)
}

impl<const N: usize, H: Hash<N> + Marshalable> HMAC<N, H> {
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
        let mut ipad: ArrayVec<[u8; MAX_MARSHAL_SIZE]> = ArrayVec::new();
        ipad.resize(block_size, 0);
        let mut opad: ArrayVec<[u8; MAX_MARSHAL_SIZE]> = ArrayVec::new();
        opad.resize(block_size, 0);

        let mut processed_key = key.to_vec();

        // If key is longer than block size, hash it first
        if key.len() > block_size {
            outer.write_all(key).expect("Hash write should not fail");
            processed_key = outer.sum().to_vec();
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
        }
    }
}

impl<const N: usize, H: Hash<N> + Marshalable> CoreWrite for HMAC<N, H> {
    fn write(&mut self, buf: &[u8]) -> CryptoResult<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> CryptoResult<()> {
        self.inner.flush()
    }
}

impl<const N: usize, H: Hash<N> + Marshalable> HashUser for HMAC<N, H> {
    /// Reset the HMAC to its initial state.
    fn reset(&mut self) {
        if self.marshaled {
            self.inner.unmarshal_binary(&self.ipad).unwrap();
            return;
        }

        // Reset inner hash and write ipad
        self.inner.reset();
        self.inner
            .write_all(&self.ipad)
            .expect("Hash write should not fail");

        let mut imarshal: ArrayVec<[u8; MAX_MARSHAL_SIZE]> = ArrayVec::new();
        imarshal.resize(self.inner.marshal_size(), 0);
        let Ok(_) = self.inner.marshal_into(&mut imarshal) else {
            return;
        };

        self.outer.reset();
        self.outer
            .write_all(&self.opad)
            .expect("Hash write should not fail");
        let mut omarshal: ArrayVec<[u8; MAX_MARSHAL_SIZE]> = ArrayVec::new();
        omarshal.resize(self.inner.marshal_size(), 0);
        let Ok(_) = self.outer.marshal_into(&mut omarshal) else {
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

impl<const N: usize, H: Hash<N> + Marshalable> Hash<N> for HMAC<N, H> {
    /// Compute the HMAC of the current state and return it.
    fn sum(&mut self) -> [u8; N] {
        // Prepare outer hash
        if self.marshaled {
            // If we have marshaled state, restore it
            self.outer.unmarshal_binary(&self.opad).unwrap();
        } else {
            // Reset outer hash and write opad
            self.outer.reset();
            self.outer
                .write_all(&self.opad)
                .expect("Hash write should not fail");
        }

        // Write the inner hash result to outer hash
        self.outer
            .write_all(&self.inner.sum())
            .expect("Hash write should not fail");

        self.outer.sum()
    }
}

/// Convenience function to create a new HMAC instance.
/// This is equivalent to HMAC::new but matches the Go API style.
pub fn new<const N: usize, H, F>(hash_fn: F, key: &[u8]) -> HMAC<N, H>
where
    H: Hash<N> + Marshalable,
    F: Fn() -> H,
{
    HMAC::new(hash_fn, key)
}

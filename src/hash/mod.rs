#[cfg(feature = "alloc")]
mod message_digest;
#[cfg(feature = "alloc")]
pub use message_digest::*;

use crate::core::CoreWrite;

/// Common interface for all hash algorithms.
pub trait HashUser {
    /// Reset resets the Hash to its initial state.
    fn reset(&mut self);
    /// Size returns the number of bytes Sum will return.
    fn size(&self) -> usize;
    /// BlockSize returns the hash's underlying block size.
    /// The Write method must be able to accept any amount
    /// of data, but it may operate more efficiently if all writes
    /// are a multiple of the block size.
    fn block_size(&self) -> usize;
}

/// A trait for hash algorithms with fixed-length output.
pub trait Hash<const N: usize>: CoreWrite + HashUser {
    /// Computes the hash value and returns it as a fixed-size array.
    ///
    /// # Returns
    /// An array of `N` bytes containing the computed hash value.
    fn sum(&mut self) -> [u8; N];
}

/// A trait for hash algorithms with variable-length output.
pub trait HashVariable: CoreWrite + HashUser {
    /// Computes the hash value and stores it in the provided buffer.
    ///
    /// # Parameters
    /// - `sum`: A mutable byte slice where the computed hash will be stored.
    ///
    /// # Returns
    /// The number of bytes written to the buffer.
    fn sum(&mut self, sum: &mut [u8]) -> usize;

    /// Computes the hash value and returns it as a vector.
    ///
    /// This method allocates a vector with capacity equal to the hash size,
    /// computes the hash, and returns the result.
    ///
    /// # Returns
    /// A vector containing the computed hash value.
    #[cfg(feature = "alloc")]
    fn sum_vec(&mut self) -> alloc::vec::Vec<u8> {
        use alloc::vec;
        let mut ret = vec![0u8; self.size()];
        let len = self.sum(&mut ret);
        ret.reserve(len);
        ret
    }
}

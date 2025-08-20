mod erased;
pub use erased::*;

/// Common interface for all hash algorithms.
pub trait HashUser {
    fn reset(&mut self);
    fn size(&self) -> usize;
    fn block_size(&self) -> usize;
}

/// A trait for hash algorithms with fixed-length output.
pub trait Hash<const N: usize>: std::io::Write + HashUser {
    /// Computes the hash value and returns it as a fixed-size array.
    ///
    /// # Returns
    /// An array of `N` bytes containing the computed hash value.
    fn sum(&mut self) -> [u8; N];
}

/// A trait for hash algorithms with variable-length output.
pub trait HashVariable: std::io::Write + HashUser {
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
    fn sum_vec(&mut self) -> Vec<u8> {
        let mut ret = vec![0u8; self.size()];
        let len = self.sum(&mut ret);
        ret.reserve(len);
        ret
    }
}

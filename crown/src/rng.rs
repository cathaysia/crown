//! Random byte source trait used by key generation and randomized padding.

/// Random byte source used by key generation and randomized padding.
pub trait Rng {
    /// Fill `out` with random bytes.
    fn fill_bytes(&mut self, out: &mut [u8]);
}

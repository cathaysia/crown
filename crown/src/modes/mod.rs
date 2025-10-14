//! # Cipher Modes of Operation
//!
//! This module provides various modes of operation for block ciphers, including both
//! block modes and stream modes. These modes transform block ciphers into different
//! operational forms, enabling block ciphers to work as stream ciphers or enhanced block ciphers.

#[cfg(feature = "alloc")]
pub mod cbc;
#[cfg(feature = "alloc")]
pub mod cfb;
#[cfg(feature = "alloc")]
pub mod ctr;
#[cfg(feature = "alloc")]
pub mod ecb;

#[cfg(feature = "alloc")]
pub mod ofb;

#[cfg(test)]
pub mod common_test;

/// A BlockMode represents a block cipher running in a block-based mode (CBC,
/// ECB etc).
pub trait BlockMode {
    /// BlockSize returns the mode's block size.
    fn block_size(&self) -> usize;

    /// encrypts or decrypts a number of blocks. The length of
    /// src must be a multiple of the block size.
    ///
    /// If len(dst) < len(src), CryptBlocks should panic. It is acceptable
    /// to pass a dst bigger than src, and in that case, CryptBlocks will
    /// only update dst[:len(src)] and will not touch the rest of dst.
    ///
    /// Multiple calls to CryptBlocks behave as if the concatenation of
    /// the src buffers was passed in a single run. That is, BlockMode
    /// maintains state and does not reset at each CryptBlocks call.
    fn encrypt(&mut self, inout: &mut [u8]);
    fn decrypt(&mut self, inout: &mut [u8]);
}

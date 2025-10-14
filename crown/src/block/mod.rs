//! # Block Cipher Implementations
//!
//! This module provides low-level implementations of various block cipher algorithms.
//! Block ciphers encrypt data in fixed-size blocks and form the foundation for
//! higher-level cryptographic operations.
//!
//! These are primitive cryptographic building blocks that require careful handling.
//! For most use cases, consider using the high-level interfaces in the [`crate::envelope`] module instead.

pub mod aes;
pub mod blowfish;
pub mod camellia;
pub mod cast5;
pub mod des;
pub mod idea;
pub mod rc2;
pub mod rc5;
pub mod rc6;
pub mod skipjack;
pub mod sm4;
pub mod tea;
pub mod twofish;
pub mod xtea;

pub const MAX_BLOCK_SIZE: usize = 144;

/// A Block represents an implementation of block cipher
/// using a given key. It provides the capability to encrypt
/// or decrypt individual blocks. The mode implementations
/// extend that capability to streams of blocks.
pub trait BlockCipher {
    /// the cipher's block size(bytes).
    fn block_size(&self) -> usize;

    /// encrypt a block.
    fn encrypt_block(&self, inout: &mut [u8]);

    /// decrypt a block.
    fn decrypt_block(&self, inout: &mut [u8]);
}

pub trait BlockCipherMarker {}

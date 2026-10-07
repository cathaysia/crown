//! # Block Cipher Implementations
//!
//! This module provides low-level implementations of various block cipher algorithms.
//! Block ciphers encrypt data in fixed-size blocks and form the foundation for
//! higher-level cryptographic operations.
//!
//! These are primitive cryptographic building blocks that require careful handling.
//! For most use cases, consider using the high-level interfaces in the [`crate::envelope`] module instead.

pub mod aes;
pub mod anubis;
pub mod aria;
pub mod blowfish;
pub mod camellia;
pub mod cast5;
pub mod des;
pub mod idea;
pub mod kasumi;
pub mod khazad;
pub mod kseed;
pub mod multi2;
pub mod noekeon;
pub mod rc2;
pub mod rc5;
pub mod rc6;
pub mod safer;
pub mod serpent;
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

    /// Optional fused hook over a whole multiple of the block size, in place
    /// (ECB uses it to reach the assembly routines that interleave blocks).
    /// Returning `false` tells the caller to fall back to the per-block
    /// methods.
    fn bulk_crypt(&self, _inout: &mut [u8], _enc: bool) -> bool {
        false
    }
}

pub trait BlockCipherMarker {}

//! # High-Level Cryptographic Interface
//!
//! This module provides a unified, high-level interface for cryptographic operations,
//! abstracting away the complexity of individual algorithms and modes.
//!
//! ## Modules
//!
//! - [`EvpHash`] - Unified hash function interface supporting MD5, SHA-1, SHA-2, SHA-3, BLAKE2, and HMAC variants
//! - [`EvpAeadCipher`] - Authenticated encryption with associated data (AEAD) for secure encryption
//! - [`EvpStreamCipher`] - Stream cipher interface for continuous encryption/decryption
//! - [`EvpBlockCipher`] - Block cipher interface with padding support for fixed-size data blocks

#![cfg(feature = "alloc")]

mod evp_hash;
pub use evp_hash::*;

mod evp_aead;
pub use evp_aead::*;

mod evp_stream;
pub use evp_stream::*;

mod evp_block;
pub use evp_block::*;

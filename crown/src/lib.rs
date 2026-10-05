#![allow(clippy::needless_range_loop)]
//! # crown Cryptographic Library
//!
//! A comprehensive cryptographic library designed to provide first-class documentation,
//! easy-to-use APIs, and wide deployment compatibility across different environments.
//!
//! ## 🚀 Quick Start
//!
//! For most use cases, we recommend using the high-level [`envelope`] module, which provides
//! unified interfaces for common cryptographic operations:
//!
//! ```rust
//! use crown::envelope::*;
//! use crown::core::CoreWrite;
//!
//! // Hash operations
//! let mut hasher = EvpHash::new_sha256()?;
//! hasher.write(b"hello world")?;
//! let digest = hasher.sum();
//!
//! // AEAD encryption
//! # let key = [0u8; 16];
//! # let nonce = [0u8; 12];
//! # let mut data = [0u8; 1024];
//! let cipher = EvpAeadCipher::new_aes_gcm(&key)?;
//! cipher.seal_in_place_separate_tag(&mut data, &nonce, &[])?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## 📚 Library Structure
//!
//! - **[`envelope`]** - High-level unified interfaces (recommended for most users)
//! - **[`aead`]** - Authenticated encryption with associated data implementations
//! - **[`block`]** - Low-level block cipher implementations
//! - **[`stream`]** - Stream cipher implementations
//! - **[`hash`]** - Cryptographic hash functions (fixed and variable length)
//! - **[`mac`]** - Message authentication codes
//! - **[`modes`]** - Cipher modes of operation for block ciphers
//! - **[`padding`]** - Padding schemes for block alignment
//! - **[`kdf`]** - Key derivation functions
//! - **[`password_hash`]** - Specialized password hashing functions
//!
//! ## 🔒 Security Recommendations
//!
//! Users should understand which algorithms are secure and which are not. For beginners,
//! we recommend the following modern, secure algorithms:
//!
//! - **Encryption**: Always use ChaCha20-Poly1305 or AES-GCM for authenticated encryption
//! - **Hashing**: Use SHA-256, SHA-3, or BLAKE2 for general purposes
//! - **Password Hashing**: Use Argon2, scrypt, or bcrypt for password storage
//! <div class="warning">
//! Avoid legacy algorithms like MD5, SHA-1, DES, and RC4 which are cryptographically broken.
//! </div>
//!
//! ## Design Goals
//!
//! - **Ease of Use**: Simple, intuitive APIs with comprehensive documentation
//! - **Performance**: Optimized implementations with platform-specific acceleration
//! - **Security**: Constant-time operations and secure defaults
//! - **Compatibility**: Support for `no_std` environments and various platforms
//!
//! ## Feature flags
#![doc = document_features::document_features!()]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod aead;
#[cfg(feature = "alloc")]
pub mod asn1;
pub mod block;
pub mod bn;
#[cfg(feature = "alloc")]
pub mod cms;
pub mod curve448;
pub mod dh;
pub mod dsa;
pub mod ec;
pub mod ecdh;
pub mod ecdsa;
pub mod ed25519;
#[cfg(feature = "alloc")]
pub mod ed448;
pub mod envelope;
pub mod hash;
pub mod kdf;
pub mod mac;
#[cfg(feature = "alloc")]
pub mod ml_dsa;
#[cfg(feature = "alloc")]
pub mod ml_kem;
pub mod modes;
#[cfg(feature = "alloc")]
pub mod ocsp;
pub mod otp;
pub mod padding;
#[cfg(feature = "password")]
pub mod password_hash;
#[cfg(feature = "alloc")]
pub mod pkcs12;
#[cfg(feature = "alloc")]
pub mod pkcs7;
#[cfg(feature = "alloc")]
pub mod rsa;
#[cfg(feature = "alloc")]
pub mod slh_dsa;
pub mod sm2;
pub mod stream;
pub mod x25519;
pub mod x448;
#[cfg(feature = "alloc")]
pub mod x509;

pub mod core;

pub mod cuda;

#[cfg(feature = "alloc")]
pub mod drbg;
pub mod error;
pub mod rng;

#[cfg(not(feature = "unstable"))]
mod utils;
#[cfg(feature = "unstable")]
pub mod utils;

#[cfg(feature = "unstable")]
mod simd;

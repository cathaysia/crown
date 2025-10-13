//! # Key Derivation Functions (KDF)
//!
//! This module provides implementations of key derivation functions that generate
//! cryptographic keys from input key material such as passwords or shared secrets.

#[cfg(feature = "std")]
pub mod hkdf;

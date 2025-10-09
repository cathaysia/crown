//! # Password Hashing Functions
//!
//! This module provides specialized hash functions designed for password storage
//! and verification. These functions are intentionally slow and memory-hard to
//! resist brute-force attacks.

#[cfg(feature = "alloc")]
pub mod argon2;
#[cfg(feature = "std")]
pub mod bcrypt;
#[cfg(feature = "alloc")]
pub mod pbkdf2;
#[cfg(feature = "alloc")]
pub mod scrypt;

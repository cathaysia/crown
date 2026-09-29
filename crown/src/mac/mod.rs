//! # Message Authentication Code (MAC)
//!
//! This module provides implementations of message authentication codes that ensure
//! data integrity and authenticity using cryptographic keys.

pub mod cmac;
pub mod gmac;
pub mod hmac;
#[cfg(feature = "alloc")]
pub mod kmac;
pub mod poly1305;
pub mod siphash;

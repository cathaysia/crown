//! ## Feature flags
#![doc = document_features::document_features!()]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod aead;
pub mod block;
pub mod envelope;
pub mod hash;
pub mod kdf;
pub mod mac;
pub mod modes;
pub mod padding;
pub mod password_hash;
pub mod stream;

pub mod core;

pub mod cuda;

pub mod error;

pub mod utils;

mod simd;

#[cfg(feature = "std")]
pub use utils::rand;

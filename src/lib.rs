//! ## Feature flags
#![doc = document_features::document_features!()]
//! ## [BlockCipher](crate::cipher::BlockCipher)
//!
//! - [aes](crate::aes::Aes)
//! - [blowfish](crate::blowfish::Blowfish)
//! - [cast5](crate::cast5::Cast5)
//! - [chacha20/xchacha20](crate::chacha20::Chacha20)
//! - [des](crate::des::Des)
//! - [rc2](crate::rc2::Rc2)
//! - [rc5](crate::rc5::Rc5)
//! - [tea](crate::tea::Tea)
//! - [twofish](crate::twofish::Twofish)
//! - [xtea](crate::xtea::Xtea)
//! - [rc6](crate::rc6::Rc6)
//!
//! ## [BlockMode](crate::cipher::BlockMode)
//!
//! - [cbc](crate::cipher::cbc)
//! - [cfb](crate::cipher::cfb)
//! - [ctr](crate::cipher::ctr)
//! - [ofb](crate::cipher::ofb)
//! - [gcm](crate::cipher::gcm)
//!
//! ## [Aead](crate::cipher::Aead)
//!
//! - [chacha20poly1305/xchacha20poly1305](crate::chacha20poly1305::ChaCha20Poly1305)
//!
//! ### [StreamCipher](crate::cipher::StreamCipher)
//!
//! - [rc4](crate::rc4::Rc4)
//! - [sala20](crate::sala20::Sala20)
//!
//! ### [Hash](crate::hash::Hash)
//!
//! - [hmac]
//! - [bcrypt]
//! - [blake2b]
//! - [blake2s]
//! - [md4]
//! - [md5]
//! - [sha1]
//! - sha2: [sha224](crate::sha256::new224), [sha256](crate::sha256::new256), [sha384](crate::sha512::sum384), [sha512](crate::sha512::sum512), [sha512/224](crate::sha512::sum512_224), [sha512/256](crate::sha512::sum512_256).
//! - [sha3]: [sha3/224](crate::sha3::sum224), [sha3/256](crate::sha3::sum256), [sha3/384](crate::sha3::sum384), [sha3/512](crate::sha3::sum512),
//! - shake: [shake128](crate::sha3::sum_shake128), [shake256](crate::sha3::sum_shake256)
//!
//! ## [HashVariable](crate::hash::HashVariable)
//!
//! - [blake2b](crate::blake2b::Blake2bVariable)
//!
//! ## Key derivation algorithm
//!
//! - [argon2]
//! - [hkdf]
//! - [pbkdf2]
//! - [scrypt]

#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod argon2;
#[cfg(feature = "std")]
pub mod bcrypt;
pub mod blake2b;
pub mod blake2s;
pub mod chacha20poly1305;
pub mod des;
pub mod hash;
#[cfg(feature = "std")]
pub mod hkdf;
pub mod hmac;
pub mod idea;
pub mod md2;
pub mod md4;
pub mod md5;
#[cfg(feature = "alloc")]
pub mod pbkdf2;
#[cfg(feature = "alloc")]
pub mod scrypt;
pub mod sha1;
pub mod sha256;
pub mod sha3;
pub mod sha512;

pub mod aes;
pub mod blowfish;
pub mod camellia;
pub mod cast5;
pub mod chacha20;
pub mod cipher;
pub mod core;
pub mod poly1305;
pub mod rc2;
pub mod rc4;
pub mod rc5;
pub mod rc6;
pub mod sala20;
pub mod tea;
pub mod twofish;
pub mod xtea;

#[cfg(feature = "alloc")]
pub mod envelope;

#[cfg(feature = "cuda")]
pub mod cuda;

pub mod error;

pub mod utils;

mod simd;

#[cfg(feature = "std")]
pub use utils::rand;

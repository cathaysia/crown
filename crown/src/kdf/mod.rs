//! # Key Derivation Functions (KDF)
//!
//! This module provides implementations of key derivation functions that generate
//! cryptographic keys from input keying material such as passwords or shared secrets.
//!
//! The KDFs ported from OpenSSL's default provider take their digest as a
//! runtime parameter. They are generic over a [`HashFactory`] (a function
//! producing a fresh type-erased hash) or an [`HmacFactory`] (a function
//! producing a fresh type-erased keyed hash), e.g.:
//!
//! ```
//! use crown::envelope::EvpHash;
//! use crown::kdf::sshkdf::{self, SshKdfType};
//!
//! let okm = sshkdf::derive(
//!     EvpHash::new_sha256,
//!     b"secret shared key",
//!     b"exchange hash",
//!     b"session id",
//!     SshKdfType::A,
//!     16,
//! )
//! .unwrap();
//! ```

#[cfg(feature = "alloc")]
pub mod hkdf;

#[cfg(feature = "alloc")]
pub mod ikev2kdf;
#[cfg(feature = "alloc")]
pub mod kbkdf;
#[cfg(feature = "alloc")]
pub mod krb5kdf;
#[cfg(feature = "alloc")]
pub mod pbkdf1;
#[cfg(feature = "alloc")]
pub mod pkcs12kdf;
#[cfg(feature = "alloc")]
pub mod srtpkdf;
#[cfg(feature = "alloc")]
pub mod sshkdf;
#[cfg(feature = "alloc")]
pub mod sskdf;
#[cfg(feature = "alloc")]
pub mod tls1_prf;
#[cfg(feature = "alloc")]
pub mod x942kdf;

#[cfg(feature = "alloc")]
use crate::envelope::EvpHash;

#[cfg(feature = "alloc")]
use crate::error::CryptoResult;

/// Factory creating a fresh type-erased hash, used by KDFs that take the
/// digest as a runtime parameter. The `EvpHash::new_*` constructors have
/// this shape, e.g. `EvpHash::new_sha256`.
#[cfg(feature = "alloc")]
pub type HashFactory = fn() -> CryptoResult<EvpHash>;

/// Factory creating a fresh type-erased HMAC keyed with the given key. The
/// `EvpHash::new_*_hmac` constructors have this shape, e.g.
/// `EvpHash::new_sha256_hmac`.
#[cfg(feature = "alloc")]
pub type HmacFactory = fn(&[u8]) -> CryptoResult<EvpHash>;

//! ASN.1/DER support for the PKI modules ([`crate::x509`], [`crate::pkcs7`],
//! [`crate::pkcs12`]).
//!
//! - [`der`] provides the TLV reader/writer, including the tag helpers and
//!   the `AlgorithmIdentifier` convenience encoder.
//! - [`oid`] provides [`oid::ObjectIdentifier`] plus the OID constants used
//!   throughout the PKI modules.
//! - [`time`] provides [`time::Asn1Time`] for UTCTime/GeneralizedTime.
//! - [`pem`] provides PEM armour with a built-in base64 codec.
//!
//! ```
//! use crown::asn1::der::{self, Reader};
//! use crown::oid;
//!
//! let alg = der::algorithm_identifier(&oid!(1, 2, 840, 113549, 1, 1, 11), Some(&der::null()));
//! let mut r = Reader::new(&alg);
//! let mut seq = r.read_sequence().unwrap();
//! assert_eq!(seq.read_oid().unwrap().to_dotted_string(), "1.2.840.113549.1.1.11");
//! seq.read_null().unwrap();
//! # Ok::<(), crown::error::CryptoError>(())
//! ```

pub mod der;
pub mod oid;
pub mod pem;
pub mod time;

pub use der::Reader;
pub use oid::ObjectIdentifier;
pub use pem::PemBlock;
pub use time::Asn1Time;

#[cfg(test)]
mod tests;

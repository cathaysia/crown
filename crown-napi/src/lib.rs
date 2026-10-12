#[macro_use]
extern crate napi_derive;

use napi::bindgen_prelude::*;

pub mod evp_aead;
pub mod evp_block;
pub mod evp_hash;
pub mod evp_kdf;
pub mod evp_kem;
pub mod evp_mac;
pub mod evp_misc;
pub mod evp_pki;
pub mod evp_pq_sign;
pub mod evp_sign;
pub mod evp_stream;
pub mod evp_xts;

pub fn crypto_err(context: &str, e: impl std::fmt::Debug) -> Error {
    Error::new(Status::GenericFailure, format!("{context}: {e:?}"))
}

//! HMAC implementation according to FIPS 198-1.
//!
//! FIPS 198-1: <https://doi.org/10.6028/NIST.FIPS.198-1>

#[cfg(test)]
mod tests;

use crate::error::CryptoResult;

#[cfg(feature = "alloc")]
mod imp;
#[cfg(feature = "alloc")]
pub use imp::*;

/// Trait for types that can be marshaled and unmarshaled to/from binary format.
pub trait Marshalable {
    fn marshal_size(&self) -> usize;

    /// Marshal the state to binary format.
    fn marshal_into(&self, out: &mut [u8]) -> CryptoResult<usize>;

    /// Unmarshal the state from binary format.
    fn unmarshal_binary(&mut self, data: &[u8]) -> CryptoResult<()>;

    #[cfg(feature = "alloc")]
    fn marshal_binary(&self) -> CryptoResult<Vec<u8>> {
        let mut out = vec![0u8; self.marshal_size()];
        self.marshal_into(&mut out)?;
        Ok(out)
    }
}

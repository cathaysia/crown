#[cfg(feature = "alloc")]
pub(crate) mod cipher;
pub(crate) mod consts;

#[cfg(feature = "alloc")]
pub use cipher::*;

#[cfg(test)]
mod tests;

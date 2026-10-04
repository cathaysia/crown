//! P-256 nistz256 assembly port.
//!
//! [`driver`] routes `crate::ec`'s P-256 scalar multiplication through the
//! assembly when the `asm` feature is on. See `NOTES.md` for the source
//! path, config pins, symbol list and register/field layout.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub mod asm;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub(crate) mod driver;

#[cfg(test)]
mod tests;

//! P-256 nistz256 assembly port.
//!
//! [`driver`] routes `crate::ec`'s P-256 scalar multiplication through the
//! assembly when the `asm` feature is on. See `NOTES.md` for the source
//! path, config pins, symbol list and register/field layout.

#[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
pub mod asm;

#[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
pub(crate) mod driver;

#[cfg(test)]
mod tests;

//! P-256 nistz256 assembly port (translated, not yet dispatched).
//!
//! See `NOTES.md` for the source path, config pins, symbol list and
//! register/field layout.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub mod asm;

#[cfg(test)]
mod tests;

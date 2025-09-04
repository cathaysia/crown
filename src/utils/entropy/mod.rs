//! Package entropy provides the passive entropy source for the FIPS 140-3
//! module. It is only used in FIPS mode by [crypto/internal/fips140/drbg.Read].
//!
//! This complies with IG 9.3.A, Additional Comment 12, which until January 1,
//! 2026 allows new modules to meet an [earlier version] of Resolution 2(b):
//! "A software module that contains an approved DRBG that receives a LOAD
//! command (or its logical equivalent) with entropy obtained from [...] inside
//! the physical perimeter of the operational environment of the module [...]."
//!
//! Distributions that have their own SP 800-90B entropy source should replace
//! this package with their own implementation.
//!
//! [earlier version]: https://csrc.nist.gov/CSRC/media/Projects/cryptographic-module-validation-program/documents/IG%209.3.A%20Resolution%202b%5BMarch%2026%202024%5D.pdf

use crate::utils::sysrand;

/// Depleted notifies the entropy source that the entropy in the module is
/// "depleted" and provides the callback for the LOAD command.
#[allow(dead_code)]
pub fn depleted<T>(load: T)
where
    T: Fn(&[u8; 48]),
{
    let mut entropy = [0u8; 48];
    sysrand::fill_bytes(&mut entropy);
    load(&entropy);
}

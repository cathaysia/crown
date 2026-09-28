//! Curve448 shared arithmetic for [`crate::x448`] and [`crate::ed448`].
//!
//! The prime field `GF(2^448 - 2^224 - 1)` lives in [`fe`]; X448 uses it
//! through a Montgomery ladder and Ed448 through twisted-Edwards group
//! operations.

pub mod fe;

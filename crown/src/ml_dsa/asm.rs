//! ML-DSA NTT/INTT AVX2 assembly (upstream `ml_dsa_ntt-x86_64.pl`).
//!
//! The port is a frozen build of the upstream perlasm output (the vendored
//! 3.5.8 reference tree predates the script); see `ntt_x86_64.ts` for the
//! provenance and regeneration command. The routines operate on the
//! FIPS 204 Montgomery-domain coefficient arrays that [`super::ntt`]
//! already uses, with the same `ZETAS_MONTGOMERY` table.
//!
//! `ml_dsa_ntt_avx2_capable` performs the CPU feature check (AVX2 + BMI2)
//! at runtime.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/ml_dsa/ntt_x86_64.ts"),
    options(att_syntax)
);

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
extern "C" {
    fn ml_dsa_ntt_avx2_capable() -> i32;
    fn ml_dsa_poly_ntt_avx2(p: *mut u32, zetas: *const u32);
    fn ml_dsa_poly_ntt_inverse_avx2(p: *mut u32);
    fn ml_dsa_poly_ntt_mult_avx2(a: *const u32, b: *const u32, out: *mut u32);
}

/// Whether the CPU supports the AVX2 routines.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub(crate) fn capable() -> bool {
    unsafe { ml_dsa_ntt_avx2_capable() != 0 }
}

/// Forward NTT in place (AVX2), using the FIPS 204 Montgomery zeta table.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub(crate) fn ntt(p: &mut [u32; super::params::N], zetas: &[u32; 256]) {
    unsafe { ml_dsa_poly_ntt_avx2(p.as_mut_ptr(), zetas.as_ptr()) };
}

/// Inverse NTT in place (AVX2).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub(crate) fn ntt_inverse(p: &mut [u32; super::params::N]) {
    unsafe { ml_dsa_poly_ntt_inverse_avx2(p.as_mut_ptr()) };
}

/// Pointwise Montgomery multiplication (AVX2).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub(crate) fn ntt_mult(
    lhs: &[u32; super::params::N],
    rhs: &[u32; super::params::N],
    out: &mut [u32; super::params::N],
) {
    unsafe { ml_dsa_poly_ntt_mult_avx2(lhs.as_ptr(), rhs.as_ptr(), out.as_mut_ptr()) };
}

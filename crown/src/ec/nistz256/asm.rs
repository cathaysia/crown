#![allow(dead_code, unused_imports)]
//! ecp_nistz256 assembly (ecp_nistz256-x86_64.pl) for x86_64.
//!
//! OpenSSL `crypto/ec/asm/ecp_nistz256-x86_64.pl` provides the P-256
//! field, Montgomery, order and Jacobian point primitives used by
//! `crypto/ec/ecp_nistz256.c`.  This module exposes them through thin
//! safe wrappers; `crate::ec::nistz256::driver` routes P-256 scalar
//! multiplication through them under `feature = "asm"`.
//!
//! C ABI (`$win64=0`, unix SysV):
//!
//! ```text
//! void ecp_nistz256_add(uint64_t res[4], const uint64_t a[4], const uint64_t b[4]);
//! void ecp_nistz256_sub(uint64_t res[4], const uint64_t a[4], const uint64_t b[4]);
//! void ecp_nistz256_neg(uint64_t res[4], const uint64_t a[4]);
//! void ecp_nistz256_mul_by_2(uint64_t res[4], const uint64_t a[4]);
//! void ecp_nistz256_div_by_2(uint64_t res[4], const uint64_t a[4]);
//! void ecp_nistz256_mul_by_3(uint64_t res[4], const uint64_t a[4]);
//!
//! void ecp_nistz256_to_mont(uint64_t res[4], const uint64_t in[4]);
//! void ecp_nistz256_from_mont(uint64_t res[4], const uint64_t in[4]);
//! void ecp_nistz256_mul_mont(uint64_t res[4], const uint64_t a[4], const uint64_t b[4]);
//! void ecp_nistz256_sqr_mont(uint64_t res[4], const uint64_t a[4]);
//!
//! void ecp_nistz256_ord_mul_mont(uint64_t res[4], const uint64_t a[4], const uint64_t b[4]);
//! void ecp_nistz256_ord_sqr_mont(uint64_t res[4], const uint64_t a[4], uint64_t rep);
//!
//! void ecp_nistz256_scatter_w5(void *val, const void *in_t, int index);
//! void ecp_nistz256_gather_w5(void *val, const void *in_t, int index);
//! void ecp_nistz256_scatter_w7(void *val, const void *in_t, int index);
//! void ecp_nistz256_gather_w7(void *val, const void *in_t, int index);
//! void ecp_nistz256_avx2_gather_w7(void *val, const void *in_t, int index);
//!
//! void ecp_nistz256_point_double(uint64_t r[12], const uint64_t a[12]);
//! void ecp_nistz256_point_add(uint64_t r[12], const uint64_t a[12], const uint64_t b[12]);
//! void ecp_nistz256_point_add_affine(uint64_t r[12], const uint64_t a[12], const uint64_t b[8]);
//! ```
//!
//! Field elements are 4 little-endian 64-bit limbs.  A Jacobian point is
//! three field elements (X, Y, Z), 12 limbs / 96 bytes.  An affine point
//! is two field elements (X, Y), 8 limbs / 64 bytes.  Montgomery domain
//! uses R = 2^256 mod p for the field and R = 2^256 mod n for the order.
//!
//! `ecp_nistz256_precomputed` is a 64-byte-aligned rodata table of 37
//! rows x 64 affine points (the windowed generator multiples).

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/ec/nistz256/x86_64.ts"),
    options(att_syntax)
);

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
extern "C" {
    fn ecp_nistz256_add(res: *mut u64, a: *const u64, b: *const u64);
    fn ecp_nistz256_sub(res: *mut u64, a: *const u64, b: *const u64);
    fn ecp_nistz256_neg(res: *mut u64, a: *const u64);
    fn ecp_nistz256_mul_by_2(res: *mut u64, a: *const u64);
    fn ecp_nistz256_div_by_2(res: *mut u64, a: *const u64);
    fn ecp_nistz256_mul_by_3(res: *mut u64, a: *const u64);

    fn ecp_nistz256_to_mont(res: *mut u64, inn: *const u64);
    fn ecp_nistz256_from_mont(res: *mut u64, inn: *const u64);
    fn ecp_nistz256_mul_mont(res: *mut u64, a: *const u64, b: *const u64);
    fn ecp_nistz256_sqr_mont(res: *mut u64, a: *const u64);

    fn ecp_nistz256_ord_mul_mont(res: *mut u64, a: *const u64, b: *const u64);
    fn ecp_nistz256_ord_sqr_mont(res: *mut u64, a: *const u64, rep: u64);

    fn ecp_nistz256_scatter_w5(val: *mut u64, in_t: *const u64, index: i32);
    fn ecp_nistz256_gather_w5(val: *mut u64, in_t: *const u64, index: i32);
    fn ecp_nistz256_scatter_w7(val: *mut u64, in_t: *const u64, index: i32);
    fn ecp_nistz256_gather_w7(val: *mut u64, in_t: *const u64, index: i32);
    fn ecp_nistz256_avx2_gather_w7(val: *mut u64, in_t: *const u64, index: i32);

    fn ecp_nistz256_point_double(r: *mut u64, a: *const u64);
    fn ecp_nistz256_point_add(r: *mut u64, a: *const u64, b: *const u64);
    fn ecp_nistz256_point_add_affine(r: *mut u64, a: *const u64, b: *const u64);
}

/// Size of one field element in limbs.
pub const P256_LIMBS: usize = 4;
/// Size of a Jacobian point in limbs (X, Y, Z).
pub const P256_POINT_LIMBS: usize = 12;
/// Size of an affine point in limbs (X, Y).
pub const P256_POINT_AFFINE_LIMBS: usize = 8;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut res = [0u64; 4];
    unsafe { ecp_nistz256_add(res.as_mut_ptr(), a.as_ptr(), b.as_ptr()) };
    res
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut res = [0u64; 4];
    unsafe { ecp_nistz256_sub(res.as_mut_ptr(), a.as_ptr(), b.as_ptr()) };
    res
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn neg(a: &[u64; 4]) -> [u64; 4] {
    let mut res = [0u64; 4];
    unsafe { ecp_nistz256_neg(res.as_mut_ptr(), a.as_ptr()) };
    res
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn mul_by_2(a: &[u64; 4]) -> [u64; 4] {
    let mut res = [0u64; 4];
    unsafe { ecp_nistz256_mul_by_2(res.as_mut_ptr(), a.as_ptr()) };
    res
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn div_by_2(a: &[u64; 4]) -> [u64; 4] {
    let mut res = [0u64; 4];
    unsafe { ecp_nistz256_div_by_2(res.as_mut_ptr(), a.as_ptr()) };
    res
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn mul_by_3(a: &[u64; 4]) -> [u64; 4] {
    let mut res = [0u64; 4];
    unsafe { ecp_nistz256_mul_by_3(res.as_mut_ptr(), a.as_ptr()) };
    res
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn to_mont(a: &[u64; 4]) -> [u64; 4] {
    let mut res = [0u64; 4];
    unsafe { ecp_nistz256_to_mont(res.as_mut_ptr(), a.as_ptr()) };
    res
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn from_mont(a: &[u64; 4]) -> [u64; 4] {
    let mut res = [0u64; 4];
    unsafe { ecp_nistz256_from_mont(res.as_mut_ptr(), a.as_ptr()) };
    res
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn mul_mont(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut res = [0u64; 4];
    unsafe { ecp_nistz256_mul_mont(res.as_mut_ptr(), a.as_ptr(), b.as_ptr()) };
    res
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn sqr_mont(a: &[u64; 4]) -> [u64; 4] {
    let mut res = [0u64; 4];
    unsafe { ecp_nistz256_sqr_mont(res.as_mut_ptr(), a.as_ptr()) };
    res
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn ord_mul_mont(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut res = [0u64; 4];
    unsafe { ecp_nistz256_ord_mul_mont(res.as_mut_ptr(), a.as_ptr(), b.as_ptr()) };
    res
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn ord_sqr_mont(a: &[u64; 4], rep: u64) -> [u64; 4] {
    let mut res = [0u64; 4];
    unsafe { ecp_nistz256_ord_sqr_mont(res.as_mut_ptr(), a.as_ptr(), rep) };
    res
}

/// Scatter one Jacobian point (12 limbs) into a w5 table.
///
/// `table` must hold at least `16 * P256_POINT_LIMBS` limbs.  Index is
/// 1-based (1..=16); slot 0 is implicitly infinity and is never stored.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn scatter_w5(table: &mut [u64], point: &[u64; 12], index: i32) {
    unsafe { ecp_nistz256_scatter_w5(table.as_mut_ptr(), point.as_ptr(), index) };
}

/// Gather one Jacobian point (12 limbs) from a w5 table (1-based index).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn gather_w5(out: &mut [u64; 12], table: &[u64], index: i32) {
    unsafe { ecp_nistz256_gather_w5(out.as_mut_ptr(), table.as_ptr(), index) };
}

/// Scatter one affine point (8 limbs) into a w7 table.
///
/// `table` must hold at least `64 * P256_POINT_AFFINE_LIMBS` limbs.
/// Index is 0-based (0..=63); the stored entry is later read back with
/// `gather_w7(.., index + 1)` because gather skips the implicit-zero slot.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn scatter_w7(table: &mut [u64], point: &[u64; 8], index: i32) {
    unsafe { ecp_nistz256_scatter_w7(table.as_mut_ptr(), point.as_ptr(), index) };
}

/// Gather one affine point (8 limbs) from a w7 table (1-based index).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn gather_w7(out: &mut [u64; 8], table: &[u64], index: i32) {
    unsafe { ecp_nistz256_gather_w7(out.as_mut_ptr(), table.as_ptr(), index) };
}

/// `r = 2*a` in Jacobian coordinates (inputs/outputs in Montgomery form).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn point_double(a: &[u64; 12]) -> [u64; 12] {
    let mut r = [0u64; 12];
    unsafe { ecp_nistz256_point_double(r.as_mut_ptr(), a.as_ptr()) };
    r
}

/// `r = a + b` in Jacobian coordinates (inputs/outputs in Montgomery form).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn point_add(a: &[u64; 12], b: &[u64; 12]) -> [u64; 12] {
    let mut r = [0u64; 12];
    unsafe { ecp_nistz256_point_add(r.as_mut_ptr(), a.as_ptr(), b.as_ptr()) };
    r
}

/// `r = a + b` with `b` affine (Montgomery form).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn point_add_affine(a: &[u64; 12], b: &[u64; 8]) -> [u64; 12] {
    let mut r = [0u64; 12];
    unsafe { ecp_nistz256_point_add_affine(r.as_mut_ptr(), a.as_ptr(), b.as_ptr()) };
    r
}

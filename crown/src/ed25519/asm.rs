//! Curve25519 field arithmetic assembly (x25519-x86_64.pl) for x86_64.
//!
//! OpenSSL `crypto/ec/curve25519.c` replaces its portable field arithmetic
//! with these symbols under `X25519_ASM`:
//!
//! * `x25519_fe51_{mul,sqr,mul121666}` — radix-2^51 helpers used by the
//!   ed25519 group operations (`fe51` is `uint64_t[5]`, the same layout as
//!   [`crate::ed25519::fe::Fe`]),
//! * `x25519_fe64_{mul,sqr,mul121666,add,sub,tobytes,eligible}` —
//!   radix-2^64 helpers for the X25519 ladder (`fe64` is `uint64_t[4]`,
//!   partially reduced values allowed; only `tobytes` fully reduces).
//!
//! The symbols are compiled and unit-tested against the portable
//! implementations. `fe::mul`/`fe::sq` dispatch to the fe51 helpers when
//! the `asm` feature is enabled, mirroring OpenSSL
//! `#define fe51_mul x25519_fe51_mul`. fe64 helpers stay available for
//! the future X25519 ladder.

#![allow(dead_code, unused_imports)]
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/ed25519/x86_64.ts"),
    options(att_syntax)
);

/// OpenSSL `fe51`: five 51-bit limbs, layout-compatible with
/// [`crate::ed25519::fe::Fe`].
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub type Fe51 = [u64; 5];

/// OpenSSL `fe64`: four 64-bit limbs (mod 2^256 - 38, partial reduction).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub type Fe64 = [u64; 4];

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
extern "C" {
    fn x25519_fe51_mul(h: *mut Fe51, f: *const Fe51, g: *const Fe51);
    fn x25519_fe51_sqr(h: *mut Fe51, f: *const Fe51);
    fn x25519_fe51_mul121666(h: *mut Fe51, f: *const Fe51);
    fn x25519_fe64_mul(h: *mut Fe64, f: *const Fe64, g: *const Fe64);
    fn x25519_fe64_sqr(h: *mut Fe64, f: *const Fe64);
    fn x25519_fe64_mul121666(h: *mut Fe64, f: *const Fe64);
    fn x25519_fe64_add(h: *mut Fe64, f: *const Fe64, g: *const Fe64);
    fn x25519_fe64_sub(h: *mut Fe64, f: *const Fe64, g: *const Fe64);
    fn x25519_fe64_tobytes(s: *mut u8, f: *const Fe64);
    fn x25519_fe64_eligible() -> u32;
}

/// ADX/BMI2 support as reported by the assembly's own CPUID probe.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn fe64_eligible() -> bool {
    unsafe { x25519_fe64_eligible() == 1 }
}

/// `h = f * g` (radix-2^51).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn fe51_mul(f: &Fe51, g: &Fe51) -> Fe51 {
    let mut h = [0u64; 5];
    unsafe { x25519_fe51_mul(&mut h, f, g) };
    h
}

/// `h = f^2` (radix-2^51).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn fe51_sqr(f: &Fe51) -> Fe51 {
    let mut h = [0u64; 5];
    unsafe { x25519_fe51_sqr(&mut h, f) };
    h
}

/// `h = f * 121666` (radix-2^51).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn fe51_mul121666(f: &Fe51) -> Fe51 {
    let mut h = [0u64; 5];
    unsafe { x25519_fe51_mul121666(&mut h, f) };
    h
}

/// `h = f * g` (radix-2^64, partial reduction).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn fe64_mul(f: &Fe64, g: &Fe64) -> Fe64 {
    let mut h = [0u64; 4];
    unsafe { x25519_fe64_mul(&mut h, f, g) };
    h
}

/// `h = f^2` (radix-2^64, partial reduction).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn fe64_sqr(f: &Fe64) -> Fe64 {
    let mut h = [0u64; 4];
    unsafe { x25519_fe64_sqr(&mut h, f) };
    h
}

/// `h = f * 121666` (radix-2^64, partial reduction).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn fe64_mul121666(f: &Fe64) -> Fe64 {
    let mut h = [0u64; 4];
    unsafe { x25519_fe64_mul121666(&mut h, f) };
    h
}

/// `h = f + g` (radix-2^64, partial reduction).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn fe64_add(f: &Fe64, g: &Fe64) -> Fe64 {
    let mut h = [0u64; 4];
    unsafe { x25519_fe64_add(&mut h, f, g) };
    h
}

/// `h = f - g` (radix-2^64, partial reduction).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn fe64_sub(f: &Fe64, g: &Fe64) -> Fe64 {
    let mut h = [0u64; 4];
    unsafe { x25519_fe64_sub(&mut h, f, g) };
    h
}

/// Fully reduced little-endian 32-byte encoding of a radix-2^64 value.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn fe64_tobytes(f: &Fe64) -> [u8; 32] {
    let mut s = [0u8; 32];
    unsafe { x25519_fe64_tobytes(s.as_mut_ptr(), f) };
    s
}

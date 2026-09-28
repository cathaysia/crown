//! bn_mul_mont assembly (x86_64-mont.pl) for x86_64.
//!
//! OpenSSL `crypto/bn/asm/x86_64-mont.pl` provides `bn_mul_mont`, the
//! Montgomery multiplication primitive at the heart of RSA's private-key
//! operations (`crypto/bn/bn_exp.c` calls it through `BN_mod_exp_mont`).
//!
//! C ABI (`$win64=0`, unix SysV):
//!
//! ```text
//! int bn_mul_mont(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
//!                 const BN_ULONG *np, const BN_ULONG *n0, int num);
//! ```
//!
//! `num` is the operand length in 64-bit limbs; the routine supports the
//! counts dispatched in-register (4, 6, 8, 12, 16, 20, ..., 64) and
//! returns 0 for unsupported counts, leaving the caller on the portable
//! path. `n0` points at `-n^-1 mod 2^64` in the low word (OpenSSL
//! `BN_MONT_CTX::n0[0]`, a second word follows for internal use).


#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/bn/x86_64.ts"),
    options(att_syntax)
);

// x86_64-mont5.pl: bn_sqr8x_internal/bn_sqrx8x_internal continue
// bn_sqr8x_mont from x86_64-mont.pl; the power5 family is the modexp core.
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/bn/mont5_x86_64.ts"),
    options(att_syntax)
);

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
extern "C" {
    fn bn_mul_mont(
        rp: *mut u64,
        ap: *const u64,
        bp: *const u64,
        np: *const u64,
        n0: *const u64,
        num: i32,
    ) -> i32;
}

/// Montgomery multiplication of `a` by `b` modulo `n` using the assembly
/// routine. `n0` is `-n^-1 mod 2^64`. Returns `None` when `bn_mul_mont`
/// rejects the limb count.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn mul_mont(a: &[u64], b: &[u64], n: &[u64], n0: u64) -> Option<Vec<u64>> {
    let num = n.len();
    if a.len() != num || b.len() != num {
        return None;
    }
    let mut rp = alloc::vec![0u64; num];
    let n0p = [n0, 0u64];
    let ok = unsafe {
        bn_mul_mont(
            rp.as_mut_ptr(),
            a.as_ptr(),
            b.as_ptr(),
            n.as_ptr(),
            n0p.as_ptr(),
            num as i32,
        )
    };
    if ok == 1 {
        // The routine writes exactly `num` limbs, including a possible
        // leading (high) zero limb; normalize for Bn equality.
        while rp.last() == Some(&0) {
            rp.pop();
        }
        Some(rp)
    } else {
        None
    }
}

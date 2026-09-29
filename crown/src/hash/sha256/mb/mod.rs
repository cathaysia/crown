//! Multi-buffer SHA-256 (`sha256-mb-x86_64.pl`) for x86_64 — SSSE3 4-way.
//!
//! OpenSSL's `crypto/sha/asm/sha256-mb-x86_64.pl` provides
//! `sha256_multi_block`, which processes up to 4 (or 8) independent
//! SHA-256 streams in parallel using SSSE3 SIMD lanes. This is the
//! kernel used by the TLS CBC-HMAC stitched ciphers.
//!
//! Only the SSSE3 tier is translated in this pass. The shaext / avx /
//! avx2 tiers are deferred — see `NOTES.md`.
//!
//! C ABI (unix SysV):
//!
//! ```text
//! void sha256_multi_block(
//!     struct { unsigned int A[8]; B[8]; C[8]; D[8]; E[8]; F[8]; G[8]; H[8]; } *ctx,
//!     struct { void *ptr; int blocks; } inp[8],
//!     int num);
//! ```

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sha256/mb/x86_64.ts"),
    options(att_syntax)
);

/// SHA-256 multi-buffer context: 8 lanes of 8-word state.
#[repr(C)]
#[derive(Clone)]
pub struct Sha256MultiCtx {
    pub a: [u32; 8],
    pub b: [u32; 8],
    pub c: [u32; 8],
    pub d: [u32; 8],
    pub e: [u32; 8],
    pub f: [u32; 8],
    pub g: [u32; 8],
    pub h: [u32; 8],
}

/// One input job: a pointer to contiguous 64-byte blocks and a count.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sha256MultiJob {
    pub ptr: *const u8,
    pub blocks: i32,
    _pad: u32,
}

impl Sha256MultiJob {
    /// Create a job for `blocks` 64-byte blocks at `data`.
    pub fn new(data: &[u8], blocks: usize) -> Self {
        debug_assert!(blocks * 64 <= data.len());
        Sha256MultiJob {
            ptr: data.as_ptr(),
            blocks: blocks as i32,
            _pad: 0,
        }
    }

    /// An inactive (empty) job.
    pub fn empty() -> Self {
        Sha256MultiJob {
            ptr: core::ptr::null(),
            blocks: 0,
            _pad: 0,
        }
    }
}

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
extern "C" {
    fn sha256_multi_block(ctx: *mut Sha256MultiCtx, inp: *const Sha256MultiJob, num: u32);
}

/// Process up to 8 independent SHA-256 streams in parallel.
///
/// `jobs` must have exactly 8 entries (use `Sha256MultiJob::empty()` for
/// unused lanes). `num` is 1 for a single 4-lane group or 2 for 8 lanes.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn multi_block(ctx: &mut Sha256MultiCtx, jobs: &[Sha256MultiJob; 8], num: u32) {
    assert!((1..=2).contains(&num), "num must be 1 or 2");
    unsafe {
        sha256_multi_block(ctx as *mut _, jobs.as_ptr(), num);
    }
}

/// Single-stream convenience: hash `blocks` 64-byte blocks from `data`
/// into `state` (8 words), using lane 0 of the multi-buffer kernel.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn multi_block_single(state: &mut [u32; 8], data: &[u8], blocks: usize) {
    assert!(blocks > 0 && data.len() >= blocks * 64);
    let mut ctx = Sha256MultiCtx {
        a: [0; 8],
        b: [0; 8],
        c: [0; 8],
        d: [0; 8],
        e: [0; 8],
        f: [0; 8],
        g: [0; 8],
        h: [0; 8],
    };
    ctx.a[0] = state[0];
    ctx.b[0] = state[1];
    ctx.c[0] = state[2];
    ctx.d[0] = state[3];
    ctx.e[0] = state[4];
    ctx.f[0] = state[5];
    ctx.g[0] = state[6];
    ctx.h[0] = state[7];
    let jobs = [
        Sha256MultiJob::new(data, blocks),
        Sha256MultiJob::empty(),
        Sha256MultiJob::empty(),
        Sha256MultiJob::empty(),
        Sha256MultiJob::empty(),
        Sha256MultiJob::empty(),
        Sha256MultiJob::empty(),
        Sha256MultiJob::empty(),
    ];
    multi_block(&mut ctx, &jobs, 1);
    state[0] = ctx.a[0];
    state[1] = ctx.b[0];
    state[2] = ctx.c[0];
    state[3] = ctx.d[0];
    state[4] = ctx.e[0];
    state[5] = ctx.f[0];
    state[6] = ctx.g[0];
    state[7] = ctx.h[0];
}

#[cfg(test)]
mod tests;

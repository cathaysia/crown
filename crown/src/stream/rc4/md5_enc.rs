//! Stitched RC4-MD5 for x86_64 (rc4-md5-x86_64.pl).
//!
//! `rc4_md5_enc` XORs the RC4 keystream over `in0` into `out` while folding
//! the *same* plaintext into MD5 — the construction used by TLS 1.0/1.1
//! `RC4-MD5` record protection.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/stream/rc4/md5_enc/x86_64.ts"),
    options(att_syntax)
);

/// OpenSSL `RC4_KEY` as consumed by `rc4_md5_enc`.
#[repr(C)]
pub struct Rc4Key {
    pub x: u32,
    pub y: u32,
    pub s: [u32; 256],
}

/// The four MD5 chaining words (state A..D). The asm does not touch `x`/`nx`/`len`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Md5BlockState {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
}

extern "C" {
    fn rc4_md5_enc(
        key: *mut Rc4Key,
        in0: *const u8,
        out: *mut u8,
        ctx: *mut Md5BlockState,
        inp: *const u8,
        len: usize,
    );
}

/// `len` is a count of 64-byte blocks. `in0`/`out`/`inp` must cover `len * 64`
/// bytes. `in0` and `inp` are usually the same buffer (plaintext): RC4 is
/// applied to it and MD5 absorbs it.
///
/// # Safety
/// `key`/`ctx` must be valid RC4/MD5 state; buffers must be `len * 64` bytes.
#[allow(dead_code)]
pub unsafe fn rc4_md5_enc_raw(
    key: *mut Rc4Key,
    in0: *const u8,
    out: *mut u8,
    ctx: *mut Md5BlockState,
    inp: *const u8,
    blocks: usize,
) {
    rc4_md5_enc(key, in0, out, ctx, inp, blocks)
}

/// Safe wrapper: processes `blocks` 64-byte chunks. `pt` is both the RC4
/// input and the MD5 input; `ct` receives the RC4 output.
#[allow(dead_code)]
pub fn rc4_md5_blocks(
    key: &mut Rc4Key,
    ctx: &mut Md5BlockState,
    pt: &[u8],
    ct: &mut [u8],
    blocks: usize,
) {
    debug_assert_eq!(pt.len(), blocks * 64);
    debug_assert_eq!(ct.len(), blocks * 64);
    unsafe {
        rc4_md5_enc(
            key,
            pt.as_ptr(),
            ct.as_mut_ptr(),
            ctx,
            pt.as_ptr(),
            blocks,
        );
    }
}

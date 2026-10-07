//! Poly1305 assembly implementation for x86_64.
//!
//! The OpenSSL assembly exports the IALU `poly1305_init`/`poly1305_blocks`/
//! `poly1305_emit` trio plus AVX, AVX2 and AVX512F+VL+BW (VPMADD52) block
//! functions. `poly1305_init` fills the function table handed to it with the
//! best available pair and returns 1; a return of 0 means no accelerated
//! path is available and the IALU entry points must be kept, exactly as
//! `crypto/poly1305/poly1305.c` does.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/mac/poly1305/x86_64.ts"),
    // The AVX512 body carries EVEX write-mask operands like `{%k2}`, which
    // the default `global_asm!` template syntax reads as substitution braces.
    options(att_syntax, raw)
);

extern "C" {
    /// Returns non-zero when it filled `func_table` with a faster pair.
    fn poly1305_init(ctx: *mut u64, key: *const u8, func_table: *mut u64) -> u64;
    fn poly1305_blocks(ctx: *mut u64, inp: *const u8, len: usize, padbit: u64);
    fn poly1305_emit(ctx: *const u64, mac: *mut u8, nonce: *const u8);
}

/// `func` in `struct poly1305_context`: the dispatch table filled by
/// `poly1305_init`.
#[repr(C)]
#[derive(Clone, Copy)]
struct FuncTable {
    blocks: unsafe extern "C" fn(*mut u64, *const u8, usize, u64),
    emit: unsafe extern "C" fn(*const u64, *mut u8, *const u8),
}

const TAG_SIZE: usize = 16;

/// `POLY1305_OPAQUE_SIZE`: the assembly keeps h/r/s at offsets 0..72 and the
/// base-2^44 path writes the lazily precomputed powers up to offset 160.
const CTX_WORDS: usize = 24;

/// Poly1305 MAC backed by the OpenSSL assembly routines.
///
/// The context layout is the opaque area expected by the assembly (it is
/// accessed with unaligned moves only, so `[u64; 24]` matches the upstream
/// `double opaque[24]`).
#[derive(Clone, Copy)]
pub struct MacAsm {
    ctx: [u64; CTX_WORDS],
    func: FuncTable,
    s: [u8; TAG_SIZE],
    buf: [u8; TAG_SIZE],
    used: usize,
}

impl MacAsm {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut ctx = [0u64; CTX_WORDS];
        // Seeded with the IALU pair, which `poly1305_init` overwrites when an
        // accelerated one is available (it returns 0 without touching the
        // table otherwise).
        let mut func = FuncTable {
            blocks: poly1305_blocks,
            emit: poly1305_emit,
        };
        unsafe {
            poly1305_init(
                ctx.as_mut_ptr(),
                key.as_ptr(),
                (&mut func as *mut FuncTable).cast(),
            );
        }

        let mut s = [0u8; TAG_SIZE];
        s.copy_from_slice(&key[16..32]);

        Self {
            ctx,
            func,
            s,
            buf: [0; TAG_SIZE],
            used: 0,
        }
    }

    pub fn write(&mut self, mut p: &[u8]) -> usize {
        let total = p.len();

        if self.used > 0 {
            let want = (TAG_SIZE - self.used).min(p.len());
            self.buf[self.used..self.used + want].copy_from_slice(&p[..want]);
            self.used += want;
            p = &p[want..];

            if self.used == TAG_SIZE {
                unsafe {
                    (self.func.blocks)(self.ctx.as_mut_ptr(), self.buf.as_ptr(), TAG_SIZE, 1);
                }
                self.used = 0;
            }
        }

        let full = p.len() & !15;
        if full > 0 {
            unsafe {
                (self.func.blocks)(self.ctx.as_mut_ptr(), p.as_ptr(), full, 1);
            }
            p = &p[full..];
        }

        if !p.is_empty() {
            self.buf[..p.len()].copy_from_slice(p);
            self.used = p.len();
        }

        total
    }

    pub fn sum(&self) -> [u8; TAG_SIZE] {
        let mut ctx = self.ctx;

        if self.used > 0 {
            let mut block = [0u8; TAG_SIZE];
            block[..self.used].copy_from_slice(&self.buf[..self.used]);
            block[self.used] = 1;
            unsafe {
                (self.func.blocks)(ctx.as_mut_ptr(), block.as_ptr(), TAG_SIZE, 0);
            }
        }

        let mut tag = [0u8; TAG_SIZE];
        unsafe {
            (self.func.emit)(ctx.as_ptr(), tag.as_mut_ptr(), self.s.as_ptr());
        }
        tag
    }
}

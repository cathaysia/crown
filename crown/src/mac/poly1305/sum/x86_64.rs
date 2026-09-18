//! Poly1305 assembly implementation for x86_64, driven by the OpenSSL
//! poly1305_init/poly1305_blocks/poly1305_emit routines.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/mac/poly1305/x86_64.ts"),
    options(att_syntax)
);

extern "C" {
    fn poly1305_init(ctx: *mut u64, key: *const u8, func_table: *mut u64);
    fn poly1305_blocks(ctx: *mut u64, inp: *const u8, len: usize, padbit: u64);
    fn poly1305_emit(ctx: *const u64, mac: *mut u8, nonce: *const u8);
}

const TAG_SIZE: usize = 16;

/// Poly1305 MAC backed by the OpenSSL assembly routines. The context layout
/// is the opaque area expected by the assembly: h[3] (base 2^64) followed by
/// the clamped r[2].
#[derive(Clone, Copy)]
pub struct MacAsm {
    ctx: [u64; 5],
    s: [u8; TAG_SIZE],
    buf: [u8; TAG_SIZE],
    used: usize,
}

impl MacAsm {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut ctx = [0u64; 5];
        // poly1305_init also stores dispatch function pointers through its
        // third argument; they are not used here.
        let mut func_table = [0u64; 2];
        unsafe {
            poly1305_init(ctx.as_mut_ptr(), key.as_ptr(), func_table.as_mut_ptr());
        }

        let mut s = [0u8; TAG_SIZE];
        s.copy_from_slice(&key[16..32]);

        Self {
            ctx,
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
                    poly1305_blocks(self.ctx.as_mut_ptr(), self.buf.as_ptr(), TAG_SIZE, 1);
                }
                self.used = 0;
            }
        }

        let full = p.len() & !15;
        if full > 0 {
            unsafe {
                poly1305_blocks(self.ctx.as_mut_ptr(), p.as_ptr(), full, 1);
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
                poly1305_blocks(ctx.as_mut_ptr(), block.as_ptr(), TAG_SIZE, 0);
            }
        }

        let mut tag = [0u8; TAG_SIZE];
        unsafe {
            poly1305_emit(ctx.as_ptr(), tag.as_mut_ptr(), self.s.as_ptr());
        }
        tag
    }
}

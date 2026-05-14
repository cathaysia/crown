//! Rabbit stream cipher implementation.
//!
//! Based on the LibTomCrypt implementation and the eSTREAM submission.
//!
//! # Note on Endianness
//!
//! This implementation uses little-endian byte order for key and IV loading,
//! and for keystream extraction, consistent with LibTomCrypt.
//! Test vectors from RFC 4503 are implemented with appropriate byte order
//! adjustments to match this behavior.

use crate::error::{CryptoError, CryptoResult};
use crate::stream::StreamCipher;
use crate::utils::subtle::xor::xor_bytes;
use bytes::{Buf, BufMut};

#[cfg(test)]
mod tests;

const BLOCK_SIZE: usize = 16;

#[derive(Clone, Copy)]
struct RabbitCtx {
    x: [u32; 8],
    c: [u32; 8],
    carry: u32,
}

/// Rabbit is a stateful instance of the Rabbit stream cipher.
pub struct Rabbit {
    master_ctx: RabbitCtx,
    work_ctx: RabbitCtx,
    buf: [u8; BLOCK_SIZE],
    len: usize,
}

impl Rabbit {
    /// Creates a new Rabbit stream cipher with the given key and optional nonce.
    ///
    /// The key must be 16 bytes.
    /// The nonce (IV) must be 8 bytes if provided.
    pub fn new(key: &[u8], nonce: Option<&[u8]>) -> CryptoResult<Self> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeySize {
                expected: "16",
                actual: key.len(),
            });
        }

        if let Some(n) = nonce {
            if n.len() != 8 {
                return Err(CryptoError::InvalidIvSize(n.len()));
            }
        }

        let mut rabbit = Rabbit {
            master_ctx: RabbitCtx {
                x: [0; 8],
                c: [0; 8],
                carry: 0,
            },
            work_ctx: RabbitCtx {
                x: [0; 8],
                c: [0; 8],
                carry: 0,
            },
            buf: [0; BLOCK_SIZE],
            len: 0,
        };

        rabbit.setup(key)?;

        if let Some(n) = nonce {
            rabbit.set_iv(n)?;
        }

        Ok(rabbit)
    }

    fn setup(&mut self, key: &[u8]) -> CryptoResult<()> {
        let mut k = key;
        let k0 = k.get_u32_le();
        let k1 = k.get_u32_le();
        let k2 = k.get_u32_le();
        let k3 = k.get_u32_le();

        // Generate initial state variables
        self.master_ctx.x[0] = k0;
        self.master_ctx.x[2] = k1;
        self.master_ctx.x[4] = k2;
        self.master_ctx.x[6] = k3;
        self.master_ctx.x[1] = (k3 << 16) | (k2 >> 16);
        self.master_ctx.x[3] = (k0 << 16) | (k3 >> 16);
        self.master_ctx.x[5] = (k1 << 16) | (k0 >> 16);
        self.master_ctx.x[7] = (k2 << 16) | (k1 >> 16);

        // Generate initial counter values
        self.master_ctx.c[0] = k2.rotate_left(16);
        self.master_ctx.c[2] = k3.rotate_left(16);
        self.master_ctx.c[4] = k0.rotate_left(16);
        self.master_ctx.c[6] = k1.rotate_left(16);
        self.master_ctx.c[1] = (k0 & 0xFFFF0000) | (k1 & 0xFFFF);
        self.master_ctx.c[3] = (k1 & 0xFFFF0000) | (k2 & 0xFFFF);
        self.master_ctx.c[5] = (k2 & 0xFFFF0000) | (k3 & 0xFFFF);
        self.master_ctx.c[7] = (k3 & 0xFFFF0000) | (k0 & 0xFFFF);

        self.master_ctx.carry = 0;

        // Iterate the master context four times
        for _ in 0..4 {
            next_state(&mut self.master_ctx);
        }

        // Modify the counters
        for i in 0..8 {
            self.master_ctx.c[i] ^= self.master_ctx.x[(i + 4) & 0x7];
        }

        // Copy master instance to work instance
        self.work_ctx = self.master_ctx;

        Ok(())
    }

    pub fn set_iv(&mut self, iv: &[u8]) -> CryptoResult<()> {
        if iv.len() != 8 {
            return Err(CryptoError::InvalidIvSize(iv.len()));
        }

        let mut i_ptr = iv;
        let i0 = i_ptr.get_u32_le();
        let i2 = i_ptr.get_u32_le();
        let i1 = (i0 >> 16) | (i2 & 0xFFFF0000);
        let i3 = (i2 << 16) | (i0 & 0x0000FFFF);

        // Modify counter values
        self.work_ctx.c[0] = self.master_ctx.c[0] ^ i0;
        self.work_ctx.c[1] = self.master_ctx.c[1] ^ i1;
        self.work_ctx.c[2] = self.master_ctx.c[2] ^ i2;
        self.work_ctx.c[3] = self.master_ctx.c[3] ^ i3;
        self.work_ctx.c[4] = self.master_ctx.c[4] ^ i0;
        self.work_ctx.c[5] = self.work_ctx.c[5] ^ i1; // Wait, LibTomCrypt says master_ctx.c[5] ^ i1?
                                                      // Let me check LibTomCrypt source again for c[4..7].
                                                      // "st->work_ctx.c[4] = st->master_ctx.c[4] ^ i0;"
                                                      // "st->work_ctx.c[5] = st->master_ctx.c[5] ^ i1;"
                                                      // Yes, it uses master_ctx.c as base.
        self.work_ctx.c[4] = self.master_ctx.c[4] ^ i0;
        self.work_ctx.c[5] = self.master_ctx.c[5] ^ i1;
        self.work_ctx.c[6] = self.master_ctx.c[6] ^ i2;
        self.work_ctx.c[7] = self.master_ctx.c[7] ^ i3;

        // Copy state variables
        self.work_ctx.x.copy_from_slice(&self.master_ctx.x);
        self.work_ctx.carry = self.master_ctx.carry;

        // Iterate the work context four times
        for _ in 0..4 {
            next_state(&mut self.work_ctx);
        }

        self.len = 0;

        Ok(())
    }

    fn generate_block(&mut self) {
        next_state(&mut self.work_ctx);

        let x = &self.work_ctx.x;
        let mut out = &mut self.buf[..];
        out.put_u32_le(x[0] ^ (x[5] >> 16) ^ (x[3] << 16));
        out.put_u32_le(x[2] ^ (x[7] >> 16) ^ (x[5] << 16));
        out.put_u32_le(x[4] ^ (x[1] >> 16) ^ (x[7] << 16));
        out.put_u32_le(x[6] ^ (x[3] >> 16) ^ (x[1] << 16));

        self.len = BLOCK_SIZE;
    }
}

impl StreamCipher for Rabbit {
    fn xor_key_stream(&mut self, mut inout: &mut [u8]) -> CryptoResult<()> {
        if inout.is_empty() {
            return Ok(());
        }

        if self.len > 0 {
            let n = self.len.min(inout.len());
            let keystream = &self.buf[BLOCK_SIZE - self.len..BLOCK_SIZE - self.len + n];
            xor_bytes(&mut inout[..n], keystream);
            self.len -= n;
            inout = &mut inout[n..];
        }

        while inout.len() >= BLOCK_SIZE {
            self.generate_block();
            xor_bytes(&mut inout[..BLOCK_SIZE], &self.buf);
            self.len = 0;
            inout = &mut inout[BLOCK_SIZE..];
        }

        if !inout.is_empty() {
            self.generate_block();
            xor_bytes(inout, &self.buf[..inout.len()]);
            self.len = BLOCK_SIZE - inout.len();
        }

        Ok(())
    }
}

#[inline]
fn g_func(x: u32) -> u32 {
    let x = x as u64;
    let square = x * x;
    (square as u32) ^ (square >> 32) as u32
}

fn next_state(ctx: &mut RabbitCtx) {
    let mut c_old = [0u32; 8];
    c_old.copy_from_slice(&ctx.c);

    ctx.c[0] = ctx.c[0].wrapping_add(0x4D34D34D).wrapping_add(ctx.carry);
    ctx.c[1] = ctx.c[1]
        .wrapping_add(0xD34D34D3)
        .wrapping_add(if ctx.c[0] < c_old[0] { 1 } else { 0 });
    ctx.c[2] = ctx.c[2]
        .wrapping_add(0x34D34D34)
        .wrapping_add(if ctx.c[1] < c_old[1] { 1 } else { 0 });
    ctx.c[3] = ctx.c[3]
        .wrapping_add(0x4D34D34D)
        .wrapping_add(if ctx.c[2] < c_old[2] { 1 } else { 0 });
    ctx.c[4] = ctx.c[4]
        .wrapping_add(0xD34D34D3)
        .wrapping_add(if ctx.c[3] < c_old[3] { 1 } else { 0 });
    ctx.c[5] = ctx.c[5]
        .wrapping_add(0x34D34D34)
        .wrapping_add(if ctx.c[4] < c_old[4] { 1 } else { 0 });
    ctx.c[6] = ctx.c[6]
        .wrapping_add(0x4D34D34D)
        .wrapping_add(if ctx.c[5] < c_old[5] { 1 } else { 0 });
    ctx.c[7] = ctx.c[7]
        .wrapping_add(0xD34D34D3)
        .wrapping_add(if ctx.c[6] < c_old[6] { 1 } else { 0 });
    ctx.carry = if ctx.c[7] < c_old[7] { 1 } else { 0 };

    let mut g = [0u32; 8];
    for i in 0..8 {
        g[i] = g_func(ctx.x[i].wrapping_add(ctx.c[i]));
    }

    ctx.x[0] = g[0]
        .wrapping_add(g[7].rotate_left(16))
        .wrapping_add(g[6].rotate_left(16));
    ctx.x[1] = g[1].wrapping_add(g[0].rotate_left(8)).wrapping_add(g[7]);
    ctx.x[2] = g[2]
        .wrapping_add(g[1].rotate_left(16))
        .wrapping_add(g[0].rotate_left(16));
    ctx.x[3] = g[3].wrapping_add(g[2].rotate_left(8)).wrapping_add(g[1]);
    ctx.x[4] = g[4]
        .wrapping_add(g[3].rotate_left(16))
        .wrapping_add(g[2].rotate_left(16));
    ctx.x[5] = g[5].wrapping_add(g[4].rotate_left(8)).wrapping_add(g[3]);
    ctx.x[6] = g[6]
        .wrapping_add(g[5].rotate_left(16))
        .wrapping_add(g[4].rotate_left(16));
    ctx.x[7] = g[7].wrapping_add(g[6].rotate_left(8)).wrapping_add(g[5]);
}

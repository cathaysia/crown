#![allow(dead_code, unused_imports)]
mod noasm;
pub use noasm::*;

use crate::{stream::StreamCipher, utils::subtle::xor::xor_bytes};
use alloc::vec;
pub struct Ctr {
    b: Aes,
    ivlo: u64,
    ivhi: u64,
    offset: u64,
}

impl Ctr {
    pub fn new(b: Aes, iv: &[u8]) -> CryptoResult<Self> {
        if iv.len() != Aes::BLOCK_SIZE {
            return Err(CryptoError::InvalidIvSize(iv.len()));
        }

        let ivhi = u64::from_be_bytes([iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7]]);
        let ivlo =
            u64::from_be_bytes([iv[8], iv[9], iv[10], iv[11], iv[12], iv[13], iv[14], iv[15]]);

        Ok(Ctr {
            b,
            ivlo,
            ivhi,
            offset: 0,
        })
    }

    pub fn xor_key_stream_at(&self, inout: &mut [u8], offset: u64) -> Result<(), CryptoError> {
        let (mut ivlo, mut ivhi) = add128(self.ivlo, self.ivhi, offset / Aes::BLOCK_SIZE as u64);
        let mut inout = inout;

        let block_offset = (offset % Aes::BLOCK_SIZE as u64) as usize;
        if block_offset != 0 {
            let mut output = [0u8; Aes::BLOCK_SIZE];

            let copy_len = core::cmp::min(inout.len(), Aes::BLOCK_SIZE - block_offset);
            output[block_offset..block_offset + copy_len].copy_from_slice(&inout[..copy_len]);

            ctr_blocks_1(&self.b, &mut output, ivlo, ivhi);

            inout[..copy_len].copy_from_slice(&output[block_offset..block_offset + copy_len]);
            inout = &mut inout[copy_len..];
            let (new_ivlo, new_ivhi) = add128(ivlo, ivhi, 1);
            ivlo = new_ivlo;
            ivhi = new_ivhi;
        }

        while inout.len() >= 8 * Aes::BLOCK_SIZE {
            let dst_chunk = &mut inout[..8 * Aes::BLOCK_SIZE];
            ctr_blocks_8(&self.b, dst_chunk, ivlo, ivhi);
            inout = &mut inout[8 * Aes::BLOCK_SIZE..];
            let (new_ivlo, new_ivhi) = add128(ivlo, ivhi, 8);
            ivlo = new_ivlo;
            ivhi = new_ivhi;
        }

        if inout.len() >= 4 * Aes::BLOCK_SIZE {
            let dst_chunk = &mut inout[..4 * Aes::BLOCK_SIZE];
            ctr_blocks_4(&self.b, dst_chunk, ivlo, ivhi);
            inout = &mut inout[4 * Aes::BLOCK_SIZE..];
            let (new_ivlo, new_ivhi) = add128(ivlo, ivhi, 4);
            ivlo = new_ivlo;
            ivhi = new_ivhi;
        }

        if inout.len() >= 2 * Aes::BLOCK_SIZE {
            let dst_chunk = &mut inout[..2 * Aes::BLOCK_SIZE];
            ctr_blocks_2(&self.b, dst_chunk, ivlo, ivhi);
            inout = &mut inout[2 * Aes::BLOCK_SIZE..];
            let (new_ivlo, new_ivhi) = add128(ivlo, ivhi, 2);
            ivlo = new_ivlo;
            ivhi = new_ivhi;
        }

        if inout.len() >= Aes::BLOCK_SIZE {
            let dst_chunk = &mut inout[..Aes::BLOCK_SIZE];
            ctr_blocks_1(&self.b, dst_chunk, ivlo, ivhi);
            inout = &mut inout[Aes::BLOCK_SIZE..];
            let (new_ivlo, new_ivhi) = add128(ivlo, ivhi, 1);
            ivlo = new_ivlo;
            ivhi = new_ivhi;
        }

        if !inout.is_empty() {
            let mut output = [0u8; Aes::BLOCK_SIZE];
            output[..inout.len()].copy_from_slice(inout);
            ctr_blocks_1(&self.b, &mut output, ivlo, ivhi);
            inout.copy_from_slice(&output[..inout.len()]);
        }

        Ok(())
    }
}

impl StreamCipher for Ctr {
    fn xor_key_stream(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
        self.xor_key_stream_at(inout, self.offset)?;

        let (new_offset, carry) = self.offset.overflowing_add(inout.len() as u64);
        if carry {
            return Err(CryptoError::CounterOverflow);
        }
        self.offset = new_offset;
        Ok(())
    }
}

pub(crate) fn ctr_blocks(b: &Aes, inout: &mut [u8], mut ivlo: u64, mut ivhi: u64) {
    // Prefer a single CTR32 run when the low 32-bit counter covers the
    // whole buffer without wrapping into the high 96 bits.
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        let n = inout.len() / 16;
        if n >= 1 && n <= u32::MAX as usize {
            let lo32 = ivlo as u32;
            if lo32.checked_add(n as u32).is_some() {
                let mut ivec = [0u8; 16];
                ivec[..8].copy_from_slice(&ivhi.to_be_bytes());
                ivec[8..].copy_from_slice(&ivlo.to_be_bytes());
                let (key, is_aesni_sched) = b.enc_schedule();
                let n16 = n * 16;
                let ptr = inout.as_mut_ptr();
                let (ip, op) = unsafe {
                    (
                        core::slice::from_raw_parts(ptr as *const u8, n16),
                        core::slice::from_raw_parts_mut(ptr, n16),
                    )
                };
                if is_aesni_sched {
                    crate::block::aes::aesni::ctr32_encrypt_blocks(ip, op, n, &key, &ivec);
                } else if crate::block::aes::bsaes::supported() {
                    crate::block::aes::bsaes::ctr32_encrypt_blocks(ip, op, &key, &ivec);
                } else {
                    // no accelerator: fall through
                }
                if is_aesni_sched || crate::block::aes::bsaes::supported() {
                    let tail = &mut inout[n16..];
                    if !tail.is_empty() {
                        // finish the partial block in software
                        let (nlo, nhi) = add128(ivlo, ivhi, n as u64);
                        let mut mask = [0u8; 16];
                        let ivlo2 = nlo;
                        let ivhi2 = nhi;
                        mask[..8].copy_from_slice(&ivhi2.to_be_bytes());
                        mask[8..].copy_from_slice(&ivlo2.to_be_bytes());
                        b.encrypt_block(&mut mask);
                        let k = tail.len();
                        for i in 0..k {
                            tail[i] ^= mask[i];
                        }
                    }
                    return;
                }
            }
        }
    }
    let mut buf = vec![0u8; inout.len()];

    for chunk in buf.chunks_mut(Aes::BLOCK_SIZE) {
        let counter_bytes = [
            (ivhi >> 56) as u8,
            (ivhi >> 48) as u8,
            (ivhi >> 40) as u8,
            (ivhi >> 32) as u8,
            (ivhi >> 24) as u8,
            (ivhi >> 16) as u8,
            (ivhi >> 8) as u8,
            ivhi as u8,
            (ivlo >> 56) as u8,
            (ivlo >> 48) as u8,
            (ivlo >> 40) as u8,
            (ivlo >> 32) as u8,
            (ivlo >> 24) as u8,
            (ivlo >> 16) as u8,
            (ivlo >> 8) as u8,
            ivlo as u8,
        ];

        chunk.copy_from_slice(&counter_bytes[..chunk.len()]);
        let (new_ivlo, new_ivhi) = add128(ivlo, ivhi, 1);
        ivlo = new_ivlo;
        ivhi = new_ivhi;

        b.encrypt_block(chunk);
    }

    xor_bytes(&mut buf, inout);
    inout.copy_from_slice(&buf);
}

fn add128(lo: u64, hi: u64, x: u64) -> (u64, u64) {
    let (new_lo, carry) = lo.overflowing_add(x);
    let (new_hi, _) = hi.overflowing_add(if carry { 1 } else { 0 });
    (new_lo, new_hi)
}

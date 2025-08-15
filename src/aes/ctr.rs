mod noasm;
pub use noasm::*;

use crate::{cipher::StreamCipher, subtle::xor::xor_bytes};

pub struct CTR {
    b: Aes,
    ivlo: u64,
    ivhi: u64,
    offset: u64,
}

impl CTR {
    pub fn new(b: Aes, iv: &[u8]) -> CryptoResult<Self> {
        if iv.len() != BLOCK_SIZE {
            return Err(CryptoError::InvalidIvSize(iv.len()));
        }

        let ivhi = u64::from_be_bytes([iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7]]);
        let ivlo =
            u64::from_be_bytes([iv[8], iv[9], iv[10], iv[11], iv[12], iv[13], iv[14], iv[15]]);

        Ok(CTR {
            b,
            ivlo,
            ivhi,
            offset: 0,
        })
    }

    pub fn round_to_block(&mut self) -> Result<(), CryptoError> {
        let remainder = self.offset % BLOCK_SIZE as u64;
        if remainder != 0 {
            let (new_offset, carry) = self.offset.overflowing_add(BLOCK_SIZE as u64 - remainder);
            if carry {
                return Err(CryptoError::CounterOverflow);
            }
            self.offset = new_offset;
        }
        Ok(())
    }

    pub fn xor_key_stream_at(&self, inout: &mut [u8], offset: u64) -> Result<(), CryptoError> {
        let (mut ivlo, mut ivhi) = add128(self.ivlo, self.ivhi, offset / BLOCK_SIZE as u64);
        let mut inout = inout;

        let block_offset = (offset % BLOCK_SIZE as u64) as usize;
        if block_offset != 0 {
            let mut output = [0u8; BLOCK_SIZE];

            let copy_len = std::cmp::min(inout.len(), BLOCK_SIZE - block_offset);
            output[block_offset..block_offset + copy_len].copy_from_slice(&inout[..copy_len]);

            ctr_blocks_1(&self.b, &mut output, ivlo, ivhi);

            inout[..copy_len].copy_from_slice(&output[block_offset..block_offset + copy_len]);
            inout = &mut inout[copy_len..];
            let (new_ivlo, new_ivhi) = add128(ivlo, ivhi, 1);
            ivlo = new_ivlo;
            ivhi = new_ivhi;
        }

        while inout.len() >= 8 * BLOCK_SIZE {
            let dst_chunk = &mut inout[..8 * BLOCK_SIZE];
            ctr_blocks_8(&self.b, dst_chunk, ivlo, ivhi);
            inout = &mut inout[8 * BLOCK_SIZE..];
            let (new_ivlo, new_ivhi) = add128(ivlo, ivhi, 8);
            ivlo = new_ivlo;
            ivhi = new_ivhi;
        }

        if inout.len() >= 4 * BLOCK_SIZE {
            let dst_chunk = &mut inout[..4 * BLOCK_SIZE];
            ctr_blocks_4(&self.b, dst_chunk, ivlo, ivhi);
            inout = &mut inout[4 * BLOCK_SIZE..];
            let (new_ivlo, new_ivhi) = add128(ivlo, ivhi, 4);
            ivlo = new_ivlo;
            ivhi = new_ivhi;
        }

        if inout.len() >= 2 * BLOCK_SIZE {
            let dst_chunk = &mut inout[..2 * BLOCK_SIZE];
            ctr_blocks_2(&self.b, dst_chunk, ivlo, ivhi);
            inout = &mut inout[2 * BLOCK_SIZE..];
            let (new_ivlo, new_ivhi) = add128(ivlo, ivhi, 2);
            ivlo = new_ivlo;
            ivhi = new_ivhi;
        }

        if inout.len() >= BLOCK_SIZE {
            let dst_chunk = &mut inout[..BLOCK_SIZE];
            ctr_blocks_1(&self.b, dst_chunk, ivlo, ivhi);
            inout = &mut inout[BLOCK_SIZE..];
            let (new_ivlo, new_ivhi) = add128(ivlo, ivhi, 1);
            ivlo = new_ivlo;
            ivhi = new_ivhi;
        }

        if !inout.is_empty() {
            let mut output = [0u8; BLOCK_SIZE];
            output[..inout.len()].copy_from_slice(inout);
            ctr_blocks_1(&self.b, &mut output, ivlo, ivhi);
            inout.copy_from_slice(&output[..inout.len()]);
        }

        Ok(())
    }
}

impl StreamCipher for CTR {
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
    let mut buf = vec![0u8; inout.len()];

    for chunk in buf.chunks_mut(BLOCK_SIZE) {
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

        b.encrypt(chunk);
    }

    xor_bytes(&mut buf, inout);
    inout.copy_from_slice(&buf);
}

fn add128(lo: u64, hi: u64, x: u64) -> (u64, u64) {
    let (new_lo, carry) = lo.overflowing_add(x);
    let (new_hi, _) = hi.overflowing_add(if carry { 1 } else { 0 });
    (new_lo, new_hi)
}

// RoundToBlock is used by CTR_DRBG, which discards the rightmost unused bits at
// each request. It rounds the offset up to the next block boundary.
pub fn round_to_block(ctr: &mut CTR) -> Result<(), CryptoError> {
    ctr.round_to_block()
}

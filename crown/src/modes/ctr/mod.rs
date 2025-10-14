#[cfg(test)]
mod aes_tests;
#[cfg(test)]
mod tests;

use crate::block::aes;
use crate::block::BlockCipher;
use crate::block::BlockCipherMarker;
use crate::error::{CryptoError, CryptoResult};
use crate::stream::StreamCipher;
use crate::utils::subtle::xor::xor_bytes;
use alloc::vec::Vec;

const STREAM_BUFFER_SIZE: usize = 512;

pub trait Ctr {
    fn to_ctr(self, iv: &[u8]) -> CryptoResult<impl StreamCipher + 'static>;
}

pub trait CtrMarker {}
impl<T: BlockCipherMarker> CtrMarker for T {}

impl Ctr for aes::Aes {
    fn to_ctr(self, iv: &[u8]) -> CryptoResult<impl StreamCipher + 'static> {
        Ok(AesCtrWrapper {
            c: aes::ctr::Ctr::new(self, iv)?,
        })
    }
}

impl<T> Ctr for T
where
    T: BlockCipher + CtrMarker + 'static,
{
    fn to_ctr(self, iv: &[u8]) -> CryptoResult<impl StreamCipher + 'static> {
        if iv.len() != self.block_size() {
            return Err(CryptoError::InvalidIvSize(iv.len()));
        }

        let buf_size = STREAM_BUFFER_SIZE.max(self.block_size());

        Ok(CtrImpl {
            b: self,
            ctr: iv.to_vec(),
            out: Vec::with_capacity(buf_size),
            out_used: 0,
        })
    }
}

struct CtrImpl<B: BlockCipher> {
    b: B,
    ctr: Vec<u8>,
    out: Vec<u8>,
    out_used: usize,
}

struct AesCtrWrapper {
    c: aes::ctr::Ctr,
}

impl StreamCipher for AesCtrWrapper {
    fn xor_key_stream(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
        self.c.xor_key_stream(inout)
    }
}

impl<B: BlockCipher> CtrImpl<B> {
    fn refill(&mut self) {
        let remain = self.out.len() - self.out_used;

        // Move remaining data to the beginning
        self.out.copy_within(self.out_used.., 0);
        self.out.resize(self.out.capacity(), 0);

        let bs = self.b.block_size();
        let mut remain = remain;

        while remain <= self.out.len() - bs {
            self.out[remain..remain + bs].copy_from_slice(&self.ctr);
            self.b.encrypt_block(&mut self.out[remain..remain + bs]);
            remain += bs;

            // Increment counter
            for i in (0..self.ctr.len()).rev() {
                self.ctr[i] = self.ctr[i].wrapping_add(1);
                if self.ctr[i] != 0 {
                    break;
                }
            }
        }

        self.out.truncate(remain);
        self.out_used = 0;
    }
}

impl<B: BlockCipher> StreamCipher for CtrImpl<B> {
    fn xor_key_stream(&mut self, mut inout: &mut [u8]) -> CryptoResult<()> {
        while !inout.is_empty() {
            if self.out_used >= self.out.len().saturating_sub(self.b.block_size()) {
                self.refill();
            }

            let n = xor_bytes(inout, &self.out[self.out_used..]);
            inout = &mut inout[n..];
            self.out_used += n;
        }

        Ok(())
    }
}

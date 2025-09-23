//! OFB (Output Feedback) Mode.

use crate::block::BlockCipher;
use crate::block::BlockCipherMarker;
use crate::error::{CryptoError, CryptoResult};
use crate::stream::StreamCipher;
use crate::utils::subtle::xor::xor_bytes;

use alloc::vec::Vec;

#[cfg(test)]
mod tests;

const STREAM_BUFFER_SIZE: usize = 512;

pub trait Ofb {
    fn to_ofb(self, iv: &[u8]) -> CryptoResult<impl StreamCipher + 'static>;
}

pub trait OfbMarker {}
impl<T: BlockCipherMarker> OfbMarker for T {}

impl<T> Ofb for T
where
    T: BlockCipher + OfbMarker + 'static,
{
    fn to_ofb(self, iv: &[u8]) -> CryptoResult<impl StreamCipher + 'static> {
        let block_size = self.block_size();
        if iv.len() != block_size {
            return Err(CryptoError::InvalidIvSize(iv.len()));
        }

        let buf_size = STREAM_BUFFER_SIZE.max(block_size);

        Ok(OfbImpl {
            b: self,
            cipher: iv.to_vec(),
            out: Vec::with_capacity(buf_size),
            out_used: 0,
        })
    }
}

struct OfbImpl<B: BlockCipher> {
    b: B,
    cipher: Vec<u8>,
    out: Vec<u8>,
    out_used: usize,
}

impl<B: BlockCipher> OfbImpl<B> {
    fn refill(&mut self) {
        let bs = self.b.block_size();
        let remain = self.out.len() - self.out_used;

        if remain > self.out_used {
            return;
        }

        // Move remaining data to the beginning
        self.out.copy_within(self.out_used.., 0);
        self.out.resize(self.out.capacity(), 0);

        let mut remain = remain;
        while remain < self.out.len() - bs {
            self.b.encrypt(&mut self.cipher);
            self.out[remain..remain + bs].copy_from_slice(&self.cipher);
            remain += bs;
        }

        self.out.truncate(remain);
        self.out_used = 0;
    }
}

impl<B: BlockCipher> StreamCipher for OfbImpl<B> {
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

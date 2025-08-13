//! OFB (Output Feedback) Mode.

use super::*;
use crate::cipher::marker::BlockCipherMarker;
use crate::cipher::StreamCipher;
use crate::error::{CryptoError, CryptoResult};
use crate::subtle::xor::xor_bytes;
use crate::utils::inexact_overlap;

#[cfg(test)]
mod tests;

const STREAM_BUFFER_SIZE: usize = 512;

pub trait OfbAble {
    fn to_ofb(self, iv: &[u8]) -> CryptoResult<impl StreamCipher>;
}

pub trait OfbAbleMarker {}
impl<T: BlockCipherMarker> OfbAbleMarker for T {}

impl<T> OfbAble for T
where
    T: BlockCipher + OfbAbleMarker + 'static,
{
    fn to_ofb(self, iv: &[u8]) -> CryptoResult<impl StreamCipher> {
        let block_size = self.block_size();
        if iv.len() != block_size {
            return Err(CryptoError::InvalidIvSize(iv.len()));
        }

        let buf_size = STREAM_BUFFER_SIZE.max(block_size);

        Ok(Ofb {
            b: self,
            cipher: iv.to_vec(),
            out: Vec::with_capacity(buf_size),
            out_used: 0,
        })
    }
}

pub struct Ofb<B: BlockCipher> {
    b: B,
    cipher: Vec<u8>,
    out: Vec<u8>,
    out_used: usize,
}

impl<B: BlockCipher> Ofb<B> {
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
            let src = self.cipher.clone();
            self.b.encrypt(&mut self.cipher, &src);
            self.out[remain..remain + bs].copy_from_slice(&self.cipher);
            remain += bs;
        }

        self.out.truncate(remain);
        self.out_used = 0;
    }
}

impl<B: BlockCipher> StreamCipher for Ofb<B> {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) -> CryptoResult<()> {
        if dst.len() < src.len() {
            panic!("crypto/cipher: output smaller than input");
        }

        if inexact_overlap(&dst[..src.len()], src) {
            panic!("crypto/cipher: invalid buffer overlap");
        }

        let mut dst = &mut dst[..src.len()];
        let mut src = src;

        while !src.is_empty() {
            if self.out_used >= self.out.len().saturating_sub(self.b.block_size()) {
                self.refill();
            }

            let n = xor_bytes(dst, src, &self.out[self.out_used..]);
            dst = &mut dst[n..];
            src = &src[n..];
            self.out_used += n;
        }

        Ok(())
    }
}

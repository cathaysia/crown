use super::*;
use crate::aes;
use crate::cipher::StreamCipher;
use crate::error::{CryptoError, CryptoResult};

const STREAM_BUFFER_SIZE: usize = 512;

pub trait CtrAble {
    fn new_ctr(self, iv: &[u8]) -> CryptoResult<Box<dyn StreamCipher>>;
}

impl CtrAble for aes::Block {
    fn new_ctr(self, iv: &[u8]) -> CryptoResult<Box<dyn StreamCipher>> {
        Ok(Box::new(AesCtrWrapper {
            c: aes::ctr::CTR::new(self, iv)?,
        }))
    }
}

impl<T> CtrAble for T
where
    T: BlockCipher + 'static,
{
    fn new_ctr(self, iv: &[u8]) -> CryptoResult<Box<dyn StreamCipher>> {
        if iv.len() != self.block_size() {
            return Err(CryptoError::InvalidIvSize(iv.len()));
        }

        let buf_size = STREAM_BUFFER_SIZE.max(self.block_size());

        Ok(Box::new(Ctr {
            b: self,
            ctr: iv.to_vec(),
            out: Vec::with_capacity(buf_size),
            out_used: 0,
        }))
    }
}

pub struct Ctr<B: BlockCipher> {
    b: B,
    ctr: Vec<u8>,
    out: Vec<u8>,
    out_used: usize,
}

pub struct AesCtrWrapper {
    c: aes::ctr::CTR,
}

impl StreamCipher for AesCtrWrapper {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) -> CryptoResult<()> {
        self.c.xor_key_stream(dst, src)
    }
}

impl<B: BlockCipher> Ctr<B> {
    fn refill(&mut self) {
        let remain = self.out.len() - self.out_used;

        // Move remaining data to the beginning
        self.out.copy_within(self.out_used.., 0);
        self.out.resize(self.out.capacity(), 0);

        let bs = self.b.block_size();
        let mut remain = remain;

        while remain <= self.out.len() - bs {
            self.b
                .encrypt(&mut self.out[remain..remain + bs], &self.ctr);
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

impl<B: BlockCipher> StreamCipher for Ctr<B> {
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
            if self.out_used >= self.out.len() - self.b.block_size() {
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

pub fn new_ctr<B: CtrAble>(block: B, iv: &[u8]) -> CryptoResult<Box<dyn StreamCipher>> {
    CtrAble::new_ctr(block, iv)
}

fn inexact_overlap(dst: &[u8], src: &[u8]) -> bool {
    let dst_ptr = dst.as_ptr() as usize;
    let src_ptr = src.as_ptr() as usize;
    let dst_end = dst_ptr + dst.len();
    let src_end = src_ptr + src.len();

    (dst_ptr < src_end && src_ptr < dst_end) && (dst_ptr != src_ptr)
}

fn xor_bytes(dst: &mut [u8], src: &[u8], key_stream: &[u8]) -> usize {
    let n = dst.len().min(src.len()).min(key_stream.len());

    for i in 0..n {
        dst[i] = src[i] ^ key_stream[i];
    }

    n
}

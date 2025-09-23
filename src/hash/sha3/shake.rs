use bytes::BufMut;

use super::*;
use crate::{
    core::{CoreRead, CoreWrite},
    error::{CryptoError, CryptoResult},
    hash::{Hash, HashUser},
    mac::hmac::Marshalable,
};
use alloc::vec;
use alloc::vec::Vec;

#[derive(Clone)]
pub struct Shake<const N: usize> {
    pub(crate) d: Sha3<N>, // SHA-3 state context and Read/Write operations

    // initBlock is the cSHAKE specific initialization set of bytes. It is initialized
    // by newCShake function and stores concatenation of N followed by S, encoded
    // by the method specified in 3.3 of [1].
    // It is stored here in order for Reset() to be able to put context into
    // initial state.
    pub(crate) init_block: Vec<u8>,
}

fn bytepad(data: &[u8], rate: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + data.len() + rate - 1);
    out.extend_from_slice(&left_encode(rate as u64));
    out.extend_from_slice(data);
    let padlen = rate - (out.len() % rate);
    if padlen < rate {
        out.resize(out.len() + padlen, 0);
    }
    out
}

fn left_encode(x: u64) -> Vec<u8> {
    // Let n be the smallest positive integer for which 2^(8n) > x.
    let n = if x == 0 {
        1
    } else {
        (64 - x.leading_zeros() + 7) / 8
    } as usize;

    // Return n || x with n as a byte and x an n bytes in big-endian order.
    let mut b = vec![0u8; n + 1];
    b[0] = n as u8;

    for i in 0..n {
        b[n - i] = (x >> (i * 8)) as u8;
    }

    b
}

pub(crate) fn new_cshake<const N: usize>(n: &[u8], s: &[u8], rate: usize, dsbyte: u8) -> Shake<N> {
    let mut c = Shake {
        d: Sha3 {
            a: [0; 200],
            n: 0,
            rate,
            dsbyte,
            state: digest::SpongeDirection::Absorbing,
        },
        init_block: Vec::with_capacity(9 + n.len() + 9 + s.len()), // leftEncode returns max 9 bytes
    };

    c.init_block
        .extend_from_slice(&left_encode((n.len() * 8) as u64));
    c.init_block.extend_from_slice(n);
    c.init_block
        .extend_from_slice(&left_encode((s.len() * 8) as u64));
    c.init_block.extend_from_slice(s);

    let padded = bytepad(&c.init_block, c.d.rate);
    c.d.write_all(&padded).unwrap();
    c
}

impl<const N: usize> Marshalable for Shake<N> {
    fn marshal_size(&self) -> usize {
        207 + self.init_block.len()
    }

    fn marshal_into(&self, mut b: &mut [u8]) -> CryptoResult<usize> {
        let len = b.len();
        if len < self.marshal_size() {
            return Err(CryptoError::BufferTooSmall);
        }
        let consume = self.d.marshal_into(b)?;
        b = &mut b[..consume];
        b.put_slice(&self.init_block);
        Ok(len - b.len())
    }

    fn unmarshal_binary(&mut self, b: &[u8]) -> CryptoResult<()> {
        const MARSHALED_SIZE: usize = 207; // magic(4) + rate(1) + state(200) + n(1) + direction(1)

        if b.len() < MARSHALED_SIZE {
            return Err(CryptoError::InvalidHashState);
        }

        self.d.unmarshal_binary(&b[..MARSHALED_SIZE])?;
        self.init_block = b[MARSHALED_SIZE..].to_vec();
        Ok(())
    }
}

impl<const N: usize> CoreWrite for Shake<N> {
    fn write(&mut self, p: &[u8]) -> CryptoResult<usize> {
        self.d.write(p)
    }

    fn flush(&mut self) -> CryptoResult<()> {
        self.d.flush()
    }
}

impl<const N: usize> CoreRead for Shake<N> {
    fn read(&mut self, out: &mut [u8]) -> CryptoResult<usize> {
        // Note that read is not exposed on Digest since SHA-3 does not offer
        // variable output length. It is only used internally by Sum.

        // If we're still absorbing, pad and apply the permutation.
        if self.d.state == digest::SpongeDirection::Absorbing {
            // Pad with this instance's domain-separator bits. We know that there's
            // at least one byte of space in the sponge because, if it were full,
            // permute would have been called to empty it. dsbyte also contains the
            // first one bit for the padding. See the comment in the state struct.
            self.d.a[self.d.n] ^= self.d.dsbyte;
            // This adds the final one bit for the padding. Because of the way that
            // bits are numbered from the LSB upwards, the final bit is the MSB of
            // the last byte.
            self.d.a[self.d.rate - 1] ^= 0x80;
            // Apply the permutation
            keccak_f1600(&mut self.d.a);
            self.d.n = 0;
            self.d.state = digest::SpongeDirection::Squeezing;
        }

        let n = out.len();
        let mut remaining = out;

        // Now, do the squeezing.
        while !remaining.is_empty() {
            // Apply the permutation if we've squeezed the sponge dry.
            if self.d.n == self.d.rate {
                keccak_f1600(&mut self.d.a);
                self.d.n = 0;
            }

            let x = core::cmp::min(remaining.len(), self.d.rate - self.d.n);
            remaining[..x].copy_from_slice(&self.d.a[self.d.n..self.d.n + x]);
            self.d.n += x;
            remaining = &mut remaining[x..];
        }

        Ok(n)
    }
}

impl<const N: usize> HashUser for Shake<N> {
    fn block_size(&self) -> usize {
        self.d.block_size()
    }

    fn size(&self) -> usize {
        self.d.size()
    }

    // Reset resets the hash to initial state.
    fn reset(&mut self) {
        self.d.reset();
        if !self.init_block.is_empty() {
            let padded = bytepad(&self.init_block, self.d.rate);
            self.d.write_all(&padded).unwrap();
        }
    }
}
impl<const N: usize> Hash<N> for Shake<N> {
    // Sum appends a portion of output to b and returns the resulting slice. The
    // output length is selected to provide full-strength generic security: 32 bytes
    // for SHAKE128 and 64 bytes for SHAKE256. It does not change the underlying
    // state. It panics if any output has already been read.
    fn sum(&mut self) -> [u8; N] {
        self.d.sum()
    }
}

use super::*;
use crate::{
    error::{CryptoError, CryptoResult},
    hash::Hash,
    hmac::Marshalable,
};
use std::io::{self, Read, Write};

#[derive(Clone)]
pub struct Shake {
    d: Sha3, // SHA-3 state context and Read/Write operations

    // initBlock is the cSHAKE specific initialization set of bytes. It is initialized
    // by newCShake function and stores concatenation of N followed by S, encoded
    // by the method specified in 3.3 of [1].
    // It is stored here in order for Reset() to be able to put context into
    // initial state.
    init_block: Vec<u8>,
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

fn new_cshake(n: &[u8], s: &[u8], rate: usize, output_len: usize, dsbyte: u8) -> Shake {
    let mut c = Shake {
        d: Sha3 {
            a: [0; 200],
            n: 0,
            rate,
            dsbyte,
            output_len,
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

impl Shake {
    fn append_binary(&self, b: &mut Vec<u8>) -> CryptoResult<Vec<u8>> {
        self.d.append_binary(b)?;
        b.extend_from_slice(&self.init_block);
        Ok(b.clone())
    }
}

impl Marshalable for Shake {
    fn marshal_binary(&self) -> CryptoResult<Vec<u8>> {
        let mut b = Vec::with_capacity(207 + self.init_block.len()); // magic(4) + rate(1) + state(200) + n(1) + direction(1)
        self.append_binary(&mut b)
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

impl Write for Shake {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        self.d.write(p)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.d.flush()
    }
}

impl Read for Shake {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
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

            let x = std::cmp::min(remaining.len(), self.d.rate - self.d.n);
            remaining[..x].copy_from_slice(&self.d.a[self.d.n..self.d.n + x]);
            self.d.n += x;
            remaining = &mut remaining[x..];
        }

        Ok(n)
    }
}

impl Hash for Shake {
    fn block_size(&self) -> usize {
        self.d.block_size()
    }

    fn size(&self) -> usize {
        self.d.size()
    }

    // Sum appends a portion of output to b and returns the resulting slice. The
    // output length is selected to provide full-strength generic security: 32 bytes
    // for SHAKE128 and 64 bytes for SHAKE256. It does not change the underlying
    // state. It panics if any output has already been read.
    fn sum(&mut self, input: &[u8]) -> Vec<u8> {
        self.d.sum(input)
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

// NewShake128 creates a new SHAKE128 XOF.
pub fn new_shake128() -> Shake {
    Shake {
        d: Sha3 {
            a: [0; 200],
            n: 0,
            rate: RATE_K256,
            dsbyte: DSBYTE_SHAKE,
            output_len: 32,
            state: digest::SpongeDirection::Absorbing,
        },
        init_block: Vec::new(),
    }
}

// NewShake256 creates a new SHAKE256 XOF.
pub fn new_shake256() -> Shake {
    Shake {
        d: Sha3 {
            a: [0; 200],
            n: 0,
            rate: RATE_K512,
            dsbyte: DSBYTE_SHAKE,
            output_len: 64,
            state: digest::SpongeDirection::Absorbing,
        },
        init_block: Vec::new(),
    }
}

// NewCShake128 creates a new cSHAKE128 XOF.
//
// N is used to define functions based on cSHAKE, it can be empty when plain
// cSHAKE is desired. S is a customization byte string used for domain
// separation. When N and S are both empty, this is equivalent to NewShake128.
pub fn new_cshake128(n: &[u8], s: &[u8]) -> Shake {
    if n.is_empty() && s.is_empty() {
        return new_shake128();
    }
    new_cshake(n, s, RATE_K256, 32, DSBYTE_CSHAKE)
}

// NewCShake256 creates a new cSHAKE256 XOF.
//
// N is used to define functions based on cSHAKE, it can be empty when plain
// cSHAKE is desired. S is a customization byte string used for domain
// separation. When N and S are both empty, this is equivalent to NewShake256.
pub fn new_cshake256(n: &[u8], s: &[u8]) -> Shake {
    if n.is_empty() && s.is_empty() {
        return new_shake256();
    }
    new_cshake(n, s, RATE_K512, 64, DSBYTE_CSHAKE)
}

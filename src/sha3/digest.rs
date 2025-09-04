use crate::{core::CoreWrite, error::CryptoResult, hash::HashUser};

use super::*;

/// spongeDirection indicates the direction bytes are flowing through the sponge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum SpongeDirection {
    /// spongeAbsorbing indicates that the sponge is absorbing input.
    Absorbing = 0,
    /// spongeSqueezing indicates that the sponge is being squeezed.
    Squeezing = 1,
}

/// [Sha3] is a SHA-3 hash implementation.
#[derive(Debug, Clone)]
pub struct Sha3<const N: usize> {
    /// main state of the hash
    pub(super) a: [u8; 1600 / 8], // 200 bytes

    /// a[n:rate] is the buffer. If absorbing, it's the remaining space to XOR
    /// into before running the permutation. If squeezing, it's the remaining
    /// output to produce before running the permutation.
    pub(super) n: usize,
    pub(super) rate: usize,

    /// dsbyte contains the "domain separation" bits and the first bit of
    /// the padding. Sections 6.1 and 6.2 of [1] separate the outputs of the
    /// SHA-3 and SHAKE functions by appending bitstrings to the message.
    /// Using a little-endian bit-ordering convention, these are "01" for SHA-3
    /// and "1111" for SHAKE, or 00000010b and 00001111b, respectively. Then the
    /// padding rule from section 5.1 is applied to pad the message to a multiple
    /// of the rate, which involves adding a "1" bit, zero or more "0" bits, and
    /// a final "1" bit. We merge the first "1" bit from the padding into dsbyte,
    /// giving 00000110b (0x06) and 00011111b (0x1f).
    /// [1] <http://csrc.nist.gov/publications/drafts/fips-202/fips_202_draft.pdf>
    ///     "Draft FIPS 202: SHA-3 Standard: Permutation-Based Hash and
    ///      Extendable-Output Functions (May 2014)"
    pub(super) dsbyte: u8,

    /// whether the sponge is absorbing or squeezing
    pub(super) state: SpongeDirection,
}

impl<const N: usize> Sha3<N> {
    /// permute applies the KeccakF-1600 permutation.
    fn permute(&mut self) {
        keccak_f1600(&mut self.a);
        self.n = 0;
    }

    /// padAndPermute appends the domain separation bits in dsbyte, applies
    /// the multi-bitrate 10..1 padding rule, and permutes the state.
    fn pad_and_permute(&mut self) {
        // Pad with this instance's domain-separator bits. We know that there's
        // at least one byte of space in the sponge because, if it were full,
        // permute would have been called to empty it. dsbyte also contains the
        // first one bit for the padding. See the comment in the state struct.
        self.a[self.n] ^= self.dsbyte;
        // This adds the final one bit for the padding. Because of the way that
        // bits are numbered from the LSB upwards, the final bit is the MSB of
        // the last byte.
        self.a[self.rate - 1] ^= 0x80;
        // Apply the permutation
        self.permute();
        self.state = SpongeDirection::Squeezing;
    }

    /// read squeezes an arbitrary number of bytes from the sponge.
    pub(crate) fn read_generic(&mut self, out: &mut [u8]) -> CryptoResult<usize> {
        // If we're still absorbing, pad and apply the permutation.
        if self.state == SpongeDirection::Absorbing {
            self.pad_and_permute();
        }

        let n = out.len();
        let mut out = out;

        // Now, do the squeezing.
        while !out.is_empty() {
            // Apply the permutation if we've squeezed the sponge dry.
            if self.n == self.rate {
                self.permute();
            }

            let x = core::cmp::min(out.len(), self.rate - self.n);
            out[..x].copy_from_slice(&self.a[self.n..self.n + x]);
            self.n += x;
            out = &mut out[x..];
        }

        Ok(n)
    }

    fn sum_generic(&self) -> [u8; N] {
        if self.state != SpongeDirection::Absorbing {
            panic!("sha3: Sum after Read");
        }

        // Make a copy of the original hash so that caller can keep writing
        // and summing.
        let mut dup = self.clone();
        let mut hash = [0u8; N];
        dup.read_generic(&mut hash).unwrap();

        hash
    }

    #[cfg(feature = "alloc")]
    pub(crate) fn append_binary(&self, b: &mut Vec<u8>) -> CryptoResult<Vec<u8>> {
        match self.dsbyte {
            DSBYTE_SHA3 => b.extend_from_slice(MAGIC_SHA3.as_bytes()),
            DSBYTE_SHAKE => b.extend_from_slice(MAGIC_SHAKE.as_bytes()),
            DSBYTE_CSHAKE => b.extend_from_slice(MAGIC_CSHAKE.as_bytes()),
            DSBYTE_KECCAK => b.extend_from_slice(MAGIC_KECCAK.as_bytes()),
            _ => panic!("unknown dsbyte"),
        }
        // rate is at most 168, and n is at most rate.
        b.push(self.rate as u8);
        b.extend_from_slice(&self.a);
        b.push(self.n as u8);
        b.push(self.state as u8);
        Ok(b.clone())
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> crate::hmac::Marshalable for Sha3<N> {
    fn marshal_binary(&self) -> CryptoResult<Vec<u8>> {
        let mut b = Vec::with_capacity(MARSHALED_SIZE);
        self.append_binary(&mut b)
    }
    fn unmarshal_binary(&mut self, b: &[u8]) -> CryptoResult<()> {
        use crate::error::CryptoError;

        if b.len() != MARSHALED_SIZE {
            return Err(CryptoError::InvalidHashState);
        }

        let magic = std::str::from_utf8(&b[..MAGIC_SHA3.len()])?;
        let b = &b[MAGIC_SHA3.len()..];

        let valid = match magic {
            MAGIC_SHA3 => self.dsbyte == DSBYTE_SHA3,
            MAGIC_SHAKE => self.dsbyte == DSBYTE_SHAKE,
            MAGIC_CSHAKE => self.dsbyte == DSBYTE_CSHAKE,
            MAGIC_KECCAK => self.dsbyte == DSBYTE_KECCAK,
            _ => false,
        };

        if !valid {
            return Err(CryptoError::InvalidHashIdentifier);
        }

        let rate = b[0] as usize;
        let b = &b[1..];
        if rate != self.rate {
            Err("sha3: invalid hash state function".to_string())?;
        }

        {
            let len = self.a.len();
            self.a.copy_from_slice(&b[..len]);
        }
        let b = &b[self.a.len()..];

        let n = b[0] as usize;
        let state = match b[1] {
            0 => SpongeDirection::Absorbing,
            1 => SpongeDirection::Squeezing,
            _ => Err("sha3: invalid hash state".to_string())?,
        };

        if n > self.rate {
            Err("sha3: invalid hash state".to_string())?;
        }
        self.n = n;
        self.state = state;

        Ok(())
    }
}

impl<const N: usize> CoreWrite for Sha3<N> {
    fn write(&mut self, p: &[u8]) -> CryptoResult<usize> {
        if self.state != SpongeDirection::Absorbing {
            panic!("sha3: Write after Read");
        }

        let n = p.len();
        let mut p = p;

        while !p.is_empty() {
            let src = {
                let ptr = self.a.as_ptr();
                unsafe { core::slice::from_raw_parts(ptr, self.a.len()) }
            };
            let x = xor_bytes(&mut self.a[self.n..self.rate], &src[self.n..self.rate], p);
            self.n += x;
            p = &p[x..];

            // If the sponge is full, apply the permutation.
            if self.n == self.rate {
                self.permute();
            }
        }

        Ok(n)
    }

    fn flush(&mut self) -> CryptoResult<()> {
        Ok(())
    }
}

impl<const N: usize> HashUser for Sha3<N> {
    /// BlockSize returns the rate of sponge underlying this hash function.
    fn block_size(&self) -> usize {
        self.rate
    }

    /// Size returns the output size of the hash function in bytes.
    fn size(&self) -> usize {
        N
    }

    /// Reset resets the Digest to its initial state.
    fn reset(&mut self) {
        // Zero the permutation's state.
        for i in 0..self.a.len() {
            self.a[i] = 0;
        }
        self.state = SpongeDirection::Absorbing;
        self.n = 0;
    }
}

impl<const N: usize> crate::hash::Hash<N> for Sha3<N> {
    /// Sum appends the current hash to b and returns the resulting slice.
    /// It does not change the underlying hash state.
    fn sum(&mut self) -> [u8; N] {
        self.sum_generic()
    }
}

// Constants for marshaling
const MAGIC_SHA3: &str = "sha\x08";
const MAGIC_SHAKE: &str = "sha\x09";
const MAGIC_CSHAKE: &str = "sha\x0a";
const MAGIC_KECCAK: &str = "sha\x0b";
// magic || rate || main state || n || sponge direction
pub(crate) const MARSHALED_SIZE: usize = 4 + 1 + 200 + 1 + 1;

/// XOR bytes from src into dst, returning the number of bytes processed
fn xor_bytes(dst: &mut [u8], _src1: &[u8], src2: &[u8]) -> usize {
    let n = core::cmp::min(dst.len(), src2.len());
    for i in 0..n {
        dst[i] ^= src2[i];
    }
    n
}

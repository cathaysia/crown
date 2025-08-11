//! Module chacha20 implements the ChaCha20 and XChaCha20 encryption algorithms
//! as specified in RFC 8439 and draft-irtf-cfrg-xchacha-01.

#[cfg(test)]
mod tests;

mod generic;

use crate::cipher::StreamCipher;
use crate::error::{CryptoError, CryptoResult};
use crate::utils::inexact_overlap;
use bytes::{Buf, BufMut};

const BUF_SIZE: usize = 64;

// The constant first 4 words of the ChaCha20 state.
const J0: u32 = 0x61707865; // expa
const J1: u32 = 0x3320646e; // nd 3
const J2: u32 = 0x79622d32; // 2-by
const J3: u32 = 0x6b206574; // te k

/// Cipher is a stateful instance of ChaCha20 or XChaCha20 using a particular key
/// and nonce. A Cipher implements the StreamCipher trait.
pub struct Chacha20 {
    // The ChaCha20 state is 16 words: 4 constant, 8 of key, 1 of counter
    // (incremented after each block), and 3 of nonce.
    key: [u32; 8],
    counter: u32,
    nonce: [u32; 3],

    // The last len bytes of buf are leftover key stream bytes from the previous
    // xor_key_stream invocation. The size of buf depends on how many blocks are
    // computed at a time by xor_key_stream_blocks.
    buf: [u8; BUF_SIZE],
    len: usize,

    // overflow is set when the counter overflowed, no more blocks can be
    // generated, and the next xor_key_stream call should panic.
    overflow: bool,

    // The counter-independent results of the first round are cached after they
    // are computed the first time.
    precomp_done: bool,
    p1: u32,
    p5: u32,
    p9: u32,
    p13: u32,
    p2: u32,
    p6: u32,
    p10: u32,
    p14: u32,
    p3: u32,
    p7: u32,
    p11: u32,
    p15: u32,
}

impl StreamCipher for Chacha20 {
    fn xor_key_stream(&mut self, dst: &mut [u8], mut src: &[u8]) -> CryptoResult<()> {
        if src.is_empty() {
            return Ok(());
        }
        if dst.len() < src.len() {
            return Err(CryptoError::InvalidLength);
        }
        let mut dst = &mut dst[..src.len()];
        if inexact_overlap(dst, src) {
            return Err(CryptoError::InvalidBufferOverlap);
        }

        // First, drain any remaining key stream from a previous xor_key_stream.
        if self.len != 0 {
            let mut key_stream = &self.buf[BUF_SIZE - self.len..];
            if src.len() < key_stream.len() {
                key_stream = &key_stream[..src.len()];
            }
            let key_stream = key_stream;
            for i in 0..key_stream.len() {
                dst[i] = src[i] ^ key_stream[i];
            }
            self.len -= key_stream.len();
            dst = &mut dst[key_stream.len()..];
            src = &src[key_stream.len()..];
        }

        if src.is_empty() {
            return Ok(());
        }

        // If we'd need to let the counter overflow and keep generating output,
        // panic immediately. If instead we'd only reach the last block, remember
        // not to generate any more output after the buffer is drained.
        let num_blocks = src.len().div_ceil(Self::block_size());
        if self.overflow || u64::from(self.counter) + num_blocks as u64 > 1 << 32 {
            return Err(CryptoError::CounterOverflow);
        } else if u64::from(self.counter) + num_blocks as u64 == 1 << 32 {
            self.overflow = true;
        }

        // xor_key_stream_blocks implementations expect input lengths that are a
        // multiple of BUF_SIZE. Platform-specific ones process multiple blocks at a
        // time, so have BUF_SIZE that are a multiple of Self::block_size().
        let full = src.len() - src.len() % BUF_SIZE;
        if full > 0 {
            self.xor_key_stream_blocks(&mut dst[..full], &src[..full]);
        }
        let dst = &mut dst[full..];
        let src = &src[full..];

        // If using a multi-block xor_key_stream_blocks would overflow, use the generic
        // one that does one block at a time.
        const BLOCKS_PER_BUF: u64 = BUF_SIZE as u64 / Chacha20::block_size() as u64;
        if u64::from(self.counter) + BLOCKS_PER_BUF > 1 << 32 {
            self.buf = [0; BUF_SIZE];
            let num_blocks = src.len().div_ceil(Self::block_size());
            let buf_len = num_blocks * Self::block_size();
            let buf = &mut self.buf[BUF_SIZE - buf_len..];
            buf[..src.len()].copy_from_slice(src);
            let buf = unsafe {
                let ptr = buf.as_mut_ptr();
                std::slice::from_raw_parts_mut(ptr, buf_len)
            };
            let src = unsafe {
                let ptr = buf.as_ptr();
                std::slice::from_raw_parts(ptr, buf_len)
            };
            self.xor_key_stream_blocks_generic(buf, src);
            self.len = buf_len - src.len();
            return Ok(());
        }

        // If we have a partial (multi-)block, pad it for xor_key_stream_blocks, and
        // keep the leftover keystream for the next xor_key_stream invocation.
        if !src.is_empty() {
            self.buf = [0; BUF_SIZE];
            self.buf[..src.len()].copy_from_slice(src);
            let buf = unsafe {
                let ptr = self.buf.as_mut_ptr();
                std::slice::from_raw_parts_mut(ptr, self.buf.len())
            };
            let src = unsafe {
                let ptr = buf.as_ptr();
                std::slice::from_raw_parts(ptr, self.buf.len())
            };
            self.xor_key_stream_blocks(&mut buf[..BUF_SIZE], &src[..BUF_SIZE]);
            let len = dst.len().min(self.buf.len());
            dst[..len].copy_from_slice(&self.buf[..len]);
            self.len = BUF_SIZE - src.len();
        }

        Ok(())
    }
}

impl Chacha20 {
    /// [Self::new_unauthenticated_cipher] creates a new ChaCha20 stream cipher.
    ///
    /// - if the key is 32 bytes long, then create a chacha20 cipher.
    /// - if the key is 24 bytes long, then create a xchacha20 cipher.
    ///
    /// # NOTE
    ///
    /// like all stream ciphers, is not authenticated and allows attackers to
    /// silently tamper with the plaintext.
    ///
    /// # Error
    ///
    /// Return error if the key is not 12 or 24 bytes. Or the nonce is not 12 or 24 bytes.
    pub fn new_unauthenticated_cipher(key: &[u8], nonce: &[u8]) -> CryptoResult<Self> {
        let mut c = Chacha20 {
            key: [0; 8],
            counter: 0,
            nonce: [0; 3],
            buf: [0; BUF_SIZE],
            len: 0,
            overflow: false,
            precomp_done: false,
            p1: 0,
            p5: 0,
            p9: 0,
            p13: 0,
            p2: 0,
            p6: 0,
            p10: 0,
            p14: 0,
            p3: 0,
            p7: 0,
            p11: 0,
            p15: 0,
        };

        if key.len() != Self::key_size() {
            return Err(CryptoError::InvalidKeySize(key.len()));
        }

        let (key, nonce) = if nonce.len() == Self::nonce_size_x() {
            // XChaCha20 uses the ChaCha20 core to mix 16 bytes of the nonce into a
            // derived key, allowing it to operate on a nonce of 24 bytes. See
            // draft-irtf-cfrg-xchacha-01, Section 2.3.
            let derived_key = h_chacha20(key, &nonce[0..16])?;
            let mut c_nonce = vec![0; Self::nonce_size()];
            c_nonce[4..12].copy_from_slice(&nonce[16..24]);
            (derived_key, c_nonce)
        } else if nonce.len() == Self::nonce_size() {
            (key.to_vec(), nonce.to_vec())
        } else {
            return Err(CryptoError::InvalidIvSize(nonce.len()));
        };

        let mut key = key.as_slice();
        c.key = [
            key.get_u32_le(),
            key.get_u32_le(),
            key.get_u32_le(),
            key.get_u32_le(),
            key.get_u32_le(),
            key.get_u32_le(),
            key.get_u32_le(),
            key.get_u32_le(),
        ];

        let mut nonce = nonce.as_slice();

        c.nonce = [nonce.get_u32_le(), nonce.get_u32_le(), nonce.get_u32_le()];

        Ok(c)
    }

    pub const fn block_size() -> usize {
        64
    }

    pub const fn key_size() -> usize {
        32
    }

    pub const fn nonce_size() -> usize {
        12
    }

    pub const fn nonce_size_x() -> usize {
        24
    }

    /// set_counter sets the Cipher counter. The next invocation of xor_key_stream will
    /// behave as if (64 * counter) bytes had been encrypted so far.
    ///
    /// To prevent accidental counter reuse, set_counter panics if counter is less
    /// than the current value.
    ///
    /// Note that the execution time of xor_key_stream is not independent of the
    /// counter value.
    pub(crate) fn set_counter(&mut self, counter: u32) {
        // Internally, self may buffer multiple blocks, which complicates this
        // implementation slightly. When checking whether the counter has rolled
        // back, we must use both self.counter and self.len to determine how many blocks
        // we have already output.
        let output_counter = self.counter - (self.len as u32 / Self::block_size() as u32);
        if self.overflow || counter < output_counter {
            panic!("chacha20: set_counter attempted to rollback counter");
        }

        // In the general case, we set the new counter value and reset self.len to 0,
        // causing the next call to xor_key_stream to refill the buffer. However, if
        // we're advancing within the existing buffer, we can save work by simply
        // setting self.len.
        if counter < self.counter {
            self.len = ((self.counter - counter) * Self::block_size() as u32) as usize;
        } else {
            self.counter = counter;
            self.len = 0;
        }
    }

    fn xor_key_stream_blocks_generic(&mut self, dst: &mut [u8], src: &[u8]) {
        if dst.len() != src.len() || dst.len() % Self::block_size() != 0 {
            panic!("chacha20: internal error: wrong dst and/or src length");
        }

        // To generate each block of key stream, the initial cipher state
        // (represented below) is passed through 20 rounds of shuffling,
        // alternatively applying quarterRounds by columns (like 1, 5, 9, 13)
        // or by diagonals (like 1, 6, 11, 12).
        //
        //      0:cccccccc   1:cccccccc   2:cccccccc   3:cccccccc
        //      4:kkkkkkkk   5:kkkkkkkk   6:kkkkkkkk   7:kkkkkkkk
        //      8:kkkkkkkk   9:kkkkkkkk  10:kkkkkkkk  11:kkkkkkkk
        //     12:bbbbbbbb  13:nnnnnnnn  14:nnnnnnnn  15:nnnnnnnn
        //
        //            c=constant k=key b=blockcount n=nonce
        let (c0, c1, c2, c3) = (J0, J1, J2, J3);
        let (c4, c5, c6, c7) = (self.key[0], self.key[1], self.key[2], self.key[3]);
        let (c8, c9, c10, c11) = (self.key[4], self.key[5], self.key[6], self.key[7]);
        let (_, c13, c14, c15) = (self.counter, self.nonce[0], self.nonce[1], self.nonce[2]);

        // Three quarters of the first round don't depend on the counter, so we can
        // calculate them here, and reuse them for multiple blocks in the loop, and
        // for future xor_key_stream invocations.
        if !self.precomp_done {
            (self.p1, self.p5, self.p9, self.p13) = quarter_round(c1, c5, c9, c13);
            (self.p2, self.p6, self.p10, self.p14) = quarter_round(c2, c6, c10, c14);
            (self.p3, self.p7, self.p11, self.p15) = quarter_round(c3, c7, c11, c15);

            self.precomp_done = true;
        }

        let mut src = src;
        let mut dst = dst;
        while src.len() >= 64 && dst.len() >= 64 {
            // The remainder of the first column round.
            let (fcr0, fcr4, fcr8, fcr12) = quarter_round(c0, c4, c8, self.counter);

            // The second diagonal round.
            let (x0, x5, x10, x15) = quarter_round(fcr0, self.p5, self.p10, self.p15);
            let (x1, x6, x11, x12) = quarter_round(self.p1, self.p6, self.p11, fcr12);
            let (x2, x7, x8, x13) = quarter_round(self.p2, self.p7, fcr8, self.p13);
            let (x3, x4, x9, x14) = quarter_round(self.p3, fcr4, self.p9, self.p14);

            // The remaining 18 rounds.
            let (mut x0, mut x4, mut x8, mut x12) = (x0, x4, x8, x12);
            let (mut x1, mut x5, mut x9, mut x13) = (x1, x5, x9, x13);
            let (mut x2, mut x6, mut x10, mut x14) = (x2, x6, x10, x14);
            let (mut x3, mut x7, mut x11, mut x15) = (x3, x7, x11, x15);

            for _ in 0..9 {
                // Column round.
                (x0, x4, x8, x12) = quarter_round(x0, x4, x8, x12);
                (x1, x5, x9, x13) = quarter_round(x1, x5, x9, x13);
                (x2, x6, x10, x14) = quarter_round(x2, x6, x10, x14);
                (x3, x7, x11, x15) = quarter_round(x3, x7, x11, x15);

                // Diagonal round.
                (x0, x5, x10, x15) = quarter_round(x0, x5, x10, x15);
                (x1, x6, x11, x12) = quarter_round(x1, x6, x11, x12);
                (x2, x7, x8, x13) = quarter_round(x2, x7, x8, x13);
                (x3, x4, x9, x14) = quarter_round(x3, x4, x9, x14);
            }

            // Add back the initial state to generate the key stream, then
            // XOR the key stream with the source and write out the result.
            add_xor(&mut dst[0..4], &src[0..4], x0, c0);
            add_xor(&mut dst[4..8], &src[4..8], x1, c1);
            add_xor(&mut dst[8..12], &src[8..12], x2, c2);
            add_xor(&mut dst[12..16], &src[12..16], x3, c3);
            add_xor(&mut dst[16..20], &src[16..20], x4, c4);
            add_xor(&mut dst[20..24], &src[20..24], x5, c5);
            add_xor(&mut dst[24..28], &src[24..28], x6, c6);
            add_xor(&mut dst[28..32], &src[28..32], x7, c7);
            add_xor(&mut dst[32..36], &src[32..36], x8, c8);
            add_xor(&mut dst[36..40], &src[36..40], x9, c9);
            add_xor(&mut dst[40..44], &src[40..44], x10, c10);
            add_xor(&mut dst[44..48], &src[44..48], x11, c11);
            add_xor(&mut dst[48..52], &src[48..52], x12, self.counter);
            add_xor(&mut dst[52..56], &src[52..56], x13, c13);
            add_xor(&mut dst[56..60], &src[56..60], x14, c14);
            add_xor(&mut dst[60..64], &src[60..64], x15, c15);

            self.counter += 1;

            src = &src[Self::block_size()..];
            dst = &mut dst[Self::block_size()..];
        }
    }
}

/// quarter_round is the core of ChaCha20. It shuffles the bits of 4 state words.
/// It's executed 4 times for each of the 20 ChaCha20 rounds, operating on all 16
/// words each round, in columnar or diagonal groups of 4 at a time.
fn quarter_round(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    let mut a = a;
    let mut b = b;
    let mut c = c;
    let mut d = d;

    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(16);

    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(12);

    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(8);

    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(7);

    (a, b, c, d)
}

/// add_xor adds the first two arguments, XORs the result with the third, and
/// writes it to the destination.
fn add_xor(dst: &mut [u8], src: &[u8], a: u32, b: u32) {
    let v = a.wrapping_add(b);
    let v_bytes = v.to_le_bytes();
    for i in 0..4 {
        dst[i] = src[i] ^ v_bytes[i];
    }
}

/// h_chacha20 uses the ChaCha20 core to generate a derived key from a 32 bytes
/// key and a 16 bytes nonce. It returns an error if key or nonce have any other
/// length. It is used as part of the XChaCha20 construction.
fn h_chacha20(mut key: &[u8], mut nonce: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != Chacha20::key_size() {
        return Err(CryptoError::InvalidKeySize(key.len()));
    }
    if nonce.len() != 16 {
        return Err(CryptoError::InvalidIvSize(nonce.len()));
    }

    let mut x0 = J0;
    let mut x1 = J1;
    let mut x2 = J2;
    let mut x3 = J3;
    let mut x4 = key.get_u32_le();
    let mut x5 = key.get_u32_le();
    let mut x6 = key.get_u32_le();
    let mut x7 = key.get_u32_le();
    let mut x8 = key.get_u32_le();
    let mut x9 = key.get_u32_le();
    let mut x10 = key.get_u32_le();
    let mut x11 = key.get_u32_le();
    let mut x12 = nonce.get_u32_le();
    let mut x13 = nonce.get_u32_le();
    let mut x14 = nonce.get_u32_le();
    let mut x15 = nonce.get_u32_le();

    for _ in 0..10 {
        // Diagonal round.
        (x0, x4, x8, x12) = quarter_round(x0, x4, x8, x12);
        (x1, x5, x9, x13) = quarter_round(x1, x5, x9, x13);
        (x2, x6, x10, x14) = quarter_round(x2, x6, x10, x14);
        (x3, x7, x11, x15) = quarter_round(x3, x7, x11, x15);
        // Column round.
        (x0, x5, x10, x15) = quarter_round(x0, x5, x10, x15);
        (x1, x6, x11, x12) = quarter_round(x1, x6, x11, x12);
        (x2, x7, x8, x13) = quarter_round(x2, x7, x8, x13);
        (x3, x4, x9, x14) = quarter_round(x3, x4, x9, x14);
    }

    let mut out = vec![0; 32];
    {
        let mut outx = out.as_mut_slice();
        outx.put_u32_le(x0);
        outx.put_u32_le(x1);
        outx.put_u32_le(x2);
        outx.put_u32_le(x3);
        outx.put_u32_le(x12);
        outx.put_u32_le(x13);
        outx.put_u32_le(x14);
        outx.put_u32_le(x15);
    }

    Ok(out)
}

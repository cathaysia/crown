//! This file provides the generic implementation of Sum and MAC. Other files
//! might provide optimized assembly implementations of some of this code.
//!
//! Poly1305 [RFC 7539] is a relatively simple algorithm: the authentication tag
//! for a 64 bytes message is approximately
//!
//!```text
//!     s + m[0:16] * r⁴ + m[16:32] * r³ + m[32:48] * r² + m[48:64] * r  mod  2¹³⁰ - 5
//!```
//!
//! for some secret r and s. It can be computed sequentially like
//!
//! ```text
//!     for len(msg) > 0:
//!         h += read(msg, 16)
//!         h *= r
//!         h %= 2¹³⁰ - 5
//!     return h + s
//! ```
//!
//! All the complexity is about doing performant constant-time math on numbers
//! larger than any available numeric type.

mod generic;
use generic::*;

use core::convert::TryInto;
use core::ops::Add;

use bytes::Buf;

use crate::utils::copy;

pub const TAG_SIZE: usize = 16;

// [R_MASK0, R_MASK1] is the specified Poly1305 clamping mask in little-endian. It
// clears some bits of the secret coefficient to make it possible to implement
// multiplication more efficiently.
const R_MASK0: u64 = 0x0FFFFFFC0FFFFFFF;
const R_MASK1: u64 = 0x0FFFFFFC0FFFFFFC;

const MASK_LOW_2_BITS: u64 = 0x0000000000000003;
const MASK_NOT_LOW_2_BITS: u64 = !MASK_LOW_2_BITS;

// [P0, P1, P2] is 2¹³⁰ - 5 in little endian order.
const P0: u64 = 0xFFFFFFFFFFFFFFFB;
const P1: u64 = 0xFFFFFFFFFFFFFFFF;
const P2: u64 = 0x0000000000000003;

/// Computes the Poly1305 authentication tag for the given message using the provided key.
pub fn sum_generic(out: &mut [u8; TAG_SIZE], msg: &[u8], key: &[u8; 32]) {
    let mut mac = MacGeneric::new(key);
    mac.write(msg);
    mac.sum(out);
}

/// MacState holds numbers in saturated 64-bit little-endian limbs. That is,
/// the value of [x0, x1, x2] is x[0] + x[1] * 2⁶⁴ + x[2] * 2¹²⁸.
#[derive(Clone, Copy, Default)]
struct MacState {
    // h is the main accumulator. It is to be interpreted modulo 2¹³⁰ - 5, but
    // can grow larger during and after rounds. It must, however, remain below
    // 2 * (2¹³⁰ - 5).
    h: [u64; 3],
    // r and s are the private key components.
    r: [u64; 2],
    s: [u64; 2],
}

#[derive(Default)]
pub(crate) struct MacGeneric {
    mac_state: MacState,
    buffer: [u8; TAG_SIZE],
    offset: usize,
}

impl MacGeneric {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut m: MacGeneric = unsafe { core::mem::zeroed() };
        initialize(key, &mut m.mac_state);

        m
    }
    /// Write splits the incoming message into TAG_SIZE chunks, and passes them to
    /// update. It buffers incomplete chunks.
    pub fn write(&mut self, mut p: &[u8]) -> usize {
        let nn = p.len();
        if self.offset > 0 {
            let n = copy(&mut self.buffer[self.offset..], p);
            if self.offset + n < TAG_SIZE {
                self.offset += n;
                return nn;
            }
            p = &p[n..];
            self.offset = 0;
            update(&mut self.mac_state, &self.buffer);
        }

        let n = p.len() - (p.len() % TAG_SIZE);
        if n > 0 {
            update(&mut self.mac_state, &p[..n]);
            p = &p[n..];
        }

        if !p.is_empty() {
            self.offset += copy(&mut self.buffer[self.offset..], p);
        }

        nn
    }

    /// Sum flushes the last incomplete chunk from the buffer, if any, and generates
    /// the MAC output. It does not modify its state, in order to allow for multiple
    /// calls to Sum, even if no Write is allowed after Sum.
    pub fn sum(&self, out: &mut [u8; TAG_SIZE]) {
        let mut state = self.mac_state;
        if self.offset > 0 {
            update(&mut state, &self.buffer[..self.offset]);
        }
        finalize(out, &state.h, &state.s);
    }
}

/// Initializes the MAC state with the given key.
fn initialize(key: &[u8; 32], m: &mut MacState) {
    m.r[0] = u64::from_le_bytes(key[0..8].try_into().unwrap()) & R_MASK0;
    m.r[1] = u64::from_le_bytes(key[8..16].try_into().unwrap()) & R_MASK1;
    m.s[0] = u64::from_le_bytes(key[16..24].try_into().unwrap());
    m.s[1] = u64::from_le_bytes(key[24..32].try_into().unwrap());
}

/// Returns x if v == 1 and y if v == 0, in constant time.
fn select64(v: u64, x: u64, y: u64) -> u64 {
    (!v.wrapping_sub(1)) & x | (v.wrapping_sub(1)) & y
}

/// Finalizes the MAC computation and writes the result to out.
fn finalize(out: &mut [u8; TAG_SIZE], h: &[u64; 3], s: &[u64; 2]) {
    let mut h0 = h[0];
    let mut h1 = h[1];
    let h2 = h[2];

    // After the partial reduction in update_generic, h might be more than
    // 2¹³⁰ - 5, but will be less than 2 * (2¹³⁰ - 5). To complete the reduction
    // in constant time, we compute t = h - (2¹³⁰ - 5), and select h as the
    // result if the subtraction underflows, and t otherwise.

    let (h_minus_p0, b) = h0.overflowing_sub(P0);
    let (h_minus_p1, b) = multi_overflowing_sub(h1, P1, b);
    let (_, b) = multi_overflowing_sub(h2, P2, b);
    let b = b as u64;

    // h = h if h < p else h - p
    h0 = select64(b, h0, h_minus_p0);
    h1 = select64(b, h1, h_minus_p1);

    // Finally, we compute the last Poly1305 step
    //
    //     tag = h + s  mod  2¹²⁸
    //
    // by just doing a wide addition with the 128 low bits of h and discarding
    // the overflow.
    let (h0, c) = h0.overflowing_add(s[0]);
    let h1 = h1.wrapping_add(s[1]).wrapping_add(c as u64);

    out[0..8].copy_from_slice(&h0.to_le_bytes());
    out[8..16].copy_from_slice(&h1.to_le_bytes());
}

fn multi_overflowing_sub(x: u64, y: u64, borrow: bool) -> (u64, bool) {
    let (diff, b1) = x.overflowing_sub(y);
    let (diff, b2) = diff.overflowing_sub(borrow as u64);

    (diff, b1 | b2)
}

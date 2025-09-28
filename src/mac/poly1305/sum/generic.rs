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
//!
use core::convert::TryInto;
use core::ops::Add;

use bytes::Buf;

use crate::utils::copy;

const TAG_SIZE: usize = 16;

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
pub fn sum_generic(msg: &[u8], key: &[u8; 32]) -> [u8; TAG_SIZE] {
    let mut mac = MacGeneric::new(key);
    mac.write(msg);
    mac.sum()
}

/// MacState holds numbers in saturated 64-bit little-endian limbs. That is,
/// the value of [x0, x1, x2] is x[0] + x[1] * 2⁶⁴ + x[2] * 2¹²⁸.
#[derive(Clone, Copy)]
pub struct MacState {
    // h is the main accumulator. It is to be interpreted modulo 2¹³⁰ - 5, but
    // can grow larger during and after rounds. It must, however, remain below
    // 2 * (2¹³⁰ - 5).
    h: [u64; 3],
    // r and s are the private key components.
    r: [u64; 2],
    s: [u64; 2],
}

pub(crate) struct MacGeneric {
    mac_state: MacState,
    buffer: [u8; TAG_SIZE],
    offset: usize,
}

impl MacGeneric {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut m: MacGeneric = MacGeneric {
            mac_state: MacState {
                h: [0; 3],
                r: [0; 2],
                s: [0; 2],
            },
            buffer: [0u8; TAG_SIZE],
            offset: 0,
        };
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
    pub fn sum(&self) -> [u8; TAG_SIZE] {
        let mut state = self.mac_state;
        if self.offset > 0 {
            update(&mut state, &self.buffer[..self.offset]);
        }
        finalize(&state.h, &state.s)
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
fn finalize(h: &[u64; 3], s: &[u64; 2]) -> [u8; TAG_SIZE] {
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

    let mut out = [0u8; TAG_SIZE];
    out[0..8].copy_from_slice(&h0.to_le_bytes());
    out[8..16].copy_from_slice(&h1.to_le_bytes());
    out
}

fn multi_overflowing_sub(x: u64, y: u64, borrow: bool) -> (u64, bool) {
    let (diff, b1) = x.overflowing_sub(y);
    let (diff, b2) = diff.overflowing_sub(borrow as u64);

    (diff, b1 | b2)
}

/// Updates the MAC state with the given message.
pub(crate) fn update(state: &mut MacState, msg: &[u8]) {
    let [mut h0, mut h1, mut h2] = state.h;
    let [r0, r1] = state.r;

    let mut msg_slice = msg;
    while !msg_slice.is_empty() {
        // For the first step, h + m, we use a chain of additions.
        // The resulting value of h might exceed 2¹³⁰ - 5, but will be partially
        // reduced at the end of the multiplication below.
        //
        // The spec requires us to set a bit just above the message size, not to
        // hide leading zeroes. For full chunks, that's 1 << 128, so we can just
        // add 1 to the most significant (2¹²⁸) limb, h2.
        if msg_slice.len() >= TAG_SIZE {
            let (new_h0, carry) = h0.overflowing_add(msg_slice.get_u64_le());
            h0 = new_h0;

            let (new_h1, carry1) = h1.overflowing_add(msg_slice.get_u64_le());
            let (new_h1, carry2) = new_h1.overflowing_add(carry as u64);
            h1 = new_h1;

            h2 = h2
                .wrapping_add((carry1 as u64) | (carry2 as u64))
                .wrapping_add(1);
        } else {
            let mut buf = [0u8; TAG_SIZE];
            buf[..msg_slice.len()].copy_from_slice(msg_slice);
            buf[msg_slice.len()] = 1;
            let mut buf = buf.as_slice();

            let (new_h0, carry) = h0.overflowing_add(buf.get_u64_le());
            h0 = new_h0;

            let (new_h1, carry1) = h1.overflowing_add(buf.get_u64_le());
            let (new_h1, carry2) = new_h1.overflowing_add(carry as u64);
            h1 = new_h1;

            h2 = h2.wrapping_add((carry1 as u64) | (carry2 as u64));

            msg_slice = &[];
        }

        // Multiplication of big number limbs is similar to elementary school
        // columnar multiplication. Instead of digits, there are 64-bit limbs.
        //
        // We are multiplying a 3 limbs number, h, by a 2 limbs number, r.
        //
        //                        h2    h1    h0  x
        //                              r1    r0  =
        //                       ----------------
        //                      h2r0  h1r0  h0r0     <-- individual 128-bit products
        //            +   h2r1  h1r1  h0r1
        //               ------------------------
        //                 m3    m2    m1    m0      <-- result in 128-bit overlapping limbs
        //               ------------------------
        //         m3.hi m2.hi m1.hi m0.hi           <-- carry propagation
        //     +         m3.lo m2.lo m1.lo m0.lo
        //        -------------------------------
        //           t4    t3    t2    t1    t0      <-- final result in 64-bit limbs

        let h0r0 = mul64(h0, r0);
        let h1r0 = mul64(h1, r0);
        let h2r0 = mul64(h2, r0);
        let h0r1 = mul64(h0, r1);
        let h1r1 = mul64(h1, r1);
        let h2r1 = mul64(h2, r1);

        // Since h2 is known to be at most 7 (5 + 1 + 1), and r0 and r1 have their
        // top 4 bits cleared by R_MASK{0,1}, we know that their product is not going
        // to overflow 64 bits, so we can ignore the high part of the products.
        //
        // This also means that the product doesn't have a fifth limb (t4).
        if h2r0.hi != 0 {
            panic!("poly1305: unexpected overflow");
        }
        if h2r1.hi != 0 {
            panic!("poly1305: unexpected overflow");
        }

        let m0 = h0r0;
        let m1 = add128(h1r0, h0r1); // These two additions don't overflow thanks again
        let m2 = add128(h2r0, h1r1); // to the 4 masked bits at the top of r0 and r1.
        let m3 = h2r1;

        let t0 = m0.lo;
        let (t1, c) = m1.lo.overflowing_add(m0.hi);
        let (t2, c1) = m2.lo.overflowing_add(m1.hi);
        let (t2, c2) = t2.overflowing_add(c as u64);
        let (t3, _) = m3.lo.overflowing_add(m2.hi);
        let (t3, _) = t3.overflowing_add((c1 as u64) | (c2 as u64));

        // Now we have the result as 4 64-bit limbs, and we need to reduce it
        // modulo 2¹³⁰ - 5. The special shape of this Crandall prime lets us do
        // a cheap partial reduction according to the reduction identity
        //
        //     c * 2¹³⁰ + n  =  c * 5 + n  mod  2¹³⁰ - 5
        //
        // because 2¹³⁰ = 5 mod 2¹³⁰ - 5. Partial reduction since the result is
        // likely to be larger than 2¹³⁰ - 5, but still small enough to fit the
        // assumptions we make about h in the rest of the code.

        // We split the final result at the 2¹³⁰ mark into h and cc, the carry.
        // Note that the carry bits are effectively shifted left by 2, in other
        // words, cc = c * 4 for the c in the reduction identity.
        h0 = t0;
        h1 = t1;
        h2 = t2 & MASK_LOW_2_BITS;
        let mut cc = Uint128 {
            lo: t2 & MASK_NOT_LOW_2_BITS,
            hi: t3,
        };

        // To add c * 5 to h, we first add cc = c * 4, and then add (cc >> 2) = c.
        let (new_h0, carry) = h0.overflowing_add(cc.lo);
        h0 = new_h0;

        let (new_h1, carry1) = h1.overflowing_add(cc.hi);
        let (new_h1, carry2) = new_h1.overflowing_add(carry as u64);
        h1 = new_h1;

        h2 = h2.wrapping_add((carry1 as u64) | (carry2 as u64));

        cc = shift_right_by_2(cc);

        let (new_h0, carry) = h0.overflowing_add(cc.lo);
        h0 = new_h0;

        let (new_h1, carry1) = h1.overflowing_add(cc.hi);
        let (new_h1, carry2) = new_h1.overflowing_add(carry as u64);
        h1 = new_h1;

        h2 = h2.wrapping_add((carry1 as u64) | (carry2 as u64));

        // h2 is at most 3 + 1 + 1 = 5, making the whole of h at most
        //
        //     5 * 2¹²⁸ + (2¹²⁸ - 1) = 6 * 2¹²⁸ - 1
    }

    state.h[0] = h0;
    state.h[1] = h1;
    state.h[2] = h2;
}

/// Shifts a 128-bit integer right by 2 bits.
fn shift_right_by_2(a: Uint128) -> Uint128 {
    Uint128 {
        lo: (a.lo >> 2) | ((a.hi & 3) << 62),
        hi: a.hi >> 2,
    }
}

/// Uint128 holds a 128-bit number as two 64-bit limbs.
#[derive(Clone, Copy, Default)]
struct Uint128 {
    lo: u64,
    hi: u64,
}

/// Multiplies two 64-bit integers and returns the 128-bit result.
fn mul64(a: u64, b: u64) -> Uint128 {
    let result = (a as u128) * (b as u128);
    Uint128 {
        lo: result as u64,
        hi: (result >> 64) as u64,
    }
}

/// Adds two 128-bit integers and returns the result.
fn add128(a: Uint128, b: Uint128) -> Uint128 {
    let mut ret = Uint128 {
        lo: a.lo.wrapping_add(b.lo),
        ..Default::default()
    };
    ret.hi = a.hi.add(b.hi);
    if a.lo.checked_add(b.lo).is_none() {
        ret.hi += 1;
    }
    ret
}

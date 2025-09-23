use super::*;

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

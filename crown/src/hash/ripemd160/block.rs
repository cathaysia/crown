//! RIPEMD-160 compression function.
//!
//! Each 64-byte block is compressed through two independent parallel lines
//! (left and right) over 80 steps each; the two results are combined with
//! the swap-in-the-middle final addition specified by Dobbertin et al.

use super::Ripemd160;

// Word selection order for the left line (r) and right line (r').
const R: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, //
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, //
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, //
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, //
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13, //
];
const R_RIGHT: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, //
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, //
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, //
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, //
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11, //
];

// Left-rotation amounts for the left line (s) and right line (s').
const S: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, //
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, //
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, //
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, //
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6, //
];
const S_RIGHT: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, //
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, //
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, //
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, //
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11, //
];

// Round constants: K_j for the left line, K'_j for the right line, one per
// 16-step round.
const K: [u32; 5] = [
    0x0000_0000,
    0x5A82_7999,
    0x6ED9_EBA1,
    0x8F1B_BCDC,
    0xA953_FD4E,
];
const K_RIGHT: [u32; 5] = [
    0x50A2_8BE6,
    0x5C4D_D124,
    0x6D70_3EF3,
    0x7A6D_76E9,
    0x0000_0000,
];

#[inline(always)]
fn f(j: usize, x: u32, y: u32, z: u32) -> u32 {
    match j / 16 {
        0 => x ^ y ^ z,
        1 => (x & y) | (!x & z),
        2 => (x | !y) ^ z,
        3 => (x & z) | (y & !z),
        _ => x ^ (y | !z),
    }
}

#[inline(always)]
#[allow(clippy::too_many_arguments)] // a RIPEMD-160 step is inherently wide
fn step(a: u32, b: u32, c: u32, d: u32, e: u32, x: u32, k: u32, rot: u32, j: usize) -> u32 {
    a.wrapping_add(f(j, b, c, d))
        .wrapping_add(x)
        .wrapping_add(k)
        .rotate_left(rot)
        .wrapping_add(e)
}

/// Compress full 64-byte chunks from `p` into `d`'s state; returns the
/// number of bytes consumed.
pub(super) fn block(d: &mut Ripemd160, p: &[u8]) -> usize {
    let n = p.len() / 64;
    for chunk in p.as_chunks::<64>().0 {
        let mut x = [0u32; 16];
        for (i, w) in x.iter_mut().enumerate() {
            *w = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }

        let (mut a, mut b, mut c, mut mut_d, mut e) = (d.s[0], d.s[1], d.s[2], d.s[3], d.s[4]);
        let (mut aa, mut bb, mut cc, mut dd, mut ee) = (a, b, c, mut_d, e);

        for j in 0..80 {
            // Left line.
            let t = step(a, b, c, mut_d, e, x[R[j]], K[j / 16], S[j], j);
            a = e;
            e = mut_d;
            mut_d = c.rotate_left(10);
            c = b;
            b = t;

            // Right line (functions applied in reverse round order).
            let t = step(
                aa,
                bb,
                cc,
                dd,
                ee,
                x[R_RIGHT[j]],
                K_RIGHT[j / 16],
                S_RIGHT[j],
                79 - j,
            );
            aa = ee;
            ee = dd;
            dd = cc.rotate_left(10);
            cc = bb;
            bb = t;
        }

        // Combine the two lines with the swap-in-the-middle addition.
        let t = d.s[1].wrapping_add(c).wrapping_add(dd);
        d.s[1] = d.s[2].wrapping_add(mut_d).wrapping_add(ee);
        d.s[2] = d.s[3].wrapping_add(e).wrapping_add(aa);
        d.s[3] = d.s[4].wrapping_add(a).wrapping_add(bb);
        d.s[4] = d.s[0].wrapping_add(b).wrapping_add(cc);
        d.s[0] = t;
    }
    n * 64
}

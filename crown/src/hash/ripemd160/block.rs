//! RIPEMD-160 compression function.
//!
//! Each 64-byte block is compressed through two independent parallel lines
//! (left and right) over 80 steps each; the two results are combined with
//! the swap-in-the-middle final addition specified by Dobbertin et al.
//!
//! The 160 steps are fully unrolled with per-round literal word indexes,
//! rotation amounts, constants and boolean functions, so the hot loop has
//! no table lookups or round dispatch.

use super::Ripemd160;

/// The five RIPEMD-160 boolean round functions, applied as `f(b, c, d)`.
#[inline(always)]
const fn f1(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}
#[inline(always)]
const fn f2(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (!b & d)
}
#[inline(always)]
const fn f3(b: u32, c: u32, d: u32) -> u32 {
    (b | !c) ^ d
}
#[inline(always)]
const fn f4(b: u32, c: u32, d: u32) -> u32 {
    (b & d) | (c & !d)
}
#[inline(always)]
const fn f5(b: u32, c: u32, d: u32) -> u32 {
    b ^ (c | !d)
}

macro_rules! step {
    ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $xw:expr, $k:expr, $rot:expr, $f:ident) => {{
        let t = $a
            .wrapping_add($f($b, $c, $d))
            .wrapping_add($xw)
            .wrapping_add($k)
            .rotate_left($rot)
            .wrapping_add($e);
        $a = $e;
        $e = $d;
        $d = $c.rotate_left(10);
        $c = $b;
        $b = t;
    }};
}

/// Compress full 64-byte chunks from `p` into `st`'s state; returns the
/// number of bytes consumed.
pub(super) fn block(st: &mut Ripemd160, p: &[u8]) -> usize {
    let n = p.len() / 64;
    for chunk in p.as_chunks::<64>().0 {
        let mut x = [0u32; 16];
        for (i, w) in x.iter_mut().enumerate() {
            *w = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }

        let (mut a, mut b, mut c, mut d, mut e) = (st.s[0], st.s[1], st.s[2], st.s[3], st.s[4]);
        let (mut aa, mut bb, mut cc, mut dd, mut ee) = (a, b, c, d, e);

        step!(a, b, c, d, e, x[0], 0x0000_0000, 11, f1);
        step!(a, b, c, d, e, x[1], 0x0000_0000, 14, f1);
        step!(a, b, c, d, e, x[2], 0x0000_0000, 15, f1);
        step!(a, b, c, d, e, x[3], 0x0000_0000, 12, f1);
        step!(a, b, c, d, e, x[4], 0x0000_0000, 5, f1);
        step!(a, b, c, d, e, x[5], 0x0000_0000, 8, f1);
        step!(a, b, c, d, e, x[6], 0x0000_0000, 7, f1);
        step!(a, b, c, d, e, x[7], 0x0000_0000, 9, f1);
        step!(a, b, c, d, e, x[8], 0x0000_0000, 11, f1);
        step!(a, b, c, d, e, x[9], 0x0000_0000, 13, f1);
        step!(a, b, c, d, e, x[10], 0x0000_0000, 14, f1);
        step!(a, b, c, d, e, x[11], 0x0000_0000, 15, f1);
        step!(a, b, c, d, e, x[12], 0x0000_0000, 6, f1);
        step!(a, b, c, d, e, x[13], 0x0000_0000, 7, f1);
        step!(a, b, c, d, e, x[14], 0x0000_0000, 9, f1);
        step!(a, b, c, d, e, x[15], 0x0000_0000, 8, f1);
        step!(a, b, c, d, e, x[7], 0x5A82_7999, 7, f2);
        step!(a, b, c, d, e, x[4], 0x5A82_7999, 6, f2);
        step!(a, b, c, d, e, x[13], 0x5A82_7999, 8, f2);
        step!(a, b, c, d, e, x[1], 0x5A82_7999, 13, f2);
        step!(a, b, c, d, e, x[10], 0x5A82_7999, 11, f2);
        step!(a, b, c, d, e, x[6], 0x5A82_7999, 9, f2);
        step!(a, b, c, d, e, x[15], 0x5A82_7999, 7, f2);
        step!(a, b, c, d, e, x[3], 0x5A82_7999, 15, f2);
        step!(a, b, c, d, e, x[12], 0x5A82_7999, 7, f2);
        step!(a, b, c, d, e, x[0], 0x5A82_7999, 12, f2);
        step!(a, b, c, d, e, x[9], 0x5A82_7999, 15, f2);
        step!(a, b, c, d, e, x[5], 0x5A82_7999, 9, f2);
        step!(a, b, c, d, e, x[2], 0x5A82_7999, 11, f2);
        step!(a, b, c, d, e, x[14], 0x5A82_7999, 7, f2);
        step!(a, b, c, d, e, x[11], 0x5A82_7999, 13, f2);
        step!(a, b, c, d, e, x[8], 0x5A82_7999, 12, f2);
        step!(a, b, c, d, e, x[3], 0x6ED9_EBA1, 11, f3);
        step!(a, b, c, d, e, x[10], 0x6ED9_EBA1, 13, f3);
        step!(a, b, c, d, e, x[14], 0x6ED9_EBA1, 6, f3);
        step!(a, b, c, d, e, x[4], 0x6ED9_EBA1, 7, f3);
        step!(a, b, c, d, e, x[9], 0x6ED9_EBA1, 14, f3);
        step!(a, b, c, d, e, x[15], 0x6ED9_EBA1, 9, f3);
        step!(a, b, c, d, e, x[8], 0x6ED9_EBA1, 13, f3);
        step!(a, b, c, d, e, x[1], 0x6ED9_EBA1, 15, f3);
        step!(a, b, c, d, e, x[2], 0x6ED9_EBA1, 14, f3);
        step!(a, b, c, d, e, x[7], 0x6ED9_EBA1, 8, f3);
        step!(a, b, c, d, e, x[0], 0x6ED9_EBA1, 13, f3);
        step!(a, b, c, d, e, x[6], 0x6ED9_EBA1, 6, f3);
        step!(a, b, c, d, e, x[13], 0x6ED9_EBA1, 5, f3);
        step!(a, b, c, d, e, x[11], 0x6ED9_EBA1, 12, f3);
        step!(a, b, c, d, e, x[5], 0x6ED9_EBA1, 7, f3);
        step!(a, b, c, d, e, x[12], 0x6ED9_EBA1, 5, f3);
        step!(a, b, c, d, e, x[1], 0x8F1B_BCDC, 11, f4);
        step!(a, b, c, d, e, x[9], 0x8F1B_BCDC, 12, f4);
        step!(a, b, c, d, e, x[11], 0x8F1B_BCDC, 14, f4);
        step!(a, b, c, d, e, x[10], 0x8F1B_BCDC, 15, f4);
        step!(a, b, c, d, e, x[0], 0x8F1B_BCDC, 14, f4);
        step!(a, b, c, d, e, x[8], 0x8F1B_BCDC, 15, f4);
        step!(a, b, c, d, e, x[12], 0x8F1B_BCDC, 9, f4);
        step!(a, b, c, d, e, x[4], 0x8F1B_BCDC, 8, f4);
        step!(a, b, c, d, e, x[13], 0x8F1B_BCDC, 9, f4);
        step!(a, b, c, d, e, x[3], 0x8F1B_BCDC, 14, f4);
        step!(a, b, c, d, e, x[7], 0x8F1B_BCDC, 5, f4);
        step!(a, b, c, d, e, x[15], 0x8F1B_BCDC, 6, f4);
        step!(a, b, c, d, e, x[14], 0x8F1B_BCDC, 8, f4);
        step!(a, b, c, d, e, x[5], 0x8F1B_BCDC, 6, f4);
        step!(a, b, c, d, e, x[6], 0x8F1B_BCDC, 5, f4);
        step!(a, b, c, d, e, x[2], 0x8F1B_BCDC, 12, f4);
        step!(a, b, c, d, e, x[4], 0xA953_FD4E, 9, f5);
        step!(a, b, c, d, e, x[0], 0xA953_FD4E, 15, f5);
        step!(a, b, c, d, e, x[5], 0xA953_FD4E, 5, f5);
        step!(a, b, c, d, e, x[9], 0xA953_FD4E, 11, f5);
        step!(a, b, c, d, e, x[7], 0xA953_FD4E, 6, f5);
        step!(a, b, c, d, e, x[12], 0xA953_FD4E, 8, f5);
        step!(a, b, c, d, e, x[2], 0xA953_FD4E, 13, f5);
        step!(a, b, c, d, e, x[10], 0xA953_FD4E, 12, f5);
        step!(a, b, c, d, e, x[14], 0xA953_FD4E, 5, f5);
        step!(a, b, c, d, e, x[1], 0xA953_FD4E, 12, f5);
        step!(a, b, c, d, e, x[3], 0xA953_FD4E, 13, f5);
        step!(a, b, c, d, e, x[8], 0xA953_FD4E, 14, f5);
        step!(a, b, c, d, e, x[11], 0xA953_FD4E, 11, f5);
        step!(a, b, c, d, e, x[6], 0xA953_FD4E, 8, f5);
        step!(a, b, c, d, e, x[15], 0xA953_FD4E, 5, f5);
        step!(a, b, c, d, e, x[13], 0xA953_FD4E, 6, f5);
        step!(aa, bb, cc, dd, ee, x[5], 0x50A2_8BE6, 8, f5);
        step!(aa, bb, cc, dd, ee, x[14], 0x50A2_8BE6, 9, f5);
        step!(aa, bb, cc, dd, ee, x[7], 0x50A2_8BE6, 9, f5);
        step!(aa, bb, cc, dd, ee, x[0], 0x50A2_8BE6, 11, f5);
        step!(aa, bb, cc, dd, ee, x[9], 0x50A2_8BE6, 13, f5);
        step!(aa, bb, cc, dd, ee, x[2], 0x50A2_8BE6, 15, f5);
        step!(aa, bb, cc, dd, ee, x[11], 0x50A2_8BE6, 15, f5);
        step!(aa, bb, cc, dd, ee, x[4], 0x50A2_8BE6, 5, f5);
        step!(aa, bb, cc, dd, ee, x[13], 0x50A2_8BE6, 7, f5);
        step!(aa, bb, cc, dd, ee, x[6], 0x50A2_8BE6, 7, f5);
        step!(aa, bb, cc, dd, ee, x[15], 0x50A2_8BE6, 8, f5);
        step!(aa, bb, cc, dd, ee, x[8], 0x50A2_8BE6, 11, f5);
        step!(aa, bb, cc, dd, ee, x[1], 0x50A2_8BE6, 14, f5);
        step!(aa, bb, cc, dd, ee, x[10], 0x50A2_8BE6, 14, f5);
        step!(aa, bb, cc, dd, ee, x[3], 0x50A2_8BE6, 12, f5);
        step!(aa, bb, cc, dd, ee, x[12], 0x50A2_8BE6, 6, f5);
        step!(aa, bb, cc, dd, ee, x[6], 0x5C4D_D124, 9, f4);
        step!(aa, bb, cc, dd, ee, x[11], 0x5C4D_D124, 13, f4);
        step!(aa, bb, cc, dd, ee, x[3], 0x5C4D_D124, 15, f4);
        step!(aa, bb, cc, dd, ee, x[7], 0x5C4D_D124, 7, f4);
        step!(aa, bb, cc, dd, ee, x[0], 0x5C4D_D124, 12, f4);
        step!(aa, bb, cc, dd, ee, x[13], 0x5C4D_D124, 8, f4);
        step!(aa, bb, cc, dd, ee, x[5], 0x5C4D_D124, 9, f4);
        step!(aa, bb, cc, dd, ee, x[10], 0x5C4D_D124, 11, f4);
        step!(aa, bb, cc, dd, ee, x[14], 0x5C4D_D124, 7, f4);
        step!(aa, bb, cc, dd, ee, x[15], 0x5C4D_D124, 7, f4);
        step!(aa, bb, cc, dd, ee, x[8], 0x5C4D_D124, 12, f4);
        step!(aa, bb, cc, dd, ee, x[12], 0x5C4D_D124, 7, f4);
        step!(aa, bb, cc, dd, ee, x[4], 0x5C4D_D124, 6, f4);
        step!(aa, bb, cc, dd, ee, x[9], 0x5C4D_D124, 15, f4);
        step!(aa, bb, cc, dd, ee, x[1], 0x5C4D_D124, 13, f4);
        step!(aa, bb, cc, dd, ee, x[2], 0x5C4D_D124, 11, f4);
        step!(aa, bb, cc, dd, ee, x[15], 0x6D70_3EF3, 9, f3);
        step!(aa, bb, cc, dd, ee, x[5], 0x6D70_3EF3, 7, f3);
        step!(aa, bb, cc, dd, ee, x[1], 0x6D70_3EF3, 15, f3);
        step!(aa, bb, cc, dd, ee, x[3], 0x6D70_3EF3, 11, f3);
        step!(aa, bb, cc, dd, ee, x[7], 0x6D70_3EF3, 8, f3);
        step!(aa, bb, cc, dd, ee, x[14], 0x6D70_3EF3, 6, f3);
        step!(aa, bb, cc, dd, ee, x[6], 0x6D70_3EF3, 6, f3);
        step!(aa, bb, cc, dd, ee, x[9], 0x6D70_3EF3, 14, f3);
        step!(aa, bb, cc, dd, ee, x[11], 0x6D70_3EF3, 12, f3);
        step!(aa, bb, cc, dd, ee, x[8], 0x6D70_3EF3, 13, f3);
        step!(aa, bb, cc, dd, ee, x[12], 0x6D70_3EF3, 5, f3);
        step!(aa, bb, cc, dd, ee, x[2], 0x6D70_3EF3, 14, f3);
        step!(aa, bb, cc, dd, ee, x[10], 0x6D70_3EF3, 13, f3);
        step!(aa, bb, cc, dd, ee, x[0], 0x6D70_3EF3, 13, f3);
        step!(aa, bb, cc, dd, ee, x[4], 0x6D70_3EF3, 7, f3);
        step!(aa, bb, cc, dd, ee, x[13], 0x6D70_3EF3, 5, f3);
        step!(aa, bb, cc, dd, ee, x[8], 0x7A6D_76E9, 15, f2);
        step!(aa, bb, cc, dd, ee, x[6], 0x7A6D_76E9, 5, f2);
        step!(aa, bb, cc, dd, ee, x[4], 0x7A6D_76E9, 8, f2);
        step!(aa, bb, cc, dd, ee, x[1], 0x7A6D_76E9, 11, f2);
        step!(aa, bb, cc, dd, ee, x[3], 0x7A6D_76E9, 14, f2);
        step!(aa, bb, cc, dd, ee, x[11], 0x7A6D_76E9, 14, f2);
        step!(aa, bb, cc, dd, ee, x[15], 0x7A6D_76E9, 6, f2);
        step!(aa, bb, cc, dd, ee, x[0], 0x7A6D_76E9, 14, f2);
        step!(aa, bb, cc, dd, ee, x[5], 0x7A6D_76E9, 6, f2);
        step!(aa, bb, cc, dd, ee, x[12], 0x7A6D_76E9, 9, f2);
        step!(aa, bb, cc, dd, ee, x[2], 0x7A6D_76E9, 12, f2);
        step!(aa, bb, cc, dd, ee, x[13], 0x7A6D_76E9, 9, f2);
        step!(aa, bb, cc, dd, ee, x[9], 0x7A6D_76E9, 12, f2);
        step!(aa, bb, cc, dd, ee, x[7], 0x7A6D_76E9, 5, f2);
        step!(aa, bb, cc, dd, ee, x[10], 0x7A6D_76E9, 15, f2);
        step!(aa, bb, cc, dd, ee, x[14], 0x7A6D_76E9, 8, f2);
        step!(aa, bb, cc, dd, ee, x[12], 0x0000_0000, 8, f1);
        step!(aa, bb, cc, dd, ee, x[15], 0x0000_0000, 5, f1);
        step!(aa, bb, cc, dd, ee, x[10], 0x0000_0000, 12, f1);
        step!(aa, bb, cc, dd, ee, x[4], 0x0000_0000, 9, f1);
        step!(aa, bb, cc, dd, ee, x[1], 0x0000_0000, 12, f1);
        step!(aa, bb, cc, dd, ee, x[5], 0x0000_0000, 5, f1);
        step!(aa, bb, cc, dd, ee, x[8], 0x0000_0000, 14, f1);
        step!(aa, bb, cc, dd, ee, x[7], 0x0000_0000, 6, f1);
        step!(aa, bb, cc, dd, ee, x[6], 0x0000_0000, 8, f1);
        step!(aa, bb, cc, dd, ee, x[2], 0x0000_0000, 13, f1);
        step!(aa, bb, cc, dd, ee, x[13], 0x0000_0000, 6, f1);
        step!(aa, bb, cc, dd, ee, x[14], 0x0000_0000, 5, f1);
        step!(aa, bb, cc, dd, ee, x[0], 0x0000_0000, 15, f1);
        step!(aa, bb, cc, dd, ee, x[3], 0x0000_0000, 13, f1);
        step!(aa, bb, cc, dd, ee, x[9], 0x0000_0000, 11, f1);
        step!(aa, bb, cc, dd, ee, x[11], 0x0000_0000, 11, f1);

        // Combine the two lines with the swap-in-the-middle addition.
        let t = st.s[1].wrapping_add(c).wrapping_add(dd);
        st.s[1] = st.s[2].wrapping_add(d).wrapping_add(ee);
        st.s[2] = st.s[3].wrapping_add(e).wrapping_add(aa);
        st.s[3] = st.s[4].wrapping_add(a).wrapping_add(bb);
        st.s[4] = st.s[0].wrapping_add(b).wrapping_add(cc);
        st.s[0] = t;
    }
    n * 64
}

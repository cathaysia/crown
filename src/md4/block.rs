//! MD4 block step.
//! In its own file so that a faster assembly or C version
//! can be substituted easily.
use super::Digest;

const SHIFT1: [u32; 4] = [3, 7, 11, 19];
const SHIFT2: [u32; 4] = [3, 5, 9, 13];
const SHIFT3: [u32; 4] = [3, 9, 11, 15];

const X_INDEX2: [usize; 16] = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
const X_INDEX3: [usize; 16] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];

const CHUNK: usize = 64;

pub fn block(dig: &mut Digest, mut p: &[u8]) -> usize {
    let mut a = dig.s[0];
    let mut b = dig.s[1];
    let mut c = dig.s[2];
    let mut d = dig.s[3];
    let mut n = 0;
    let mut x = [0u32; 16];

    while p.len() >= CHUNK {
        let (aa, bb, cc, dd) = (a, b, c, d);

        // convert bytes to 32-bit integers(little-endian)
        (0..16).for_each(|i| {
            let j = i * 4;
            x[i] = u32::from_le_bytes([p[j], p[j + 1], p[j + 2], p[j + 3]]);
        });

        // If this needs to be made faster in the future,
        // the usual trick is to unroll each of these
        // loops by a factor of 4; that lets you replace
        // the shift[] lookups with constants and,
        // with suitable variable renaming in each
        // unrolled body, delete the a, b, c, d = d, a, b, c
        // (or you can let the optimizer do the renaming).
        //
        // The index variables are uint so that % by a power
        // of two can be optimized easily by a compiler.

        // Round 1.
        for i in 0..16 {
            let x_val = x[i];
            let s = SHIFT1[i % 4];
            let f = ((c ^ d) & b) ^ d;
            a = a.wrapping_add(f).wrapping_add(x_val);
            a = a.rotate_left(s);
            let temp = (d, a, b, c);
            a = temp.0;
            b = temp.1;
            c = temp.2;
            d = temp.3;
        }

        // Round 2.
        for i in 0..16 {
            let x_val = x[X_INDEX2[i]];
            let s = SHIFT2[i % 4];
            let g = (b & c) | (b & d) | (c & d);
            a = a
                .wrapping_add(g)
                .wrapping_add(x_val)
                .wrapping_add(0x5a827999);
            a = a.rotate_left(s);
            let temp = (d, a, b, c);
            a = temp.0;
            b = temp.1;
            c = temp.2;
            d = temp.3;
        }

        // Round 3.
        for i in 0..16 {
            let x_val = x[X_INDEX3[i]];
            let s = SHIFT3[i % 4];
            let h = b ^ c ^ d;
            a = a
                .wrapping_add(h)
                .wrapping_add(x_val)
                .wrapping_add(0x6ed9eba1);
            a = a.rotate_left(s);
            let temp = (d, a, b, c);
            a = temp.0;
            b = temp.1;
            c = temp.2;
            d = temp.3;
        }

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);

        p = &p[CHUNK..];
        n += CHUNK;
    }

    dig.s[0] = a;
    dig.s[1] = b;
    dig.s[2] = c;
    dig.s[3] = d;
    n
}

use super::{Sha1, CHUNK};

const K0: u32 = 0x5A827999;
const K1: u32 = 0x6ED9EBA1;
const K2: u32 = 0x8F1BBCDC;
const K3: u32 = 0xCA62C1D6;

pub fn block_generic(dig: &mut Sha1, p: &[u8]) {
    let mut w = [0u32; 16];
    let mut p = p;

    let (mut h0, mut h1, mut h2, mut h3, mut h4) =
        (dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4]);

    while p.len() >= CHUNK {
        (0..16).for_each(|i| {
            let j = i * 4;
            w[i] = ((p[j] as u32) << 24)
                | ((p[j + 1] as u32) << 16)
                | ((p[j + 2] as u32) << 8)
                | (p[j + 3] as u32);
        });

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        let mut i = 0;

        // Round 1: i = 0..16
        while i < 16 {
            let f = (b & c) | ((!b) & d);
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(w[i & 0xf])
                .wrapping_add(K0);
            (a, b, c, d, e) = (t, a, b.rotate_left(30), c, d);
            i += 1;
        }

        // Round 1 continued: i = 16..20
        while i < 20 {
            let tmp = w[(i - 3) & 0xf] ^ w[(i - 8) & 0xf] ^ w[(i - 14) & 0xf] ^ w[i & 0xf];
            w[i & 0xf] = tmp.rotate_left(1);

            let f = (b & c) | ((!b) & d);
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(w[i & 0xf])
                .wrapping_add(K0);
            (a, b, c, d, e) = (t, a, b.rotate_left(30), c, d);
            i += 1;
        }

        // Round 2: i = 20..40
        while i < 40 {
            let tmp = w[(i - 3) & 0xf] ^ w[(i - 8) & 0xf] ^ w[(i - 14) & 0xf] ^ w[i & 0xf];
            w[i & 0xf] = tmp.rotate_left(1);

            let f = b ^ c ^ d;
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(w[i & 0xf])
                .wrapping_add(K1);
            (a, b, c, d, e) = (t, a, b.rotate_left(30), c, d);
            i += 1;
        }

        // Round 3: i = 40..60
        while i < 60 {
            let tmp = w[(i - 3) & 0xf] ^ w[(i - 8) & 0xf] ^ w[(i - 14) & 0xf] ^ w[i & 0xf];
            w[i & 0xf] = tmp.rotate_left(1);

            let f = ((b | c) & d) | (b & c);
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(w[i & 0xf])
                .wrapping_add(K2);
            (a, b, c, d, e) = (t, a, b.rotate_left(30), c, d);
            i += 1;
        }

        // Round 4: i = 60..80
        while i < 80 {
            let tmp = w[(i - 3) & 0xf] ^ w[(i - 8) & 0xf] ^ w[(i - 14) & 0xf] ^ w[i & 0xf];
            w[i & 0xf] = tmp.rotate_left(1);

            let f = b ^ c ^ d;
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(w[i & 0xf])
                .wrapping_add(K3);
            (a, b, c, d, e) = (t, a, b.rotate_left(30), c, d);
            i += 1;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);

        p = &p[CHUNK..];
    }

    dig.h[0] = h0;
    dig.h[1] = h1;
    dig.h[2] = h2;
    dig.h[3] = h3;
    dig.h[4] = h4;
}

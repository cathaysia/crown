#![allow(dead_code)]

use core::num::Wrapping;

use bytes::Buf;

use super::Md5;

const SHIFT1: [u32; 4] = [7, 12, 17, 22];
const SHIFT2: [u32; 4] = [5, 9, 14, 20];
const SHIFT3: [u32; 4] = [4, 11, 16, 23];
const SHIFT4: [u32; 4] = [6, 10, 15, 21];

const TABLE1: [Wrapping<u32>; 16] = [
    Wrapping(0xd76aa478),
    Wrapping(0xe8c7b756),
    Wrapping(0x242070db),
    Wrapping(0xc1bdceee),
    Wrapping(0xf57c0faf),
    Wrapping(0x4787c62a),
    Wrapping(0xa8304613),
    Wrapping(0xfd469501),
    Wrapping(0x698098d8),
    Wrapping(0x8b44f7af),
    Wrapping(0xffff5bb1),
    Wrapping(0x895cd7be),
    Wrapping(0x6b901122),
    Wrapping(0xfd987193),
    Wrapping(0xa679438e),
    Wrapping(0x49b40821),
];

const TABLE2: [Wrapping<u32>; 16] = [
    Wrapping(0xf61e2562),
    Wrapping(0xc040b340),
    Wrapping(0x265e5a51),
    Wrapping(0xe9b6c7aa),
    Wrapping(0xd62f105d),
    Wrapping(0x2441453),
    Wrapping(0xd8a1e681),
    Wrapping(0xe7d3fbc8),
    Wrapping(0x21e1cde6),
    Wrapping(0xc33707d6),
    Wrapping(0xf4d50d87),
    Wrapping(0x455a14ed),
    Wrapping(0xa9e3e905),
    Wrapping(0xfcefa3f8),
    Wrapping(0x676f02d9),
    Wrapping(0x8d2a4c8a),
];

const TABLE3: [Wrapping<u32>; 16] = [
    Wrapping(0xfffa3942),
    Wrapping(0x8771f681),
    Wrapping(0x6d9d6122),
    Wrapping(0xfde5380c),
    Wrapping(0xa4beea44),
    Wrapping(0x4bdecfa9),
    Wrapping(0xf6bb4b60),
    Wrapping(0xbebfbc70),
    Wrapping(0x289b7ec6),
    Wrapping(0xeaa127fa),
    Wrapping(0xd4ef3085),
    Wrapping(0x4881d05),
    Wrapping(0xd9d4d039),
    Wrapping(0xe6db99e5),
    Wrapping(0x1fa27cf8),
    Wrapping(0xc4ac5665),
];

const TABLE4: [Wrapping<u32>; 16] = [
    Wrapping(0xf4292244),
    Wrapping(0x432aff97),
    Wrapping(0xab9423a7),
    Wrapping(0xfc93a039),
    Wrapping(0x655b59c3),
    Wrapping(0x8f0ccc92),
    Wrapping(0xffeff47d),
    Wrapping(0x85845dd1),
    Wrapping(0x6fa87e4f),
    Wrapping(0xfe2ce6e0),
    Wrapping(0xa3014314),
    Wrapping(0x4e0811a1),
    Wrapping(0xf7537e82),
    Wrapping(0xbd3af235),
    Wrapping(0x2ad7d2bb),
    Wrapping(0xeb86d391),
];

macro_rules! md5_round1 {
    ($a:ident, $b:ident, $c:ident, $d:ident, $x:ident, $i:expr) => {
        $a = $b
            + Wrapping(
                (((($c ^ $d) & $b) ^ $d) + $a + $x[$i] + TABLE1[$i])
                    .0
                    .rotate_left(SHIFT1[$i % 4]),
            );
    };
}

macro_rules! md5_round2 {
    ($a:ident, $b:ident, $c:ident, $d:ident, $x:ident, $i:expr) => {
        $a = $b
            + Wrapping(
                (((($b ^ $c) & $d) ^ $c) + $a + $x[(1 + 5 * $i) & 15] + TABLE2[$i])
                    .0
                    .rotate_left(SHIFT2[$i % 4]),
            );
    };
}

macro_rules! md5_round3 {
    ($a:ident, $b:ident, $c:ident, $d:ident, $x:ident, $i:expr) => {
        $a = $b
            + Wrapping(
                (($b ^ $c ^ $d) + $a + $x[(5 + 3 * $i) & 15] + TABLE3[$i])
                    .0
                    .rotate_left(SHIFT3[$i % 4]),
            );
    };
}

macro_rules! md5_round4 {
    ($a:ident, $b:ident, $c:ident, $d:ident, $x:ident, $i:expr) => {
        $a = $b
            + Wrapping(
                (($c ^ ($b | !$d)) + $a + $x[(7 * $i) & 15] + TABLE4[$i])
                    .0
                    .rotate_left(SHIFT4[$i % 4]),
            );
    };
}

pub fn block_generic(dig: &mut Md5, mut blocks: &[u8]) {
    let mut a = Wrapping(dig.s[0]);
    let mut b = Wrapping(dig.s[1]);
    let mut c = Wrapping(dig.s[2]);
    let mut d = Wrapping(dig.s[3]);

    let mut i = 0;
    let len = blocks.len();
    while i + 64 <= len {
        let aa = a;
        let bb = b;
        let cc = c;
        let dd = d;

        let mut x = [Wrapping(0u32); 16];
        (0..16).for_each(|i| {
            x[i] = Wrapping(blocks.get_u32_le());
        });

        // Round 1
        for i in 0..4 {
            md5_round1!(a, b, c, d, x, i * 4);
            md5_round1!(d, a, b, c, x, i * 4 + 1);
            md5_round1!(c, d, a, b, x, i * 4 + 2);
            md5_round1!(b, c, d, a, x, i * 4 + 3);
        }

        // Round 2
        for i in 0..4 {
            md5_round2!(a, b, c, d, x, i * 4);
            md5_round2!(d, a, b, c, x, i * 4 + 1);
            md5_round2!(c, d, a, b, x, i * 4 + 2);
            md5_round2!(b, c, d, a, x, i * 4 + 3);
        }

        // Round 3
        for i in 0..4 {
            md5_round3!(a, b, c, d, x, i * 4);
            md5_round3!(d, a, b, c, x, i * 4 + 1);
            md5_round3!(c, d, a, b, x, i * 4 + 2);
            md5_round3!(b, c, d, a, x, i * 4 + 3);
        }

        // Round 4
        for i in 0..4 {
            md5_round4!(a, b, c, d, x, i * 4);
            md5_round4!(d, a, b, c, x, i * 4 + 1);
            md5_round4!(c, d, a, b, x, i * 4 + 2);
            md5_round4!(b, c, d, a, x, i * 4 + 3);
        }

        a += aa;
        b += bb;
        c += cc;
        d += dd;

        i += 64;
    }

    dig.s[0] = a.0;
    dig.s[1] = b.0;
    dig.s[2] = c.0;
    dig.s[3] = d.0;
}

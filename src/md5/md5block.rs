use crate::md5::Digest;

const SHIFT1: [u32; 4] = [7, 12, 17, 22];
const SHIFT2: [u32; 4] = [5, 9, 14, 20];
const SHIFT3: [u32; 4] = [4, 11, 16, 23];
const SHIFT4: [u32; 4] = [6, 10, 15, 21];

const TABLE1: [u32; 16] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
];

const TABLE2: [u32; 16] = [
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
];

const TABLE3: [u32; 16] = [
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
];

const TABLE4: [u32; 16] = [
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

macro_rules! md5_round1 {
    ($a:ident, $b:ident, $c:ident, $d:ident, $x:ident, $i:expr) => {
        $a = $b.wrapping_add(
            (((($c ^ $d) & $b) ^ $d)
                .wrapping_add($a)
                .wrapping_add($x[$i])
                .wrapping_add(TABLE1[$i]))
            .rotate_left(SHIFT1[$i % 4]),
        );
    };
}

macro_rules! md5_round2 {
    ($a:ident, $b:ident, $c:ident, $d:ident, $x:ident, $i:expr) => {
        let idx = (1 + 5 * $i) & 15;
        $a = $b.wrapping_add(
            (((($b ^ $c) & $d) ^ $c)
                .wrapping_add($a)
                .wrapping_add($x[idx])
                .wrapping_add(TABLE2[$i]))
            .rotate_left(SHIFT2[$i % 4]),
        );
    };
}

macro_rules! md5_round3 {
    ($a:ident, $b:ident, $c:ident, $d:ident, $x:ident, $i:expr) => {
        let idx = (5 + 3 * $i) & 15;
        $a = $b.wrapping_add(
            (($b ^ $c ^ $d)
                .wrapping_add($a)
                .wrapping_add($x[idx])
                .wrapping_add(TABLE3[$i]))
            .rotate_left(SHIFT3[$i % 4]),
        );
    };
}

macro_rules! md5_round4 {
    ($a:ident, $b:ident, $c:ident, $d:ident, $x:ident, $i:expr) => {
        let idx = (7 * $i) & 15;
        $a = $b.wrapping_add(
            (($c ^ ($b | !$d))
                .wrapping_add($a)
                .wrapping_add($x[idx])
                .wrapping_add(TABLE4[$i]))
            .rotate_left(SHIFT4[$i % 4]),
        );
    };
}

pub fn block_generic(dig: &mut Digest, p: &[u8]) {
    let mut a = dig.s[0];
    let mut b = dig.s[1];
    let mut c = dig.s[2];
    let mut d = dig.s[3];

    let mut i = 0;
    while i + 64 <= p.len() {
        let q = &p[i..i + 64];

        let aa = a;
        let bb = b;
        let cc = c;
        let dd = d;

        let x = [
            le_u32(&q[0..4]),
            le_u32(&q[4..8]),
            le_u32(&q[8..12]),
            le_u32(&q[12..16]),
            le_u32(&q[16..20]),
            le_u32(&q[20..24]),
            le_u32(&q[24..28]),
            le_u32(&q[28..32]),
            le_u32(&q[32..36]),
            le_u32(&q[36..40]),
            le_u32(&q[40..44]),
            le_u32(&q[44..48]),
            le_u32(&q[48..52]),
            le_u32(&q[52..56]),
            le_u32(&q[56..60]),
            le_u32(&q[60..64]),
        ];

        // Round 1
        md5_round1!(a, b, c, d, x, 0);
        md5_round1!(d, a, b, c, x, 1);
        md5_round1!(c, d, a, b, x, 2);
        md5_round1!(b, c, d, a, x, 3);
        md5_round1!(a, b, c, d, x, 4);
        md5_round1!(d, a, b, c, x, 5);
        md5_round1!(c, d, a, b, x, 6);
        md5_round1!(b, c, d, a, x, 7);
        md5_round1!(a, b, c, d, x, 8);
        md5_round1!(d, a, b, c, x, 9);
        md5_round1!(c, d, a, b, x, 10);
        md5_round1!(b, c, d, a, x, 11);
        md5_round1!(a, b, c, d, x, 12);
        md5_round1!(d, a, b, c, x, 13);
        md5_round1!(c, d, a, b, x, 14);
        md5_round1!(b, c, d, a, x, 15);

        // Round 2
        md5_round2!(a, b, c, d, x, 0);
        md5_round2!(d, a, b, c, x, 1);
        md5_round2!(c, d, a, b, x, 2);
        md5_round2!(b, c, d, a, x, 3);
        md5_round2!(a, b, c, d, x, 4);
        md5_round2!(d, a, b, c, x, 5);
        md5_round2!(c, d, a, b, x, 6);
        md5_round2!(b, c, d, a, x, 7);
        md5_round2!(a, b, c, d, x, 8);
        md5_round2!(d, a, b, c, x, 9);
        md5_round2!(c, d, a, b, x, 10);
        md5_round2!(b, c, d, a, x, 11);
        md5_round2!(a, b, c, d, x, 12);
        md5_round2!(d, a, b, c, x, 13);
        md5_round2!(c, d, a, b, x, 14);
        md5_round2!(b, c, d, a, x, 15);

        // Round 3
        md5_round3!(a, b, c, d, x, 0);
        md5_round3!(d, a, b, c, x, 1);
        md5_round3!(c, d, a, b, x, 2);
        md5_round3!(b, c, d, a, x, 3);
        md5_round3!(a, b, c, d, x, 4);
        md5_round3!(d, a, b, c, x, 5);
        md5_round3!(c, d, a, b, x, 6);
        md5_round3!(b, c, d, a, x, 7);
        md5_round3!(a, b, c, d, x, 8);
        md5_round3!(d, a, b, c, x, 9);
        md5_round3!(c, d, a, b, x, 10);
        md5_round3!(b, c, d, a, x, 11);
        md5_round3!(a, b, c, d, x, 12);
        md5_round3!(d, a, b, c, x, 13);
        md5_round3!(c, d, a, b, x, 14);
        md5_round3!(b, c, d, a, x, 15);

        // Round 4
        md5_round4!(a, b, c, d, x, 0);
        md5_round4!(d, a, b, c, x, 1);
        md5_round4!(c, d, a, b, x, 2);
        md5_round4!(b, c, d, a, x, 3);
        md5_round4!(a, b, c, d, x, 4);
        md5_round4!(d, a, b, c, x, 5);
        md5_round4!(c, d, a, b, x, 6);
        md5_round4!(b, c, d, a, x, 7);
        md5_round4!(a, b, c, d, x, 8);
        md5_round4!(d, a, b, c, x, 9);
        md5_round4!(c, d, a, b, x, 10);
        md5_round4!(b, c, d, a, x, 11);
        md5_round4!(a, b, c, d, x, 12);
        md5_round4!(d, a, b, c, x, 13);
        md5_round4!(c, d, a, b, x, 14);
        md5_round4!(b, c, d, a, x, 15);

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);

        i += 64;
    }

    dig.s[0] = a;
    dig.s[1] = b;
    dig.s[2] = c;
    dig.s[3] = d;
}

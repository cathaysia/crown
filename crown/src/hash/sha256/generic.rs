// SHA-256 block step — portable software path.
//
// Uses a 4-word schedule + x2-round formulation (same structure as
// RustCrypto's `sha2` soft backend): better ILP and less stack traffic
// than the textbook expand-then-compress loop.

#![allow(dead_code)]

const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// K constants in the reversed 4-word packing used by the soft path.
const K32X4: [[u32; 4]; 16] = [
    [K32[3], K32[2], K32[1], K32[0]],
    [K32[7], K32[6], K32[5], K32[4]],
    [K32[11], K32[10], K32[9], K32[8]],
    [K32[15], K32[14], K32[13], K32[12]],
    [K32[19], K32[18], K32[17], K32[16]],
    [K32[23], K32[22], K32[21], K32[20]],
    [K32[27], K32[26], K32[25], K32[24]],
    [K32[31], K32[30], K32[29], K32[28]],
    [K32[35], K32[34], K32[33], K32[32]],
    [K32[39], K32[38], K32[37], K32[36]],
    [K32[43], K32[42], K32[41], K32[40]],
    [K32[47], K32[46], K32[45], K32[44]],
    [K32[51], K32[50], K32[49], K32[48]],
    [K32[55], K32[54], K32[53], K32[52]],
    [K32[59], K32[58], K32[57], K32[56]],
    [K32[63], K32[62], K32[61], K32[60]],
];

const CHUNK: usize = 64;

#[inline(always)]
fn add4(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    [
        a[0].wrapping_add(b[0]),
        a[1].wrapping_add(b[1]),
        a[2].wrapping_add(b[2]),
        a[3].wrapping_add(b[3]),
    ]
}

#[inline(always)]
fn sha256load(v2: [u32; 4], v3: [u32; 4]) -> [u32; 4] {
    [v3[3], v2[0], v2[1], v2[2]]
}

#[inline(always)]
fn sha256swap(v0: [u32; 4]) -> [u32; 4] {
    [v0[2], v0[3], v0[0], v0[1]]
}

#[inline(always)]
fn sha256msg1(v0: [u32; 4], v1: [u32; 4]) -> [u32; 4] {
    let x = sha256load(v0, v1);
    let s0 = [
        x[0].rotate_right(7) ^ x[0].rotate_right(18) ^ (x[0] >> 3),
        x[1].rotate_right(7) ^ x[1].rotate_right(18) ^ (x[1] >> 3),
        x[2].rotate_right(7) ^ x[2].rotate_right(18) ^ (x[2] >> 3),
        x[3].rotate_right(7) ^ x[3].rotate_right(18) ^ (x[3] >> 3),
    ];
    add4(v0, s0)
}

#[inline(always)]
fn sha256msg2(v4: [u32; 4], v3: [u32; 4]) -> [u32; 4] {
    #[inline(always)]
    fn s1(a: u32) -> u32 {
        a.rotate_right(17) ^ a.rotate_right(19) ^ (a >> 10)
    }
    let [x3, x2, x1, x0] = v4;
    let [w15, w14, _, _] = v3;
    let w16 = x0.wrapping_add(s1(w14));
    let w17 = x1.wrapping_add(s1(w15));
    let w18 = x2.wrapping_add(s1(w16));
    let w19 = x3.wrapping_add(s1(w17));
    [w19, w18, w17, w16]
}

#[inline(always)]
fn schedule4(v0: [u32; 4], v1: [u32; 4], v2: [u32; 4], v3: [u32; 4]) -> [u32; 4] {
    let t1 = sha256msg1(v0, v1);
    let t2 = sha256load(v2, v3);
    sha256msg2(add4(t1, t2), v3)
}

#[inline(always)]
fn round_x2(cdgh: [u32; 4], abef: [u32; 4], wk: [u32; 4]) -> [u32; 4] {
    #[inline(always)]
    fn big_s0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }
    #[inline(always)]
    fn big_s1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }
    #[inline(always)]
    fn ch(e: u32, f: u32, g: u32) -> u32 {
        g ^ (e & (f ^ g))
    }
    #[inline(always)]
    fn maj(a: u32, b: u32, c: u32) -> u32 {
        (a & b) ^ (a & c) ^ (b & c)
    }

    let [_, _, wk1, wk0] = wk;
    let [a0, b0, e0, f0] = abef;
    let [c0, d0, g0, h0] = cdgh;

    let x0 = big_s1(e0)
        .wrapping_add(ch(e0, f0, g0))
        .wrapping_add(wk0)
        .wrapping_add(h0);
    let y0 = big_s0(a0).wrapping_add(maj(a0, b0, c0));
    let (a1, b1, c1, d1, e1, f1, g1, h1) = (
        x0.wrapping_add(y0),
        a0,
        b0,
        c0,
        x0.wrapping_add(d0),
        e0,
        f0,
        g0,
    );

    let x1 = big_s1(e1)
        .wrapping_add(ch(e1, f1, g1))
        .wrapping_add(wk1)
        .wrapping_add(h1);
    let y1 = big_s0(a1).wrapping_add(maj(a1, b1, c1));
    let (a2, b2, _, _, e2, f2, _, _) = (
        x1.wrapping_add(y1),
        a1,
        b1,
        c1,
        x1.wrapping_add(d1),
        e1,
        f1,
        g1,
    );
    [a2, b2, e2, f2]
}

fn block_u32(state: &mut [u32; 8], block: &[u8]) {
    let mut w0 = [0u32; 4];
    let mut w1 = [0u32; 4];
    let mut w2 = [0u32; 4];
    let mut w3 = [0u32; 4];
    for i in 0..4 {
        let j = i * 4;
        w0[i] = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
        let j = (i + 4) * 4;
        w1[i] = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
        let j = (i + 8) * 4;
        w2[i] = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
        let j = (i + 12) * 4;
        w3[i] = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
    }
    // reverse each 4-word group to match K32X4 packing
    w0 = [w0[3], w0[2], w0[1], w0[0]];
    w1 = [w1[3], w1[2], w1[1], w1[0]];
    w2 = [w2[3], w2[2], w2[1], w2[0]];
    w3 = [w3[3], w3[2], w3[1], w3[0]];

    let mut abef = [state[0], state[1], state[4], state[5]];
    let mut cdgh = [state[2], state[3], state[6], state[7]];

    macro_rules! rounds4 {
        ($rest:expr, $i:expr) => {{
            let t1 = add4($rest, K32X4[$i]);
            cdgh = round_x2(cdgh, abef, t1);
            abef = round_x2(abef, cdgh, sha256swap(t1));
        }};
    }
    macro_rules! sr4 {
        ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $i:expr) => {{
            $e = schedule4($a, $b, $c, $d);
            rounds4!($e, $i);
        }};
    }

    rounds4!(w0, 0);
    rounds4!(w1, 1);
    rounds4!(w2, 2);
    rounds4!(w3, 3);
    let mut w4;
    sr4!(w0, w1, w2, w3, w4, 4);
    sr4!(w1, w2, w3, w4, w0, 5);
    sr4!(w2, w3, w4, w0, w1, 6);
    sr4!(w3, w4, w0, w1, w2, 7);
    sr4!(w4, w0, w1, w2, w3, 8);
    sr4!(w0, w1, w2, w3, w4, 9);
    sr4!(w1, w2, w3, w4, w0, 10);
    sr4!(w2, w3, w4, w0, w1, 11);
    sr4!(w3, w4, w0, w1, w2, 12);
    sr4!(w4, w0, w1, w2, w3, 13);
    sr4!(w0, w1, w2, w3, w4, 14);
    sr4!(w1, w2, w3, w4, w0, 15);

    let [a, b, e, f] = abef;
    let [c, d, g, h] = cdgh;
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

pub fn block_generic<const N: usize, const IS_224: bool>(
    dig: &mut super::Sha256<N, IS_224>,
    p: &[u8],
) {
    // Local copy avoids repeated bounds checks / aliasing stores.
    let mut state = dig.h;
    for block in p.chunks_exact(CHUNK) {
        block_u32(&mut state, block);
    }
    dig.h = state;
}

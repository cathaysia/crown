//! Cross-check `sha256_multi_block` against a portable SHA-256 compression oracle.
#![cfg(all(feature = "asm", target_arch = "x86_64"))]

use super::*;

/// Portable SHA-256 compression (FIPS 180-4) — test oracle.
fn sha256_compress(h: &mut [u32; 8], block: &[u8]) {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn sha256_blocks_portable(state: &mut [u32; 8], data: &[u8]) {
    for chunk in data.chunks_exact(64) {
        sha256_compress(state, chunk);
    }
}

fn prf(seed: &mut u64) -> u8 {
    *seed = seed
        .wrapping_mul(0x9e3779b97f4a7c15)
        .wrapping_add(0x165667b19e3779f9);
    (*seed >> 24) as u8
}

fn fill(seed: &mut u64, len: usize) -> Vec<u8> {
    (0..len).map(|_| prf(seed)).collect()
}

#[test]
fn single_stream_matches_portable() {
    let mut seed = 0x1234_5678u64;
    for &nblocks in &[1usize, 2, 3, 5, 8, 16] {
        let data = fill(&mut seed, nblocks * 64);
        let mut state = IV;
        multi_block_single(&mut state, &data, nblocks);
        let mut expect = IV;
        sha256_blocks_portable(&mut expect, &data);
        assert_eq!(state, expect, "nblocks={nblocks}");
    }
}

#[test]
fn four_lanes_match_portable() {
    let mut seed = 0xabcd_ef01u64;
    for &nblocks in &[1usize, 2, 4] {
        let data: Vec<Vec<u8>> = (0..4).map(|_| fill(&mut seed, nblocks * 64)).collect();
        let mut ctx = Sha256MultiCtx {
            a: [0; 8],
            b: [0; 8],
            c: [0; 8],
            d: [0; 8],
            e: [0; 8],
            f: [0; 8],
            g: [0; 8],
            h: [0; 8],
        };
        for lane in 0..4 {
            ctx.a[lane] = IV[0];
            ctx.b[lane] = IV[1];
            ctx.c[lane] = IV[2];
            ctx.d[lane] = IV[3];
            ctx.e[lane] = IV[4];
            ctx.f[lane] = IV[5];
            ctx.g[lane] = IV[6];
            ctx.h[lane] = IV[7];
        }
        let jobs = [
            Sha256MultiJob::new(&data[0], nblocks),
            Sha256MultiJob::new(&data[1], nblocks),
            Sha256MultiJob::new(&data[2], nblocks),
            Sha256MultiJob::new(&data[3], nblocks),
            Sha256MultiJob::empty(),
            Sha256MultiJob::empty(),
            Sha256MultiJob::empty(),
            Sha256MultiJob::empty(),
        ];
        multi_block(&mut ctx, &jobs, 1);
        for lane in 0..4 {
            let mut expect = IV;
            sha256_blocks_portable(&mut expect, &data[lane]);
            assert_eq!(
                [
                    ctx.a[lane],
                    ctx.b[lane],
                    ctx.c[lane],
                    ctx.d[lane],
                    ctx.e[lane],
                    ctx.f[lane],
                    ctx.g[lane],
                    ctx.h[lane],
                ],
                expect,
                "lane={lane} nblocks={nblocks}"
            );
        }
    }
}

#[test]
fn mixed_block_counts() {
    let mut seed = 0x5555_aaaau64;
    let counts = [3usize, 1, 4, 2];
    let data: Vec<Vec<u8>> = counts.iter().map(|&n| fill(&mut seed, n * 64)).collect();
    let mut ctx = Sha256MultiCtx {
        a: [0; 8],
        b: [0; 8],
        c: [0; 8],
        d: [0; 8],
        e: [0; 8],
        f: [0; 8],
        g: [0; 8],
        h: [0; 8],
    };
    for lane in 0..4 {
        ctx.a[lane] = IV[0];
        ctx.b[lane] = IV[1];
        ctx.c[lane] = IV[2];
        ctx.d[lane] = IV[3];
        ctx.e[lane] = IV[4];
        ctx.f[lane] = IV[5];
        ctx.g[lane] = IV[6];
        ctx.h[lane] = IV[7];
    }
    let jobs = [
        Sha256MultiJob::new(&data[0], counts[0]),
        Sha256MultiJob::new(&data[1], counts[1]),
        Sha256MultiJob::new(&data[2], counts[2]),
        Sha256MultiJob::new(&data[3], counts[3]),
        Sha256MultiJob::empty(),
        Sha256MultiJob::empty(),
        Sha256MultiJob::empty(),
        Sha256MultiJob::empty(),
    ];
    multi_block(&mut ctx, &jobs, 1);
    for lane in 0..4 {
        let mut expect = IV;
        sha256_blocks_portable(&mut expect, &data[lane]);
        assert_eq!(
            [
                ctx.a[lane],
                ctx.b[lane],
                ctx.c[lane],
                ctx.d[lane],
                ctx.e[lane],
                ctx.f[lane],
                ctx.g[lane],
                ctx.h[lane],
            ],
            expect,
            "lane={lane} counts={counts:?}"
        );
    }
}

#[test]
fn inactive_lane_preserves_state() {
    let mut seed = 0x9999_1111u64;
    let data = fill(&mut seed, 2 * 64);
    let sentinel = [
        0x11111111u32,
        0x22222222,
        0x33333333,
        0x44444444,
        0x55555555,
        0x66666666,
        0x77777777,
        0x88888888,
    ];
    let mut ctx = Sha256MultiCtx {
        a: [0; 8],
        b: [0; 8],
        c: [0; 8],
        d: [0; 8],
        e: [0; 8],
        f: [0; 8],
        g: [0; 8],
        h: [0; 8],
    };
    ctx.a[0] = IV[0];
    ctx.b[0] = IV[1];
    ctx.c[0] = IV[2];
    ctx.d[0] = IV[3];
    ctx.e[0] = IV[4];
    ctx.f[0] = IV[5];
    ctx.g[0] = IV[6];
    ctx.h[0] = IV[7];
    for lane in 1..4 {
        ctx.a[lane] = sentinel[0];
        ctx.b[lane] = sentinel[1];
        ctx.c[lane] = sentinel[2];
        ctx.d[lane] = sentinel[3];
        ctx.e[lane] = sentinel[4];
        ctx.f[lane] = sentinel[5];
        ctx.g[lane] = sentinel[6];
        ctx.h[lane] = sentinel[7];
    }
    let jobs = [
        Sha256MultiJob::new(&data, 2),
        Sha256MultiJob::empty(),
        Sha256MultiJob::empty(),
        Sha256MultiJob::empty(),
        Sha256MultiJob::empty(),
        Sha256MultiJob::empty(),
        Sha256MultiJob::empty(),
        Sha256MultiJob::empty(),
    ];
    multi_block(&mut ctx, &jobs, 1);
    let mut expect = IV;
    sha256_blocks_portable(&mut expect, &data);
    assert_eq!(
        [ctx.a[0], ctx.b[0], ctx.c[0], ctx.d[0], ctx.e[0], ctx.f[0], ctx.g[0], ctx.h[0]],
        expect
    );
    for lane in 1..4 {
        assert_eq!(
            [
                ctx.a[lane],
                ctx.b[lane],
                ctx.c[lane],
                ctx.d[lane],
                ctx.e[lane],
                ctx.f[lane],
                ctx.g[lane],
                ctx.h[lane],
            ],
            sentinel,
            "lane={lane} must be preserved"
        );
    }
}

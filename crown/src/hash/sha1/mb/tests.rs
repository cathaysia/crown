//! Cross-check `sha1_multi_block` against a portable SHA-1 compression oracle.
#![cfg(all(feature = "asm", target_arch = "x86_64"))]

use super::*;

/// Portable SHA-1 compression (FIPS 180-4) — test oracle.
fn sha1_compress(h: &mut [u32; 5], block: &[u8]) {
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
    for i in 0..80 {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5a827999),
            20..=39 => (b ^ c ^ d, 0x6ed9eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
            _ => (b ^ c ^ d, 0xca62c1d6),
        };
        let t = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
}

/// SHA-1 IV (FIPS 180-4).
const IV: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// Process `data` (whole blocks only) with the portable oracle.
fn sha1_blocks_portable(state: &mut [u32; 5], data: &[u8]) {
    for chunk in data.chunks_exact(64) {
        sha1_compress(state, chunk);
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
        sha1_blocks_portable(&mut expect, &data);
        assert_eq!(state, expect, "nblocks={nblocks}");
    }
}

#[test]
fn four_lanes_match_portable() {
    let mut seed = 0xabcd_ef01u64;
    // All four lanes with the same number of blocks.
    for &nblocks in &[1usize, 2, 4] {
        let data: Vec<Vec<u8>> = (0..4).map(|_| fill(&mut seed, nblocks * 64)).collect();
        let mut ctx = Sha1MultiCtx {
            a: [0; 8],
            b: [0; 8],
            c: [0; 8],
            d: [0; 8],
            e: [0; 8],
        };
        for lane in 0..4 {
            ctx.a[lane] = IV[0];
            ctx.b[lane] = IV[1];
            ctx.c[lane] = IV[2];
            ctx.d[lane] = IV[3];
            ctx.e[lane] = IV[4];
        }
        let jobs = [
            Sha1MultiJob::new(&data[0], nblocks),
            Sha1MultiJob::new(&data[1], nblocks),
            Sha1MultiJob::new(&data[2], nblocks),
            Sha1MultiJob::new(&data[3], nblocks),
            Sha1MultiJob::empty(),
            Sha1MultiJob::empty(),
            Sha1MultiJob::empty(),
            Sha1MultiJob::empty(),
        ];
        multi_block(&mut ctx, &jobs, 1);
        for lane in 0..4 {
            let mut expect = IV;
            sha1_blocks_portable(&mut expect, &data[lane]);
            assert_eq!(
                [
                    ctx.a[lane],
                    ctx.b[lane],
                    ctx.c[lane],
                    ctx.d[lane],
                    ctx.e[lane]
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
    // Different block counts per lane: the multi-buffer kernel must
    // keep shorter lanes unchanged once their counter hits zero.
    let counts = [3usize, 1, 4, 2];
    let data: Vec<Vec<u8>> = counts.iter().map(|&n| fill(&mut seed, n * 64)).collect();
    let mut ctx = Sha1MultiCtx {
        a: [0; 8],
        b: [0; 8],
        c: [0; 8],
        d: [0; 8],
        e: [0; 8],
    };
    for lane in 0..4 {
        ctx.a[lane] = IV[0];
        ctx.b[lane] = IV[1];
        ctx.c[lane] = IV[2];
        ctx.d[lane] = IV[3];
        ctx.e[lane] = IV[4];
    }
    let jobs = [
        Sha1MultiJob::new(&data[0], counts[0]),
        Sha1MultiJob::new(&data[1], counts[1]),
        Sha1MultiJob::new(&data[2], counts[2]),
        Sha1MultiJob::new(&data[3], counts[3]),
        Sha1MultiJob::empty(),
        Sha1MultiJob::empty(),
        Sha1MultiJob::empty(),
        Sha1MultiJob::empty(),
    ];
    multi_block(&mut ctx, &jobs, 1);
    for lane in 0..4 {
        let mut expect = IV;
        sha1_blocks_portable(&mut expect, &data[lane]);
        assert_eq!(
            [
                ctx.a[lane],
                ctx.b[lane],
                ctx.c[lane],
                ctx.d[lane],
                ctx.e[lane]
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
        0x1111_1111u32,
        0x2222_2222,
        0x3333_3333,
        0x4444_4444,
        0x5555_5555,
    ];
    let mut ctx = Sha1MultiCtx {
        a: [0; 8],
        b: [0; 8],
        c: [0; 8],
        d: [0; 8],
        e: [0; 8],
    };
    // Lane 0 is active; lanes 1-3 are inactive (blocks = 0).
    ctx.a[0] = IV[0];
    ctx.b[0] = IV[1];
    ctx.c[0] = IV[2];
    ctx.d[0] = IV[3];
    ctx.e[0] = IV[4];
    for lane in 1..4 {
        ctx.a[lane] = sentinel[0];
        ctx.b[lane] = sentinel[1];
        ctx.c[lane] = sentinel[2];
        ctx.d[lane] = sentinel[3];
        ctx.e[lane] = sentinel[4];
    }
    let jobs = [
        Sha1MultiJob::new(&data, 2),
        Sha1MultiJob::empty(),
        Sha1MultiJob::empty(),
        Sha1MultiJob::empty(),
        Sha1MultiJob::empty(),
        Sha1MultiJob::empty(),
        Sha1MultiJob::empty(),
        Sha1MultiJob::empty(),
    ];
    multi_block(&mut ctx, &jobs, 1);
    // Lane 0 updated correctly.
    let mut expect = IV;
    sha1_blocks_portable(&mut expect, &data);
    assert_eq!([ctx.a[0], ctx.b[0], ctx.c[0], ctx.d[0], ctx.e[0]], expect);
    // Lanes 1-3 untouched.
    for lane in 1..4 {
        assert_eq!(
            [
                ctx.a[lane],
                ctx.b[lane],
                ctx.c[lane],
                ctx.d[lane],
                ctx.e[lane]
            ],
            sentinel,
            "lane={lane} must be preserved"
        );
    }
}

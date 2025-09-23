use super::{BLOCK_SIZE, IV};

const PRECOMPUTED: [[u8; 16]; 12] = [
    [0, 2, 4, 6, 1, 3, 5, 7, 8, 10, 12, 14, 9, 11, 13, 15],
    [14, 4, 9, 13, 10, 8, 15, 6, 1, 0, 11, 5, 12, 2, 7, 3],
    [11, 12, 5, 15, 8, 0, 2, 13, 10, 3, 7, 9, 14, 6, 1, 4],
    [7, 3, 13, 11, 9, 1, 12, 14, 2, 5, 4, 15, 6, 10, 0, 8],
    [9, 5, 2, 10, 0, 7, 4, 15, 14, 11, 6, 3, 1, 12, 8, 13],
    [2, 6, 0, 8, 12, 10, 11, 3, 4, 7, 15, 1, 13, 5, 14, 9],
    [12, 1, 14, 4, 5, 15, 13, 10, 0, 6, 9, 8, 7, 3, 2, 11],
    [13, 7, 12, 3, 11, 14, 1, 9, 5, 15, 8, 2, 0, 4, 6, 10],
    [6, 14, 11, 0, 15, 9, 3, 8, 12, 13, 1, 10, 2, 7, 4, 5],
    [10, 8, 7, 1, 2, 4, 6, 5, 15, 9, 3, 13, 11, 14, 12, 0],
    [0, 2, 4, 6, 1, 3, 5, 7, 8, 10, 12, 14, 9, 11, 13, 15],
    [14, 4, 9, 13, 10, 8, 15, 6, 1, 0, 11, 5, 12, 2, 7, 3],
];

pub fn hash_blocks_generic(h: &mut [u64; 8], c: &mut [u64; 2], flag: u64, blocks: &[u8]) {
    let mut m = [0u64; 16];
    let mut c0 = c[0];
    let mut c1 = c[1];

    let mut i = 0;
    while i < blocks.len() {
        c0 = c0.wrapping_add(BLOCK_SIZE as u64);
        if c0 < BLOCK_SIZE as u64 {
            c1 = c1.wrapping_add(1);
        }

        let mut v0 = h[0];
        let mut v1 = h[1];
        let mut v2 = h[2];
        let mut v3 = h[3];
        let mut v4 = h[4];
        let mut v5 = h[5];
        let mut v6 = h[6];
        let mut v7 = h[7];
        let mut v8 = IV[0];
        let mut v9 = IV[1];
        let mut v10 = IV[2];
        let mut v11 = IV[3];
        let mut v12 = IV[4];
        let mut v13 = IV[5];
        let mut v14 = IV[6];
        let mut v15 = IV[7];

        v12 ^= c0;
        v13 ^= c1;
        v14 ^= flag;

        (0..16).for_each(|j| {
            m[j] = u64::from_le_bytes([
                blocks[i],
                blocks[i + 1],
                blocks[i + 2],
                blocks[i + 3],
                blocks[i + 4],
                blocks[i + 5],
                blocks[i + 6],
                blocks[i + 7],
            ]);
            i += 8;
        });

        (0..12).for_each(|j| {
            let s = &PRECOMPUTED[j];

            v0 = v0.wrapping_add(m[s[0] as usize]);
            v0 = v0.wrapping_add(v4);
            v12 ^= v0;
            v12 = v12.rotate_right(32);
            v8 = v8.wrapping_add(v12);
            v4 ^= v8;
            v4 = v4.rotate_right(24);
            v1 = v1.wrapping_add(m[s[1] as usize]);
            v1 = v1.wrapping_add(v5);
            v13 ^= v1;
            v13 = v13.rotate_right(32);
            v9 = v9.wrapping_add(v13);
            v5 ^= v9;
            v5 = v5.rotate_right(24);
            v2 = v2.wrapping_add(m[s[2] as usize]);
            v2 = v2.wrapping_add(v6);
            v14 ^= v2;
            v14 = v14.rotate_right(32);
            v10 = v10.wrapping_add(v14);
            v6 ^= v10;
            v6 = v6.rotate_right(24);
            v3 = v3.wrapping_add(m[s[3] as usize]);
            v3 = v3.wrapping_add(v7);
            v15 ^= v3;
            v15 = v15.rotate_right(32);
            v11 = v11.wrapping_add(v15);
            v7 ^= v11;
            v7 = v7.rotate_right(24);

            v0 = v0.wrapping_add(m[s[4] as usize]);
            v0 = v0.wrapping_add(v4);
            v12 ^= v0;
            v12 = v12.rotate_right(16);
            v8 = v8.wrapping_add(v12);
            v4 ^= v8;
            v4 = v4.rotate_right(63);
            v1 = v1.wrapping_add(m[s[5] as usize]);
            v1 = v1.wrapping_add(v5);
            v13 ^= v1;
            v13 = v13.rotate_right(16);
            v9 = v9.wrapping_add(v13);
            v5 ^= v9;
            v5 = v5.rotate_right(63);
            v2 = v2.wrapping_add(m[s[6] as usize]);
            v2 = v2.wrapping_add(v6);
            v14 ^= v2;
            v14 = v14.rotate_right(16);
            v10 = v10.wrapping_add(v14);
            v6 ^= v10;
            v6 = v6.rotate_right(63);
            v3 = v3.wrapping_add(m[s[7] as usize]);
            v3 = v3.wrapping_add(v7);
            v15 ^= v3;
            v15 = v15.rotate_right(16);
            v11 = v11.wrapping_add(v15);
            v7 ^= v11;
            v7 = v7.rotate_right(63);

            v0 = v0.wrapping_add(m[s[8] as usize]);
            v0 = v0.wrapping_add(v5);
            v15 ^= v0;
            v15 = v15.rotate_right(32);
            v10 = v10.wrapping_add(v15);
            v5 ^= v10;
            v5 = v5.rotate_right(24);
            v1 = v1.wrapping_add(m[s[9] as usize]);
            v1 = v1.wrapping_add(v6);
            v12 ^= v1;
            v12 = v12.rotate_right(32);
            v11 = v11.wrapping_add(v12);
            v6 ^= v11;
            v6 = v6.rotate_right(24);
            v2 = v2.wrapping_add(m[s[10] as usize]);
            v2 = v2.wrapping_add(v7);
            v13 ^= v2;
            v13 = v13.rotate_right(32);
            v8 = v8.wrapping_add(v13);
            v7 ^= v8;
            v7 = v7.rotate_right(24);
            v3 = v3.wrapping_add(m[s[11] as usize]);
            v3 = v3.wrapping_add(v4);
            v14 ^= v3;
            v14 = v14.rotate_right(32);
            v9 = v9.wrapping_add(v14);
            v4 ^= v9;
            v4 = v4.rotate_right(24);

            v0 = v0.wrapping_add(m[s[12] as usize]);
            v0 = v0.wrapping_add(v5);
            v15 ^= v0;
            v15 = v15.rotate_right(16);
            v10 = v10.wrapping_add(v15);
            v5 ^= v10;
            v5 = v5.rotate_right(63);
            v1 = v1.wrapping_add(m[s[13] as usize]);
            v1 = v1.wrapping_add(v6);
            v12 ^= v1;
            v12 = v12.rotate_right(16);
            v11 = v11.wrapping_add(v12);
            v6 ^= v11;
            v6 = v6.rotate_right(63);
            v2 = v2.wrapping_add(m[s[14] as usize]);
            v2 = v2.wrapping_add(v7);
            v13 ^= v2;
            v13 = v13.rotate_right(16);
            v8 = v8.wrapping_add(v13);
            v7 ^= v8;
            v7 = v7.rotate_right(63);
            v3 = v3.wrapping_add(m[s[15] as usize]);
            v3 = v3.wrapping_add(v4);
            v14 ^= v3;
            v14 = v14.rotate_right(16);
            v9 = v9.wrapping_add(v14);
            v4 ^= v9;
            v4 = v4.rotate_right(63);
        });

        h[0] ^= v0 ^ v8;
        h[1] ^= v1 ^ v9;
        h[2] ^= v2 ^ v10;
        h[3] ^= v3 ^ v11;
        h[4] ^= v4 ^ v12;
        h[5] ^= v5 ^ v13;
        h[6] ^= v6 ^ v14;
        h[7] ^= v7 ^ v15;
    }
    c[0] = c0;
    c[1] = c1;
}

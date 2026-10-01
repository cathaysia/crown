use super::{BLOCK_SIZE, IV};

// The G function with the blake2s rotation schedule; rotations are written
// in the reciprocal (left) form used by this module.
macro_rules! g {
    ($a:ident, $b:ident, $c:ident, $d:ident, $mx:expr, $my:expr) => {
        $a = $a.wrapping_add($mx);
        $a = $a.wrapping_add($b);
        $d ^= $a;
        $d = $d.rotate_left(16);
        $c = $c.wrapping_add($d);
        $b ^= $c;
        $b = $b.rotate_left(20);
        $a = $a.wrapping_add($my);
        $a = $a.wrapping_add($b);
        $d ^= $a;
        $d = $d.rotate_left(24);
        $c = $c.wrapping_add($d);
        $b ^= $c;
        $b = $b.rotate_left(25);
    };
}

pub fn hash_blocks_generic(h: &mut [u32; 8], c: &mut [u32; 2], flag: u32, blocks: &[u8]) {
    let mut m = [0u32; 16];
    let mut c0 = c[0];
    let mut c1 = c[1];

    let mut i = 0;
    while i < blocks.len() {
        c0 = c0.wrapping_add(BLOCK_SIZE as u32);
        if c0 < BLOCK_SIZE as u32 {
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

        for (j, chunk) in blocks[i..i + BLOCK_SIZE]
            .as_chunks::<4>()
            .0
            .iter()
            .enumerate()
        {
            m[j] = u32::from_le_bytes(*chunk);
        }
        i += BLOCK_SIZE;

        // Round 0
        g!(v0, v4, v8, v12, m[0], m[1]);
        g!(v1, v5, v9, v13, m[2], m[3]);
        g!(v2, v6, v10, v14, m[4], m[5]);
        g!(v3, v7, v11, v15, m[6], m[7]);
        g!(v0, v5, v10, v15, m[8], m[9]);
        g!(v1, v6, v11, v12, m[10], m[11]);
        g!(v2, v7, v8, v13, m[12], m[13]);
        g!(v3, v4, v9, v14, m[14], m[15]);

        // Round 1
        g!(v0, v4, v8, v12, m[14], m[10]);
        g!(v1, v5, v9, v13, m[4], m[8]);
        g!(v2, v6, v10, v14, m[9], m[15]);
        g!(v3, v7, v11, v15, m[13], m[6]);
        g!(v0, v5, v10, v15, m[1], m[12]);
        g!(v1, v6, v11, v12, m[0], m[2]);
        g!(v2, v7, v8, v13, m[11], m[7]);
        g!(v3, v4, v9, v14, m[5], m[3]);

        // Round 2
        g!(v0, v4, v8, v12, m[11], m[8]);
        g!(v1, v5, v9, v13, m[12], m[0]);
        g!(v2, v6, v10, v14, m[5], m[2]);
        g!(v3, v7, v11, v15, m[15], m[13]);
        g!(v0, v5, v10, v15, m[10], m[14]);
        g!(v1, v6, v11, v12, m[3], m[6]);
        g!(v2, v7, v8, v13, m[7], m[1]);
        g!(v3, v4, v9, v14, m[9], m[4]);

        // Round 3
        g!(v0, v4, v8, v12, m[7], m[9]);
        g!(v1, v5, v9, v13, m[3], m[1]);
        g!(v2, v6, v10, v14, m[13], m[12]);
        g!(v3, v7, v11, v15, m[11], m[14]);
        g!(v0, v5, v10, v15, m[2], m[6]);
        g!(v1, v6, v11, v12, m[5], m[10]);
        g!(v2, v7, v8, v13, m[4], m[0]);
        g!(v3, v4, v9, v14, m[15], m[8]);

        // Round 4
        g!(v0, v4, v8, v12, m[9], m[0]);
        g!(v1, v5, v9, v13, m[5], m[7]);
        g!(v2, v6, v10, v14, m[2], m[4]);
        g!(v3, v7, v11, v15, m[10], m[15]);
        g!(v0, v5, v10, v15, m[14], m[1]);
        g!(v1, v6, v11, v12, m[11], m[12]);
        g!(v2, v7, v8, v13, m[6], m[8]);
        g!(v3, v4, v9, v14, m[3], m[13]);

        // Round 5
        g!(v0, v4, v8, v12, m[2], m[12]);
        g!(v1, v5, v9, v13, m[6], m[10]);
        g!(v2, v6, v10, v14, m[0], m[11]);
        g!(v3, v7, v11, v15, m[8], m[3]);
        g!(v0, v5, v10, v15, m[4], m[13]);
        g!(v1, v6, v11, v12, m[7], m[5]);
        g!(v2, v7, v8, v13, m[15], m[14]);
        g!(v3, v4, v9, v14, m[1], m[9]);

        // Round 6
        g!(v0, v4, v8, v12, m[12], m[5]);
        g!(v1, v5, v9, v13, m[1], m[15]);
        g!(v2, v6, v10, v14, m[14], m[13]);
        g!(v3, v7, v11, v15, m[4], m[10]);
        g!(v0, v5, v10, v15, m[0], m[7]);
        g!(v1, v6, v11, v12, m[6], m[3]);
        g!(v2, v7, v8, v13, m[9], m[2]);
        g!(v3, v4, v9, v14, m[8], m[11]);

        // Round 7
        g!(v0, v4, v8, v12, m[13], m[11]);
        g!(v1, v5, v9, v13, m[7], m[14]);
        g!(v2, v6, v10, v14, m[12], m[1]);
        g!(v3, v7, v11, v15, m[3], m[9]);
        g!(v0, v5, v10, v15, m[5], m[0]);
        g!(v1, v6, v11, v12, m[15], m[4]);
        g!(v2, v7, v8, v13, m[8], m[6]);
        g!(v3, v4, v9, v14, m[2], m[10]);

        // Round 8
        g!(v0, v4, v8, v12, m[6], m[15]);
        g!(v1, v5, v9, v13, m[14], m[9]);
        g!(v2, v6, v10, v14, m[11], m[3]);
        g!(v3, v7, v11, v15, m[0], m[8]);
        g!(v0, v5, v10, v15, m[12], m[2]);
        g!(v1, v6, v11, v12, m[13], m[7]);
        g!(v2, v7, v8, v13, m[1], m[4]);
        g!(v3, v4, v9, v14, m[10], m[5]);

        // Round 9
        g!(v0, v4, v8, v12, m[10], m[2]);
        g!(v1, v5, v9, v13, m[8], m[4]);
        g!(v2, v6, v10, v14, m[7], m[6]);
        g!(v3, v7, v11, v15, m[1], m[5]);
        g!(v0, v5, v10, v15, m[15], m[11]);
        g!(v1, v6, v11, v12, m[9], m[14]);
        g!(v2, v7, v8, v13, m[3], m[12]);
        g!(v3, v4, v9, v14, m[13], m[0]);

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

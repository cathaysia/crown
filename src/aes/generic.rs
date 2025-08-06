use crate::aes::{BlockExpanded, POWX, SBOX0, SBOX1, TD0, TD1, TD2, TD3, TE0, TE1, TE2, TE3};

fn check_generic_is_expected() {
    // Implementation specific check
}

pub fn encrypt_block_generic(c: &BlockExpanded, dst: &mut [u8], src: &[u8]) {
    check_generic_is_expected();
    let xk = &c.enc;

    assert!(src.len() >= 16);
    let s0 = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
    let s1 = u32::from_be_bytes([src[4], src[5], src[6], src[7]]);
    let s2 = u32::from_be_bytes([src[8], src[9], src[10], src[11]]);
    let s3 = u32::from_be_bytes([src[12], src[13], src[14], src[15]]);

    let mut s0 = s0 ^ xk[0];
    let mut s1 = s1 ^ xk[1];
    let mut s2 = s2 ^ xk[2];
    let mut s3 = s3 ^ xk[3];

    let mut k = 4;
    for _ in 0..c.rounds - 1 {
        let t0 = xk[k]
            ^ TE0[((s0 >> 24) & 0xff) as usize]
            ^ TE1[((s1 >> 16) & 0xff) as usize]
            ^ TE2[((s2 >> 8) & 0xff) as usize]
            ^ TE3[(s3 & 0xff) as usize];
        let t1 = xk[k + 1]
            ^ TE0[((s1 >> 24) & 0xff) as usize]
            ^ TE1[((s2 >> 16) & 0xff) as usize]
            ^ TE2[((s3 >> 8) & 0xff) as usize]
            ^ TE3[(s0 & 0xff) as usize];
        let t2 = xk[k + 2]
            ^ TE0[((s2 >> 24) & 0xff) as usize]
            ^ TE1[((s3 >> 16) & 0xff) as usize]
            ^ TE2[((s0 >> 8) & 0xff) as usize]
            ^ TE3[(s1 & 0xff) as usize];
        let t3 = xk[k + 3]
            ^ TE0[((s3 >> 24) & 0xff) as usize]
            ^ TE1[((s0 >> 16) & 0xff) as usize]
            ^ TE2[((s1 >> 8) & 0xff) as usize]
            ^ TE3[(s2 & 0xff) as usize];
        k += 4;
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    let t0 = s0;
    let t1 = s1;
    let t2 = s2;
    let t3 = s3;

    s0 = ((SBOX0[((t0 >> 24) & 0xff) as usize] as u32) << 24)
        | ((SBOX0[((t1 >> 16) & 0xff) as usize] as u32) << 16)
        | ((SBOX0[((t2 >> 8) & 0xff) as usize] as u32) << 8)
        | (SBOX0[(t3 & 0xff) as usize] as u32);
    s1 = ((SBOX0[((t1 >> 24) & 0xff) as usize] as u32) << 24)
        | ((SBOX0[((t2 >> 16) & 0xff) as usize] as u32) << 16)
        | ((SBOX0[((t3 >> 8) & 0xff) as usize] as u32) << 8)
        | (SBOX0[(t0 & 0xff) as usize] as u32);
    s2 = ((SBOX0[((t2 >> 24) & 0xff) as usize] as u32) << 24)
        | ((SBOX0[((t3 >> 16) & 0xff) as usize] as u32) << 16)
        | ((SBOX0[((t0 >> 8) & 0xff) as usize] as u32) << 8)
        | (SBOX0[(t1 & 0xff) as usize] as u32);
    s3 = ((SBOX0[((t3 >> 24) & 0xff) as usize] as u32) << 24)
        | ((SBOX0[((t0 >> 16) & 0xff) as usize] as u32) << 16)
        | ((SBOX0[((t1 >> 8) & 0xff) as usize] as u32) << 8)
        | (SBOX0[(t2 & 0xff) as usize] as u32);

    s0 ^= xk[k];
    s1 ^= xk[k + 1];
    s2 ^= xk[k + 2];
    s3 ^= xk[k + 3];

    assert!(dst.len() >= 16);
    dst[0..4].copy_from_slice(&s0.to_be_bytes());
    dst[4..8].copy_from_slice(&s1.to_be_bytes());
    dst[8..12].copy_from_slice(&s2.to_be_bytes());
    dst[12..16].copy_from_slice(&s3.to_be_bytes());
}

pub fn decrypt_block_generic(c: &BlockExpanded, dst: &mut [u8], src: &[u8]) {
    check_generic_is_expected();
    let xk = &c.dec;

    assert!(src.len() >= 16);
    let s0 = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
    let s1 = u32::from_be_bytes([src[4], src[5], src[6], src[7]]);
    let s2 = u32::from_be_bytes([src[8], src[9], src[10], src[11]]);
    let s3 = u32::from_be_bytes([src[12], src[13], src[14], src[15]]);

    let mut s0 = s0 ^ xk[0];
    let mut s1 = s1 ^ xk[1];
    let mut s2 = s2 ^ xk[2];
    let mut s3 = s3 ^ xk[3];

    let mut k = 4;
    for _ in 0..c.rounds - 1 {
        let t0 = xk[k]
            ^ TD0[((s0 >> 24) & 0xff) as usize]
            ^ TD1[((s3 >> 16) & 0xff) as usize]
            ^ TD2[((s2 >> 8) & 0xff) as usize]
            ^ TD3[(s1 & 0xff) as usize];
        let t1 = xk[k + 1]
            ^ TD0[((s1 >> 24) & 0xff) as usize]
            ^ TD1[((s0 >> 16) & 0xff) as usize]
            ^ TD2[((s3 >> 8) & 0xff) as usize]
            ^ TD3[(s2 & 0xff) as usize];
        let t2 = xk[k + 2]
            ^ TD0[((s2 >> 24) & 0xff) as usize]
            ^ TD1[((s1 >> 16) & 0xff) as usize]
            ^ TD2[((s0 >> 8) & 0xff) as usize]
            ^ TD3[(s3 & 0xff) as usize];
        let t3 = xk[k + 3]
            ^ TD0[((s3 >> 24) & 0xff) as usize]
            ^ TD1[((s2 >> 16) & 0xff) as usize]
            ^ TD2[((s1 >> 8) & 0xff) as usize]
            ^ TD3[(s0 & 0xff) as usize];
        k += 4;
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    let t0 = s0;
    let t1 = s1;
    let t2 = s2;
    let t3 = s3;

    s0 = ((SBOX1[((t0 >> 24) & 0xff) as usize] as u32) << 24)
        | ((SBOX1[((t3 >> 16) & 0xff) as usize] as u32) << 16)
        | ((SBOX1[((t2 >> 8) & 0xff) as usize] as u32) << 8)
        | (SBOX1[(t1 & 0xff) as usize] as u32);
    s1 = ((SBOX1[((t1 >> 24) & 0xff) as usize] as u32) << 24)
        | ((SBOX1[((t0 >> 16) & 0xff) as usize] as u32) << 16)
        | ((SBOX1[((t3 >> 8) & 0xff) as usize] as u32) << 8)
        | (SBOX1[(t2 & 0xff) as usize] as u32);
    s2 = ((SBOX1[((t2 >> 24) & 0xff) as usize] as u32) << 24)
        | ((SBOX1[((t1 >> 16) & 0xff) as usize] as u32) << 16)
        | ((SBOX1[((t0 >> 8) & 0xff) as usize] as u32) << 8)
        | (SBOX1[(t3 & 0xff) as usize] as u32);
    s3 = ((SBOX1[((t3 >> 24) & 0xff) as usize] as u32) << 24)
        | ((SBOX1[((t2 >> 16) & 0xff) as usize] as u32) << 16)
        | ((SBOX1[((t1 >> 8) & 0xff) as usize] as u32) << 8)
        | (SBOX1[(t0 & 0xff) as usize] as u32);

    s0 ^= xk[k];
    s1 ^= xk[k + 1];
    s2 ^= xk[k + 2];
    s3 ^= xk[k + 3];

    assert!(dst.len() >= 16);
    dst[0..4].copy_from_slice(&s0.to_be_bytes());
    dst[4..8].copy_from_slice(&s1.to_be_bytes());
    dst[8..12].copy_from_slice(&s2.to_be_bytes());
    dst[12..16].copy_from_slice(&s3.to_be_bytes());
}

fn subw(w: u32) -> u32 {
    ((SBOX0[((w >> 24) & 0xff) as usize] as u32) << 24)
        | ((SBOX0[((w >> 16) & 0xff) as usize] as u32) << 16)
        | ((SBOX0[((w >> 8) & 0xff) as usize] as u32) << 8)
        | (SBOX0[(w & 0xff) as usize] as u32)
}

fn rotw(w: u32) -> u32 {
    w.rotate_left(8)
}

pub fn expand_key_generic(c: &mut BlockExpanded, key: &[u8]) {
    check_generic_is_expected();

    let nk = key.len() / 4;
    let mut i = 0;

    for j in 0..nk {
        c.enc[j] = u32::from_be_bytes([key[4 * j], key[4 * j + 1], key[4 * j + 2], key[4 * j + 3]]);
        i += 1;
    }

    while i < c.round_keys_size() {
        let mut t = c.enc[i - 1];
        if i % nk == 0 {
            t = subw(rotw(t)) ^ ((POWX[i / nk - 1] as u32) << 24);
        } else if nk > 6 && i % nk == 4 {
            t = subw(t);
        }
        c.enc[i] = c.enc[i - nk] ^ t;
        i += 1;
    }

    let n = c.round_keys_size();
    let mut i = 0;
    while i < n {
        let ei = n - i - 4;
        for j in 0..4 {
            let mut x = c.enc[ei + j];
            if i > 0 && i + 4 < n {
                x = TD0[SBOX0[((x >> 24) & 0xff) as usize] as usize]
                    ^ TD1[SBOX0[((x >> 16) & 0xff) as usize] as usize]
                    ^ TD2[SBOX0[((x >> 8) & 0xff) as usize] as usize]
                    ^ TD3[SBOX0[(x & 0xff) as usize] as usize];
            }
            c.dec[i + j] = x;
        }
        i += 4;
    }
}

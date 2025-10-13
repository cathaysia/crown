#[cfg(test)]
mod tests;

use crate::error::CryptoError;
use crate::error::CryptoResult;
use crate::hash::sha256;
use crate::password_hash::pbkdf2;
use alloc::vec;
use alloc::vec::Vec;

const MAX_INT: i32 = i32::MAX;

fn block_copy(dst: &mut [u32], src: &[u32], n: usize) {
    dst[..n].copy_from_slice(&src[..n]);
}

fn block_xor(dst: &mut [u32], src: &[u32], n: usize) {
    for (i, &v) in src[..n].iter().enumerate() {
        dst[i] ^= v;
    }
}

fn salsa_xor(tmp: &mut [u32; 16], input: &[u32], out: &mut [u32]) {
    let w0 = tmp[0] ^ input[0];
    let w1 = tmp[1] ^ input[1];
    let w2 = tmp[2] ^ input[2];
    let w3 = tmp[3] ^ input[3];
    let w4 = tmp[4] ^ input[4];
    let w5 = tmp[5] ^ input[5];
    let w6 = tmp[6] ^ input[6];
    let w7 = tmp[7] ^ input[7];
    let w8 = tmp[8] ^ input[8];
    let w9 = tmp[9] ^ input[9];
    let w10 = tmp[10] ^ input[10];
    let w11 = tmp[11] ^ input[11];
    let w12 = tmp[12] ^ input[12];
    let w13 = tmp[13] ^ input[13];
    let w14 = tmp[14] ^ input[14];
    let w15 = tmp[15] ^ input[15];

    let mut x0 = w0;
    let mut x1 = w1;
    let mut x2 = w2;
    let mut x3 = w3;
    let mut x4 = w4;
    let mut x5 = w5;
    let mut x6 = w6;
    let mut x7 = w7;
    let mut x8 = w8;
    let mut x9 = w9;
    let mut x10 = w10;
    let mut x11 = w11;
    let mut x12 = w12;
    let mut x13 = w13;
    let mut x14 = w14;
    let mut x15 = w15;

    for _ in (0..8).step_by(2) {
        x4 ^= (x0.wrapping_add(x12)).rotate_left(7);
        x8 ^= (x4.wrapping_add(x0)).rotate_left(9);
        x12 ^= (x8.wrapping_add(x4)).rotate_left(13);
        x0 ^= (x12.wrapping_add(x8)).rotate_left(18);

        x9 ^= (x5.wrapping_add(x1)).rotate_left(7);
        x13 ^= (x9.wrapping_add(x5)).rotate_left(9);
        x1 ^= (x13.wrapping_add(x9)).rotate_left(13);
        x5 ^= (x1.wrapping_add(x13)).rotate_left(18);

        x14 ^= (x10.wrapping_add(x6)).rotate_left(7);
        x2 ^= (x14.wrapping_add(x10)).rotate_left(9);
        x6 ^= (x2.wrapping_add(x14)).rotate_left(13);
        x10 ^= (x6.wrapping_add(x2)).rotate_left(18);

        x3 ^= (x15.wrapping_add(x11)).rotate_left(7);
        x7 ^= (x3.wrapping_add(x15)).rotate_left(9);
        x11 ^= (x7.wrapping_add(x3)).rotate_left(13);
        x15 ^= (x11.wrapping_add(x7)).rotate_left(18);

        x1 ^= (x0.wrapping_add(x3)).rotate_left(7);
        x2 ^= (x1.wrapping_add(x0)).rotate_left(9);
        x3 ^= (x2.wrapping_add(x1)).rotate_left(13);
        x0 ^= (x3.wrapping_add(x2)).rotate_left(18);

        x6 ^= (x5.wrapping_add(x4)).rotate_left(7);
        x7 ^= (x6.wrapping_add(x5)).rotate_left(9);
        x4 ^= (x7.wrapping_add(x6)).rotate_left(13);
        x5 ^= (x4.wrapping_add(x7)).rotate_left(18);

        x11 ^= (x10.wrapping_add(x9)).rotate_left(7);
        x8 ^= (x11.wrapping_add(x10)).rotate_left(9);
        x9 ^= (x8.wrapping_add(x11)).rotate_left(13);
        x10 ^= (x9.wrapping_add(x8)).rotate_left(18);

        x12 ^= (x15.wrapping_add(x14)).rotate_left(7);
        x13 ^= (x12.wrapping_add(x15)).rotate_left(9);
        x14 ^= (x13.wrapping_add(x12)).rotate_left(13);
        x15 ^= (x14.wrapping_add(x13)).rotate_left(18);
    }

    x0 = x0.wrapping_add(w0);
    x1 = x1.wrapping_add(w1);
    x2 = x2.wrapping_add(w2);
    x3 = x3.wrapping_add(w3);
    x4 = x4.wrapping_add(w4);
    x5 = x5.wrapping_add(w5);
    x6 = x6.wrapping_add(w6);
    x7 = x7.wrapping_add(w7);
    x8 = x8.wrapping_add(w8);
    x9 = x9.wrapping_add(w9);
    x10 = x10.wrapping_add(w10);
    x11 = x11.wrapping_add(w11);
    x12 = x12.wrapping_add(w12);
    x13 = x13.wrapping_add(w13);
    x14 = x14.wrapping_add(w14);
    x15 = x15.wrapping_add(w15);

    out[0] = x0;
    tmp[0] = x0;
    out[1] = x1;
    tmp[1] = x1;
    out[2] = x2;
    tmp[2] = x2;
    out[3] = x3;
    tmp[3] = x3;
    out[4] = x4;
    tmp[4] = x4;
    out[5] = x5;
    tmp[5] = x5;
    out[6] = x6;
    tmp[6] = x6;
    out[7] = x7;
    tmp[7] = x7;
    out[8] = x8;
    tmp[8] = x8;
    out[9] = x9;
    tmp[9] = x9;
    out[10] = x10;
    tmp[10] = x10;
    out[11] = x11;
    tmp[11] = x11;
    out[12] = x12;
    tmp[12] = x12;
    out[13] = x13;
    tmp[13] = x13;
    out[14] = x14;
    tmp[14] = x14;
    out[15] = x15;
    tmp[15] = x15;
}

fn block_mix(tmp: &mut [u32; 16], input: &[u32], out: &mut [u32], r: usize) {
    block_copy(tmp, &input[(2 * r - 1) * 16..], 16);
    for i in (0..2 * r).step_by(2) {
        salsa_xor(tmp, &input[i * 16..], &mut out[i * 8..]);
        salsa_xor(tmp, &input[i * 16 + 16..], &mut out[i * 8 + r * 16..]);
    }
}

fn integer(b: &[u32], r: usize) -> u64 {
    let j = (2 * r - 1) * 16;
    (b[j] as u64) | ((b[j + 1] as u64) << 32)
}

fn smix(b: &mut [u8], r: usize, n: usize, v: &mut [u32], xy: &mut [u32]) {
    let mut tmp = [0u32; 16];
    let big_r = 32 * r;
    let (x, y) = xy.split_at_mut(big_r);

    let mut j = 0;
    (0..big_r).for_each(|i| {
        x[i] = u32::from_le_bytes([b[j], b[j + 1], b[j + 2], b[j + 3]]);
        j += 4;
    });

    for i in (0..n).step_by(2) {
        block_copy(&mut v[i * big_r..], x, big_r);
        block_mix(&mut tmp, x, y, r);

        block_copy(&mut v[(i + 1) * big_r..], y, big_r);
        block_mix(&mut tmp, y, x, r);
    }

    for _ in (0..n).step_by(2) {
        let j = (integer(x, r) & ((n - 1) as u64)) as usize;
        block_xor(x, &v[j * big_r..], big_r);
        block_mix(&mut tmp, x, y, r);

        let j = (integer(y, r) & ((n - 1) as u64)) as usize;
        block_xor(y, &v[j * big_r..], big_r);
        block_mix(&mut tmp, y, x, r);
    }

    j = 0;
    for &v in &x[..big_r] {
        let bytes = v.to_le_bytes();
        b[j..j + 4].copy_from_slice(&bytes);
        j += 4;
    }
}

pub fn key(
    password: &[u8],
    salt: &[u8],
    n: usize,
    r: usize,
    p: usize,
    key_len: usize,
) -> CryptoResult<Vec<u8>> {
    if n <= 1 || (n & (n - 1)) != 0 {
        return Err(CryptoError::StrError({
            "scrypt: N must be > 1 and a power of 2"
        }));
    }
    if (r as u64) * (p as u64) >= 1 << 30
        || r > (MAX_INT as usize) / 128 / p
        || r > (MAX_INT as usize) / 256
        || n > (MAX_INT as usize) / 128 / r
    {
        return Err(CryptoError::StrError({
            "scrypt: parameters are too large"
        }));
    }

    let mut xy = vec![0u32; 64 * r];
    let mut v = vec![0u32; 32 * n * r];
    let mut b = pbkdf2::key(password, salt, 1, p * 128 * r, sha256::new256);

    for i in 0..p {
        smix(&mut b[i * 128 * r..], r, n, &mut v, &mut xy);
    }

    Ok(pbkdf2::key(password, &b, 1, key_len, sha256::new256))
}

use bytes::{Buf, BufMut};

use crate::utils::copy;

const ROUNDS: usize = 20;

pub const SIGMA: [u8; 16] = *b"expand 32-byte k";

pub fn core(inout: &mut [u8; 64], key: &[u8; 32], constant: &[u8; 16]) {
    let mut key = key.as_slice();
    let mut input1 = inout.as_slice();
    let mut constant = constant.as_slice();

    let j0 = constant.get_u32_le();
    let j1 = key.get_u32_le();
    let j2 = key.get_u32_le();
    let j3 = key.get_u32_le();
    let j4 = key.get_u32_le();
    let j5 = constant.get_u32_le();
    let j6 = input1.get_u32_le();
    let j7 = input1.get_u32_le();
    let j8 = input1.get_u32_le();
    let j9 = input1.get_u32_le();
    let j10 = constant.get_u32_le();
    let j11 = key.get_u32_le();
    let j12 = key.get_u32_le();
    let j13 = key.get_u32_le();
    let j14 = key.get_u32_le();
    let j15 = constant.get_u32_le();

    let mut x0 = j0;
    let mut x1 = j1;
    let mut x2 = j2;
    let mut x3 = j3;
    let mut x4 = j4;
    let mut x5 = j5;
    let mut x6 = j6;
    let mut x7 = j7;
    let mut x8 = j8;
    let mut x9 = j9;
    let mut x10 = j10;
    let mut x11 = j11;
    let mut x12 = j12;
    let mut x13 = j13;
    let mut x14 = j14;
    let mut x15 = j15;

    for _ in (0..ROUNDS).step_by(2) {
        let mut u = x0.wrapping_add(x12);
        x4 ^= u.rotate_left(7);
        u = x4.wrapping_add(x0);
        x8 ^= u.rotate_left(9);
        u = x8.wrapping_add(x4);
        x12 ^= u.rotate_left(13);
        u = x12.wrapping_add(x8);
        x0 ^= u.rotate_left(18);

        u = x5.wrapping_add(x1);
        x9 ^= u.rotate_left(7);
        u = x9.wrapping_add(x5);
        x13 ^= u.rotate_left(9);
        u = x13.wrapping_add(x9);
        x1 ^= u.rotate_left(13);
        u = x1.wrapping_add(x13);
        x5 ^= u.rotate_left(18);

        u = x10.wrapping_add(x6);
        x14 ^= u.rotate_left(7);
        u = x14.wrapping_add(x10);
        x2 ^= u.rotate_left(9);
        u = x2.wrapping_add(x14);
        x6 ^= u.rotate_left(13);
        u = x6.wrapping_add(x2);
        x10 ^= u.rotate_left(18);

        u = x15.wrapping_add(x11);
        x3 ^= u.rotate_left(7);
        u = x3.wrapping_add(x15);
        x7 ^= u.rotate_left(9);
        u = x7.wrapping_add(x3);
        x11 ^= u.rotate_left(13);
        u = x11.wrapping_add(x7);
        x15 ^= u.rotate_left(18);

        u = x0.wrapping_add(x3);
        x1 ^= u.rotate_left(7);
        u = x1.wrapping_add(x0);
        x2 ^= u.rotate_left(9);
        u = x2.wrapping_add(x1);
        x3 ^= u.rotate_left(13);
        u = x3.wrapping_add(x2);
        x0 ^= u.rotate_left(18);

        u = x5.wrapping_add(x4);
        x6 ^= u.rotate_left(7);
        u = x6.wrapping_add(x5);
        x7 ^= u.rotate_left(9);
        u = x7.wrapping_add(x6);
        x4 ^= u.rotate_left(13);
        u = x4.wrapping_add(x7);
        x5 ^= u.rotate_left(18);

        u = x10.wrapping_add(x9);
        x11 ^= u.rotate_left(7);
        u = x11.wrapping_add(x10);
        x8 ^= u.rotate_left(9);
        u = x8.wrapping_add(x11);
        x9 ^= u.rotate_left(13);
        u = x9.wrapping_add(x8);
        x10 ^= u.rotate_left(18);

        u = x15.wrapping_add(x14);
        x12 ^= u.rotate_left(7);
        u = x12.wrapping_add(x15);
        x13 ^= u.rotate_left(9);
        u = x13.wrapping_add(x12);
        x14 ^= u.rotate_left(13);
        u = x14.wrapping_add(x13);
        x15 ^= u.rotate_left(18);
    }

    x0 = x0.wrapping_add(j0);
    x1 = x1.wrapping_add(j1);
    x2 = x2.wrapping_add(j2);
    x3 = x3.wrapping_add(j3);
    x4 = x4.wrapping_add(j4);
    x5 = x5.wrapping_add(j5);
    x6 = x6.wrapping_add(j6);
    x7 = x7.wrapping_add(j7);
    x8 = x8.wrapping_add(j8);
    x9 = x9.wrapping_add(j9);
    x10 = x10.wrapping_add(j10);
    x11 = x11.wrapping_add(j11);
    x12 = x12.wrapping_add(j12);
    x13 = x13.wrapping_add(j13);
    x14 = x14.wrapping_add(j14);
    x15 = x15.wrapping_add(j15);

    let mut out = inout.as_mut_slice();
    out.put_u32_le(x0);
    out.put_u32_le(x1);
    out.put_u32_le(x2);
    out.put_u32_le(x3);
    out.put_u32_le(x4);
    out.put_u32_le(x5);
    out.put_u32_le(x6);
    out.put_u32_le(x7);
    out.put_u32_le(x8);
    out.put_u32_le(x9);
    out.put_u32_le(x10);
    out.put_u32_le(x11);
    out.put_u32_le(x12);
    out.put_u32_le(x13);
    out.put_u32_le(x14);
    out.put_u32_le(x15);
}

pub fn generic_xor_key_stream(inout: &mut [u8], counter: &mut [u8; 16], key: &[u8; 32]) {
    let mut block = [0u8; 64];
    let mut counter_copy = *counter;

    let mut out_slice = inout;

    while out_slice.len() >= 64 {
        copy(&mut block, &counter_copy);
        core(&mut block, key, &SIGMA);

        for i in 0..64 {
            out_slice[i] ^= block[i];
        }

        let mut u = 1u32;
        (8..16).for_each(|i| {
            u += counter_copy[i] as u32;
            counter_copy[i] = u as u8;
            u >>= 8;
        });

        out_slice = &mut out_slice[64..];
    }

    if !out_slice.is_empty() {
        copy(&mut block, &counter_copy);
        core(&mut block, key, &SIGMA);
        for (i, v) in out_slice.iter_mut().enumerate() {
            *v ^= block[i];
        }
    }
}

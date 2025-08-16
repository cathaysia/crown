use bytes::{Buf, BufMut};

pub const SIGMA: [u8; 16] = *b"expand 32-byte k";

pub fn hsalsa20(inout: &mut [u8; 32], key: &[u8; 32], constant: &[u8; 16]) {
    let mut key = key.as_slice();
    let mut input2 = inout.as_slice();
    let mut constant = constant.as_slice();

    let mut x0 = constant.get_u32_le();
    let mut x1 = key.get_u32_le();
    let mut x2 = key.get_u32_le();
    let mut x3 = key.get_u32_le();
    let mut x4 = key.get_u32_le();
    let mut x5 = constant.get_u32_le();
    let mut x6 = input2.get_u32_le();
    let mut x7 = input2.get_u32_le();
    let mut x8 = input2.get_u32_le();
    let mut x9 = input2.get_u32_le();
    let mut x10 = constant.get_u32_le();
    let mut x11 = key.get_u32_le();
    let mut x12 = key.get_u32_le();
    let mut x13 = key.get_u32_le();
    let mut x14 = key.get_u32_le();
    let mut x15 = constant.get_u32_le();

    for _ in 0..10 {
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

    let mut out = inout.as_mut_slice();

    out.put_u32_le(x0);
    out.put_u32_le(x5);
    out.put_u32_le(x10);
    out.put_u32_le(x15);
    out.put_u32_le(x6);
    out.put_u32_le(x7);
    out.put_u32_le(x8);
    out.put_u32_le(x9);
}

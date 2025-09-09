use bytes::{Buf, BufMut};

use crate::error::{CryptoError, CryptoResult};

pub struct Rc6Key {
    pub key: [u32; 44],
}

macro_rules! ROL {
    ($w:expr, $i:expr) => {
        $w.rotate_left($i)
    };
}

macro_rules! ROR {
    ($w:expr, $i:expr) => {
        $w.rotate_right($i)
    };
}

static RC6_STAB: [u32; 44] = [
    0xb7e15163, 0x5618cb1c, 0xf45044d5, 0x9287be8e, 0x30bf3847, 0xcef6b200, 0x6d2e2bb9, 0xb65a572,
    0xa99d1f2b, 0x47d498e4, 0xe60c129d, 0x84438c56, 0x227b060f, 0xc0b27fc8, 0x5ee9f981, 0xfd21733a,
    0x9b58ecf3, 0x399066ac, 0xd7c7e065, 0x75ff5a1e, 0x1436d3d7, 0xb26e4d90, 0x50a5c749, 0xeedd4102,
    0x8d14babb, 0x2b4c3474, 0xc983ae2d, 0x67bb27e6, 0x5f2a19f, 0xa42a1b58, 0x42619511, 0xe0990eca,
    0x7ed08883, 0x1d08023c, 0xbb3f7bf5, 0x5976f5ae, 0xf7ae6f67, 0x95e5e920, 0x341d62d9, 0xd254dc92,
    0x708c564b, 0xec3d004, 0xacfb49bd, 0x4b32c376,
];

pub fn rc6_setup(
    key: &[u8],
    keylen: usize,
    num_rounds: usize,
    skey: &mut Rc6Key,
) -> CryptoResult<()> {
    if num_rounds != 0 && num_rounds != 20 {
        return Err(CryptoError::InvalidRound(num_rounds));
    }
    if !(..=128).contains(&keylen) {
        return Err(CryptoError::InvalidKeySize {
            expected: "<= 128",
            actual: keylen,
        });
    }

    let mut j = 0;
    let mut i = j;
    let mut a = i;
    let mut larr = [0u32; 64];
    // copy the key into the L array
    while i < keylen as u32 {
        a = (a << 8) | (key[i as usize] as i32 & 255) as u32;
        i = i.wrapping_add(1);
        if i & 3 == 0 {
            larr[j as usize] = a.swap_bytes();
            j = j.wrapping_add(1);
            a = 0;
        }
    }

    // handle odd sized keys
    if keylen as i32 & 3 != 0 {
        a <<= 8_i32 * (4 - (keylen as i32 & 3));
        let fresh8 = j;
        j = j.wrapping_add(1);
        larr[fresh8 as usize] = a.swap_bytes();
    }
    // setup the S array
    let mut sarr = [0u32; 50];
    sarr[..44].copy_from_slice(&RC6_STAB);

    let s = 3_u32.wrapping_mul(if 44 > j { 44 } else { j });
    let l = j;
    let mut v = 0u32;
    j = v;
    i = j;
    let mut b = i;
    a = b;
    while v < s {
        sarr[i as usize] = ROL!((sarr[i as usize]).wrapping_add(a).wrapping_add(b), 3);
        a = sarr[i as usize];
        larr[j as usize] = {
            ROL!(
                (larr[j as usize]).wrapping_add(a).wrapping_add(b),
                a.wrapping_add(b)
            )
        };
        b = larr[j as usize];
        i = i.wrapping_add(1);
        if i == 44 {
            i = 0;
        }
        j = j.wrapping_add(1);
        if j == l {
            j = 0;
        }
        v = v.wrapping_add(1);
    }
    i = 0;
    while i < 44 {
        skey.key[i as usize] = sarr[i as usize];
        i = i.wrapping_add(1);
    }
    Ok(())
}

pub fn rc6_ecb_encrypt(mut inout: &mut [u8], skey: &Rc6Key) -> CryptoResult<()> {
    let (mut a, mut b, mut c, mut d) = {
        let mut inout = &*inout;
        (
            inout.get_u32_le(),
            inout.get_u32_le(),
            inout.get_u32_le(),
            inout.get_u32_le(),
        )
    };

    b = b.wrapping_add(skey.key[0]);
    d = d.wrapping_add(skey.key[1]);
    let mut key = &skey.key[2..];

    let mut t: u32;
    let mut u: u32;

    macro_rules! RND {
        ($a:ident, $b:ident, $c:ident, $d:ident) => {
            t = $b.wrapping_mul($b.wrapping_add($b).wrapping_add(1));
            t = ROL!(t, 5);
            u = $d.wrapping_mul($d.wrapping_add($d).wrapping_add(1));
            u = ROL!(u, 5);
            $a = (ROL!($a ^ t, u)).wrapping_add(key[0]);
            $c = (ROL!($c ^ u, t)).wrapping_add(key[1]);
            key = &key[2..];
        };
    }

    for _ in 0..5 {
        RND!(a, b, c, d);
        RND!(b, c, d, a);
        RND!(c, d, a, b);
        RND!(d, a, b, c);
    }
    a = a.wrapping_add(skey.key[42]);
    c = c.wrapping_add(skey.key[43]);

    inout.put_u32_le(a);
    inout.put_u32_le(b);
    inout.put_u32_le(c);
    inout.put_u32_le(d);

    Ok(())
}

pub fn rc6_ecb_decrypt(mut inout: &mut [u8], skey: &Rc6Key) -> Result<(), CryptoError> {
    let mut t: u32;
    let mut u: u32;

    let (mut a, mut b, mut c, mut d) = {
        let mut inout = &*inout;
        (
            inout.get_u32_le(),
            inout.get_u32_le(),
            inout.get_u32_le(),
            inout.get_u32_le(),
        )
    };

    a = a.wrapping_sub(skey.key[42]);
    c = c.wrapping_sub(skey.key[43]);

    macro_rules! RND {
        ($idx:ident, $K:ident, $a:ident, $b:ident, $c:ident, $d:ident) => {
            t = $b.wrapping_mul($b.wrapping_add($b).wrapping_add(1));
            t = ROL!(t, 5);
            u = $d.wrapping_mul($d.wrapping_add($d).wrapping_add(1));
            u = ROL!(u, 5);
            $c = ROR!($c.wrapping_sub($K[$idx + 1]), t) ^ u;
            $a = ROR!($a.wrapping_sub($K[$idx]), u) ^ t;
            $idx -= 2;
        };
    }
    let mut idx = 40;
    let key = &skey.key;
    for _ in 0..5 {
        RND!(idx, key, d, a, b, c);
        RND!(idx, key, c, d, a, b);
        RND!(idx, key, b, c, d, a);
        RND!(idx, key, a, b, c, d);
    }
    b = b.wrapping_sub(skey.key[0]);
    d = d.wrapping_sub(skey.key[1]);

    inout.put_u32_le(a);
    inout.put_u32_le(b);
    inout.put_u32_le(c);
    inout.put_u32_le(d);
    Ok(())
}

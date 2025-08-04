#![allow(unsafe_op_in_unsafe_fn, non_snake_case)]

use crate::error::CryptoError;

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

macro_rules! LOAD32L {
    ($ptr:expr) => {
        u32::from_be_bytes([
            (*$ptr.add(3)) & 255,
            (*$ptr.add(2)) & 255,
            (*$ptr.add(1)) & 255,
            (*$ptr.add(0)) & 255,
        ])
    };
}

macro_rules! STORE32L {
    ($x:expr, $y:expr) => {
        std::ptr::copy(std::ptr::addr_of!($x).cast::<u8>(), $y, 4);
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
    key: *const u8,
    keylen: usize,
    num_rounds: usize,
    skey: &mut Rc6Key,
) -> Result<(), CryptoError> {
    assert!(!key.is_null());

    if num_rounds != 0 && num_rounds != 20 {
        return Err(CryptoError::InvalidRound);
    }
    if !(..=128).contains(&keylen) {
        return Err(CryptoError::InvalidKeySize(keylen));
    }

    let mut j = 0;
    let mut i = j;
    let mut A = i;
    let mut L = [0u32; 64];
    // copy the key into the L array
    while i < keylen as u32 {
        let fresh6 = i;
        i = i.wrapping_add(1);
        A = (A << 8) | (unsafe { *key.offset(fresh6 as isize) } as i32 & 255) as u32;
        if i & 3 == 0 {
            let fresh7 = j;
            j = j.wrapping_add(1);
            L[fresh7 as usize] = A.swap_bytes();
            A = 0;
        }
    }

    // handle odd sized keys
    if keylen as i32 & 3 != 0 {
        A <<= 8_i32 * (4 - (keylen as i32 & 3));
        let fresh8 = j;
        j = j.wrapping_add(1);
        L[fresh8 as usize] = A.swap_bytes();
    }
    // setup the S array
    let mut S = [0u32; 50];
    S[..44].copy_from_slice(&RC6_STAB);

    let s = 3_u32.wrapping_mul(if 44 > j { 44 } else { j });
    let l = j;
    let mut v = 0u32;
    j = v;
    i = j;
    let mut B = i;
    A = B;
    while v < s {
        S[i as usize] = ROL!((S[i as usize]).wrapping_add(A).wrapping_add(B), 3);
        A = S[i as usize];
        L[j as usize] = {
            ROL!(
                (L[j as usize]).wrapping_add(A).wrapping_add(B),
                A.wrapping_add(B)
            )
        };
        B = L[j as usize];
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
        skey.key[i as usize] = S[i as usize];
        i = i.wrapping_add(1);
    }
    Ok(())
}

pub unsafe fn rc6_ecb_encrypt(
    pt: *const u8,
    ct: *mut u8,
    skey: &Rc6Key,
) -> Result<(), CryptoError> {
    assert!(!pt.is_null());
    assert!(!ct.is_null());

    let mut a = LOAD32L!(pt.add(0));
    let mut b = LOAD32L!(pt.add(4));
    let mut c = LOAD32L!(pt.add(8));
    let mut d = LOAD32L!(pt.add(12));

    b = b.wrapping_add(skey.key[0]);
    d = d.wrapping_add(skey.key[1]);
    let mut K = (skey.key).as_ptr().offset(2);

    let mut t: u32;
    let mut u: u32;

    macro_rules! RND {
        ($a:ident, $b:ident, $c:ident, $d:ident) => {
            t = $b.wrapping_mul($b.wrapping_add($b).wrapping_add(1));
            t = ROL!(t, 5);
            u = $d.wrapping_mul($d.wrapping_add($d).wrapping_add(1));
            u = ROL!(u, 5);
            $a = (ROL!($a ^ t, u)).wrapping_add(*K.offset(0));
            $c = (ROL!($c ^ u, t)).wrapping_add(*K.offset(1));
            K = K.offset(2);
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

    STORE32L!(a, ct);
    STORE32L!(b, ct.add(4));
    STORE32L!(c, ct.add(8));
    STORE32L!(d, ct.add(12));

    Ok(())
}

pub unsafe fn rc6_ecb_decrypt(
    ct: *const u8,
    pt: *mut u8,
    skey: &Rc6Key,
) -> Result<(), CryptoError> {
    assert!(!pt.is_null());
    assert!(!ct.is_null());

    let mut t: u32;
    let mut u: u32;

    let mut a = LOAD32L!(ct.add(0));
    let mut b = LOAD32L!(ct.add(4));
    let mut c = LOAD32L!(ct.add(8));
    let mut d = LOAD32L!(ct.add(12));

    a = a.wrapping_sub(skey.key[42]);
    c = c.wrapping_sub(skey.key[43]);

    macro_rules! RND {
        ($K:ident, $a:ident, $b:ident, $c:ident, $d:ident) => {
            t = $b.wrapping_mul($b.wrapping_add($b).wrapping_add(1));
            t = ROL!(t, 5);
            u = $d.wrapping_mul($d.wrapping_add($d).wrapping_add(1));
            u = ROL!(u, 5);
            $c = ROR!($c.wrapping_sub(*$K.offset(1)), t) ^ u;
            $a = ROR!($a.wrapping_sub(*$K.offset(0)), u) ^ t;
            $K = $K.offset(-2);
        };
    }
    let mut K = (skey.key).as_ptr().offset(40);
    for _ in 0..5 {
        RND!(K, d, a, b, c);
        RND!(K, c, d, a, b);
        RND!(K, b, c, d, a);
        RND!(K, a, b, c, d);
    }
    b = b.wrapping_sub(skey.key[0]);
    d = d.wrapping_sub(skey.key[1]);

    STORE32L!(a, pt.add(0));
    STORE32L!(b, pt.add(4));
    STORE32L!(c, pt.add(8));
    STORE32L!(d, pt.add(12));
    Ok(())
}

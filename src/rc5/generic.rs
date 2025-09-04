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

use bytes::{Buf, BufMut};

use crate::{
    error::{CryptoError, CryptoResult},
    rc5::Rc5,
};

const DEFAULT_ROUNDS: usize = 12;

static RC5_STAB: [u32; 50] = [
    0xb7e15163, 0x5618cb1c, 0xf45044d5, 0x9287be8e, 0x30bf3847, 0xcef6b200, 0x6d2e2bb9, 0xb65a572,
    0xa99d1f2b, 0x47d498e4, 0xe60c129d, 0x84438c56, 0x227b060f, 0xc0b27fc8, 0x5ee9f981, 0xfd21733a,
    0x9b58ecf3, 0x399066ac, 0xd7c7e065, 0x75ff5a1e, 0x1436d3d7, 0xb26e4d90, 0x50a5c749, 0xeedd4102,
    0x8d14babb, 0x2b4c3474, 0xc983ae2d, 0x67bb27e6, 0x5f2a19f, 0xa42a1b58, 0x42619511, 0xe0990eca,
    0x7ed08883, 0x1d08023c, 0xbb3f7bf5, 0x5976f5ae, 0xf7ae6f67, 0x95e5e920, 0x341d62d9, 0xd254dc92,
    0x708c564b, 0xec3d004, 0xacfb49bd, 0x4b32c376, 0xe96a3d2f, 0x87a1b6e8, 0x25d930a1, 0xc410aa5a,
    0x62482413, 0x7f9dcc,
];

impl Rc5 {
    pub(crate) fn setup(&mut self, key: &[u8], mut num_rounds: usize) -> CryptoResult<()> {
        let mut la: [u32; 64] = [0; 64];

        if num_rounds == 0 {
            num_rounds = DEFAULT_ROUNDS;
        }
        if !(12..=24).contains(&num_rounds) {
            return Err(CryptoError::InvalidRound(num_rounds));
        }
        if !(8..=128).contains(&key.len()) {
            return Err(CryptoError::InvalidKeySize(key.len()));
        }
        self.rounds = num_rounds;
        let skey = &mut self.key;
        let mut j = 0;
        let mut i = j;
        let mut a = i;
        while i < key.len() as u32 {
            let fresh0 = i;
            i = i.wrapping_add(1);
            a = (a << 8) | (key[fresh0 as usize] as i32 & 255) as u32;
            if i & 3 == 0 {
                let fresh1 = j;
                j = j.wrapping_add(1);
                la[fresh1 as usize] = a.swap_bytes();
                a = 0;
            }
        }
        if key.len() & 3 != 0 {
            a <<= (8 * (4 - (key.len() as i32 & 3))) as u32;
            let fresh2 = j;
            j = j.wrapping_add(1);
            la[fresh2 as usize] = a.swap_bytes();
        }
        let t = (2 * (num_rounds + 1)) as u32;
        skey.copy_from_slice(&RC5_STAB);

        let s = 3 * t.max(j);
        let l = j;
        let mut v = 0;
        j = v;
        i = j;
        let mut b = i;
        a = b;
        while v < s {
            let xxx = skey[i as usize];
            let fresh3 = &mut skey[i as usize];
            *fresh3 = ROL!(xxx.wrapping_add(a).wrapping_add(b), 3);
            a = *fresh3;
            la[j as usize] = ROL!(
                (la[j as usize]).wrapping_add(a).wrapping_add(b),
                a.wrapping_add(b)
            );
            b = la[j as usize];
            i = i.wrapping_add(1);
            if i == t {
                i = 0;
            }
            j = j.wrapping_add(1);
            if j == l {
                j = 0;
            }
            v = v.wrapping_add(1);
        }
        Ok(())
    }
    pub(crate) fn encrypt_generic(&self, mut inout: &mut [u8]) -> CryptoResult<()> {
        if self.rounds < 12 || self.rounds > 24 {
            return Err(CryptoError::InvalidRound(self.rounds));
        }
        let (mut a, mut b) = {
            let mut inout = &*inout;
            (inout.get_u32_le(), inout.get_u32_le())
        };

        a = a.wrapping_add(self.key[0]);
        b = b.wrapping_add(self.key[1]);
        let mut key = &self.key[2..];
        if self.rounds as i32 & 1 == 0 {
            (0..self.rounds).step_by(2).for_each(|_| {
                a = ROL!(a ^ b, b).wrapping_add(key[0]);
                b = ROL!(b ^ a, a).wrapping_add(key[1]);
                a = ROL!(a ^ b, b).wrapping_add(key[2]);
                b = ROL!(b ^ a, a).wrapping_add(key[3]);
                key = &key[4..];
            });
        } else {
            (0..self.rounds).for_each(|_| {
                a = ROL!(a ^ b, b).wrapping_add(key[0]);
                b = ROL!(b ^ a, a).wrapping_add(key[1]);
                key = &key[2..];
            });
        }

        inout.put_u32_le(a);
        inout.put_u32_le(b);
        Ok(())
    }

    pub(crate) fn decrypt_generic(&self, mut inout: &mut [u8]) -> CryptoResult<()> {
        if self.rounds < 12 || self.rounds > 24 {
            return Err(CryptoError::InvalidRound(self.rounds));
        }
        let (mut a, mut b) = {
            let mut inout = &*inout;
            (inout.get_u32_le(), inout.get_u32_le())
        };
        let mut idx = self.rounds << 1;
        if self.rounds as i32 & 1 == 0 {
            idx -= 2;
            (0..self.rounds - 1).rev().step_by(2).for_each(|_| {
                b = ROR!(b.wrapping_sub(self.key[idx + 3]), a) ^ a;
                a = ROR!(a.wrapping_sub(self.key[idx + 2]), b) ^ b;
                b = ROR!(b.wrapping_sub(self.key[idx + 1]), a) ^ a;
                a = ROR!(a.wrapping_sub(self.key[idx]), b) ^ b;
                idx = idx.wrapping_sub(4);
            });
        } else {
            (0..self.rounds - 1).rev().for_each(|_| {
                b = ROR!(b - self.key[idx + 1], a) ^ a;
                a = ROR!(a - self.key[idx], b) ^ b;
                idx = idx.wrapping_sub(2);
            });
        }
        a = a.wrapping_sub(self.key[0]);
        b = b.wrapping_sub(self.key[1]);

        inout.put_u32_le(a);
        inout.put_u32_le(b);
        Ok(())
    }
}

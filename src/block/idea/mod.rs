#[cfg(test)]
mod tests;

use bytes::{Buf, BufMut};

use crate::{
    block::{BlockCipher, BlockCipherMarker},
    error::{CryptoError, CryptoResult},
};

const LTC_IDEA_ROUNDS: usize = 8;
const LTC_IDEA_KEYLEN: usize = 6 * LTC_IDEA_ROUNDS + 4;

macro_rules! LOW16 {
    ($x:expr) => {
        $x & 0xffff
    };
}

macro_rules! HIGH16 {
    ($x:expr) => {
        $x >> 16
    };
}

macro_rules! MUL {
    ($a:expr, $b:expr) => {{
        let mut p = LOW16!($a) as u32 * $b as u32;
        if p != 0 {
            p = LOW16!(p).wrapping_sub(HIGH16!(p));
            $a = (p as u16).wrapping_sub(HIGH16!(p) as u16);
        } else {
            $a = 1u16.wrapping_sub($a).wrapping_sub($b);
        }
    }};
}

pub struct Idea {
    ek: [u16; 52],
    dk: [u16; 52],
}

impl BlockCipherMarker for Idea {}

fn s_mul_inv(x: u16) -> u16 {
    let mut y = x;
    for _ in 0..16 {
        MUL!(y, LOW16!(y));
        MUL!(y, x);
    }
    LOW16!(y)
}

fn s_add_inv(x: u16) -> u16 {
    LOW16!(0u16.wrapping_sub(x))
}

impl Idea {
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeySize {
                expected: "16",
                actual: key.len(),
            });
        }
        let mut skey = Idea {
            ek: [0; 52],
            dk: [0; 52],
        };
        skey.init(key)?;
        Ok(skey)
    }

    fn init(&mut self, mut key: &[u8]) -> CryptoResult<()> {
        let e_key = &mut self.ek;
        let d_key = &mut self.dk;

        (0..8).for_each(|i| {
            e_key[i] = key.get_u16();
        });
        for i in 8..(LTC_IDEA_KEYLEN as isize) {
            let j = (i - i % 8) - 8;
            e_key[i as usize] = LOW16!(
                (e_key[(j + (i + 1) % 8) as usize] << 9) | (e_key[(j + (i + 2) % 8) as usize] >> 7)
            );
        }

        for i in 0..LTC_IDEA_ROUNDS {
            d_key[i * 6] = s_mul_inv(e_key[(LTC_IDEA_ROUNDS - i) * 6]);
            d_key[i * 6 + 1] =
                s_add_inv(e_key[(LTC_IDEA_ROUNDS - i) * 6 + 1 + (if i > 0 { 1 } else { 0 })]);
            d_key[i * 6 + 2] =
                s_add_inv(e_key[(LTC_IDEA_ROUNDS - i) * 6 + 2 - (if i > 0 { 1 } else { 0 })]);
            d_key[i * 6 + 3] = s_mul_inv(e_key[(LTC_IDEA_ROUNDS - i) * 6 + 3]);
            d_key[i * 6 + 4] = e_key[(LTC_IDEA_ROUNDS - 1 - i) * 6 + 4];
            d_key[i * 6 + 5] = e_key[(LTC_IDEA_ROUNDS - 1 - i) * 6 + 5];
        }
        let i = LTC_IDEA_ROUNDS;
        d_key[i * 6] = s_mul_inv(e_key[(LTC_IDEA_ROUNDS - i) * 6]);
        d_key[i * 6 + 1] = s_add_inv(e_key[(LTC_IDEA_ROUNDS - i) * 6 + 1]);
        d_key[i * 6 + 2] = s_add_inv(e_key[(LTC_IDEA_ROUNDS - i) * 6 + 2]);
        d_key[i * 6 + 3] = s_mul_inv(e_key[(LTC_IDEA_ROUNDS - i) * 6 + 3]);
        Ok(())
    }

    fn process_block(m_key: &[u16], inout: &mut [u8]) -> CryptoResult<()> {
        let mut t0;
        let mut t1;

        let (mut x0, mut x1, mut x2, mut x3) = {
            let mut buf = &*inout;
            (buf.get_u16(), buf.get_u16(), buf.get_u16(), buf.get_u16())
        };

        for i in 0..LTC_IDEA_ROUNDS {
            MUL!(x0, m_key[i * 6]);
            x1 = x1.wrapping_add(m_key[i * 6 + 1]);
            x2 = x2.wrapping_add(m_key[i * 6 + 2]);
            MUL!(x3, m_key[i * 6 + 3]);
            t0 = x0 ^ x2;
            MUL!(t0, m_key[i * 6 + 4]);
            t1 = t0.wrapping_add(x1 ^ x3);
            MUL!(t1, m_key[i * 6 + 5]);
            t0 = t0.wrapping_add(t1);
            x0 ^= t1;
            x3 ^= t0;
            t0 ^= x1;
            x1 = x2 ^ t1;
            x2 = t0;
        }

        MUL!(x0, m_key[LTC_IDEA_ROUNDS * 6]);
        x2 = x2.wrapping_add(m_key[LTC_IDEA_ROUNDS * 6 + 1]);
        x1 = x1.wrapping_add(m_key[LTC_IDEA_ROUNDS * 6 + 2]);
        MUL!(x3, m_key[LTC_IDEA_ROUNDS * 6 + 3]);

        let mut buf = inout;
        buf.put_u16(x0);
        buf.put_u16(x2);
        buf.put_u16(x1);
        buf.put_u16(x3);

        Ok(())
    }
}

impl BlockCipher for Idea {
    fn block_size(&self) -> usize {
        8
    }

    fn encrypt(&self, inout: &mut [u8]) {
        let _ = Self::process_block(&self.ek, inout);
    }

    fn decrypt(&self, inout: &mut [u8]) {
        let _ = Self::process_block(&self.dk, inout);
    }
}

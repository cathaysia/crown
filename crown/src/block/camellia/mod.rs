//! Module camellia implements the camellia block cipher
//! algorithm as defined in RFC 3713.

#![allow(non_snake_case)]
use bytes::{Buf, BufMut};

use crate::{
    block::{BlockCipher, BlockCipherMarker},
    error::{CryptoError, CryptoResult},
};

mod feistel;
use feistel::F;

#[cfg(test)]
mod tests;

pub struct Camellia {
    pub kw: [u64; 4],
    pub k: [u64; 24],
    pub kl: [u64; 6],
    pub rounds: usize,
}

impl Camellia {
    pub fn new(key: &[u8], num_rounds: Option<usize>) -> CryptoResult<Self> {
        let mut s = Self {
            kw: [0; 4],
            k: [0; 24],
            kl: [0; 6],
            rounds: 0,
        };

        s.init(key, num_rounds.unwrap_or(0))?;

        Ok(s)
    }
}

impl BlockCipherMarker for Camellia {}

impl BlockCipher for Camellia {
    fn block_size(&self) -> usize {
        16
    }

    fn encrypt_block(&self, inout: &mut [u8]) {
        self.encrypt_block(inout).unwrap();
    }

    fn decrypt_block(&self, inout: &mut [u8]) {
        self.decrypt_block(inout).unwrap();
    }
}

const KEY_SIGMA: [u64; 6] = [
    0xa09e667f3bcc908b,
    0xb67ae8584caa73b2,
    0xc6ef372fe94f82be,
    0x54ff53a5f1d36f1c,
    0x10e527fade682d1d,
    0xb05688c2b3e6c1fd,
];

fn rot_128(in_0: &[u8], count: u32, out: &mut [u8]) {
    let mut x: u32;
    let w: u32 = count >> 3;
    let b: u32 = count & 7_u32;
    x = 0_u32;
    while x < 16_u32 {
        out[x as usize] = (((in_0[(x.wrapping_add(w) & 15_u32) as usize] as i32) << b)
            | (in_0[(x.wrapping_add(w).wrapping_add(1_u32) & 15_u32) as usize] as i32
                >> 8_u32.wrapping_sub(b))) as u8;
        x = x.wrapping_add(1);
    }
}

impl Camellia {
    fn init(&mut self, key: &[u8], num_rounds: usize) -> CryptoResult<()> {
        let mut T: [u8; 48] = [0; 48];
        let mut kA: [u8; 16] = [0; 16];
        let mut kB: [u8; 16] = [0; 16];
        let mut kR: [u8; 16] = [0; 16];
        let mut kL: [u8; 16] = [0; 16];
        let mut x: i32;
        let mut A: u64;
        let mut B: u64;

        let keylen = key.len();

        if keylen != 16 && keylen != 24 && keylen != 32 {
            return Err(CryptoError::InvalidKeySize {
                expected: "16 | 24 | 32",
                actual: keylen,
            });
        }
        self.rounds = if keylen == 16 { 18 } else { 24 };
        if num_rounds != 0 && num_rounds != self.rounds {
            return Err(CryptoError::InvalidRound(num_rounds));
        }
        if keylen == 16 {
            for x in 0..16 {
                T[x] = key[x];
                T[x + 16] = 0;
            }
        } else if keylen == 24 {
            T[..24].copy_from_slice(&key[..24]);
            for x in 24..32 {
                T[x] = key[x - 8] ^ 0xff;
            }
        } else {
            T[..32].copy_from_slice(&key[..32]);
        }
        kL[..16].copy_from_slice(&T[..16]);
        kR[..16].copy_from_slice(&T[16..32]);
        for x in 32..48 {
            T[x] = (T[x - 32] as i32 ^ T[x - 16] as i32) as u8;
        }

        A = (&T[32..]).get_u64();
        B = (&T[40..]).get_u64();
        B ^= F(A ^ KEY_SIGMA[0]);
        A ^= F(B ^ KEY_SIGMA[1]);
        (&mut T[32..]).put_u64(A);
        (&mut T[40..]).put_u64(B);
        x = 0;
        while x < 16 {
            T[(x + 32) as usize] = (T[(x + 32) as usize] as i32 ^ kL[x as usize] as i32) as u8;
            x += 1;
        }
        A = (&T[32..]).get_u64();
        B = (&T[40..]).get_u64();
        B ^= F(A ^ KEY_SIGMA[2]);
        A ^= F(B ^ KEY_SIGMA[3]);
        (&mut T[32..]).put_u64(A);
        (&mut T[40..]).put_u64(B);
        x = 0;
        while x < 16 {
            kA[x as usize] = T[(x + 32) as usize];
            x += 1;
        }
        x = 0;
        while x < 16 {
            T[(x + 32) as usize] = (T[(x + 32) as usize] as i32 ^ kR[x as usize] as i32) as u8;
            x += 1;
        }
        if keylen == 16 {
            self.kw[0] = (&kL[..]).get_u64();
            self.kw[1] = (&kL[8..]).get_u64();

            self.k[0] = (&kA[..]).get_u64();
            self.k[1] = (&kA[8..]).get_u64();

            rot_128(&kL, 15_u32, &mut T[32..]);
            self.k[2] = (&T[32..]).get_u64();
            self.k[3] = (&T[40..]).get_u64();

            rot_128(&kA, 15_u32, &mut T[32..]);
            self.k[4] = (&T[32..]).get_u64();
            self.k[5] = (&T[40..]).get_u64();

            rot_128(&kA, 30_u32, &mut T[32..]);
            self.kl[0] = (&T[32..]).get_u64();
            self.kl[1] = (&T[40..]).get_u64();

            rot_128(&kL, 45_u32, &mut T[32..]);
            self.k[6] = (&T[32..]).get_u64();
            self.k[7] = (&T[40..]).get_u64();

            rot_128(&kA, 45_u32, &mut T[32..]);
            self.k[8] = (&T[32..]).get_u64();
            rot_128(&kL, 60_u32, &mut T[32..]);
            self.k[9] = (&T[40..]).get_u64();

            rot_128(&kA, 60_u32, &mut T[32..]);
            self.k[10] = (&T[32..]).get_u64();
            self.k[11] = (&T[40..]).get_u64();

            rot_128(&kL, 77_u32, &mut T[32..]);
            self.kl[2] = (&T[32..]).get_u64();
            self.kl[3] = (&T[40..]).get_u64();

            rot_128(&kL, 94_u32, &mut T[32..]);
            self.k[12] = (&T[32..]).get_u64();
            self.k[13] = (&T[40..]).get_u64();

            rot_128(&kA, 94_u32, &mut T[32..]);
            self.k[14] = (&T[32..]).get_u64();
            self.k[15] = (&T[40..]).get_u64();

            rot_128(&kL, 111_u32, &mut T[32..]);
            self.k[16] = (&T[32..]).get_u64();
            self.k[17] = (&T[40..]).get_u64();

            rot_128(&kA, 111_u32, &mut T[32..]);
            self.kw[2] = (&T[32..]).get_u64();
            self.kw[3] = (&T[40..]).get_u64();
        } else {
            A = (&T[32..]).get_u64();
            B = (&T[40..]).get_u64();
            B ^= F(A ^ KEY_SIGMA[4]);
            A ^= F(B ^ KEY_SIGMA[5]);
            (&mut T[32..]).put_u64(A);
            (&mut T[40..]).put_u64(B);

            kB[..16].copy_from_slice(&T[32..32 + 16]);
            self.kw[0] = (&kL[..]).get_u64();
            self.kw[1] = (&kL[8..]).get_u64();

            self.k[0] = (&kB[..]).get_u64();
            self.k[1] = (&kB[8..]).get_u64();

            rot_128(&kR, 15_u32, &mut T[32..]);
            self.k[2] = (&T[32..]).get_u64();
            self.k[3] = (&T[40..]).get_u64();

            rot_128(&kA, 15_u32, &mut T[32..]);
            self.k[4] = (&T[32..]).get_u64();
            self.k[5] = (&T[40..]).get_u64();

            rot_128(&kR, 30_u32, &mut T[32..]);
            self.kl[0] = (&T[32..]).get_u64();
            self.kl[1] = (&T[40..]).get_u64();

            rot_128(&kB, 30_u32, &mut T[32..]);
            self.k[6] = (&T[32..]).get_u64();
            self.k[7] = (&T[40..]).get_u64();

            rot_128(&kL, 45_u32, &mut T[32..]);
            self.k[8] = (&T[32..]).get_u64();
            self.k[9] = (&T[40..]).get_u64();

            rot_128(&kA, 45_u32, &mut T[32..]);
            self.k[10] = (&T[32..]).get_u64();
            self.k[11] = (&T[40..]).get_u64();

            rot_128(&kL, 60_u32, &mut T[32..]);
            self.kl[2] = (&T[32..]).get_u64();
            self.kl[3] = (&T[40..]).get_u64();

            rot_128(&kR, 60_u32, &mut T[32..]);
            self.k[12] = (&T[32..]).get_u64();
            self.k[13] = (&T[40..]).get_u64();

            rot_128(&kB, 60_u32, &mut T[32..]);
            self.k[14] = (&T[32..]).get_u64();
            self.k[15] = (&T[40..]).get_u64();

            rot_128(&kL, 77_u32, &mut T[32..]);
            self.k[16] = (&T[32..]).get_u64();
            self.k[17] = (&T[40..]).get_u64();

            rot_128(&kA, 77_u32, &mut T[32..]);
            self.kl[4] = (&T[32..]).get_u64();
            self.kl[5] = (&T[40..]).get_u64();

            rot_128(&kR, 94_u32, &mut T[32..]);
            self.k[18] = (&T[32..]).get_u64();
            self.k[19] = (&T[40..]).get_u64();

            rot_128(&kA, 94_u32, &mut T[32..]);
            self.k[20] = (&T[32..]).get_u64();
            self.k[21] = (&T[40..]).get_u64();

            rot_128(&kL, 111_u32, &mut T[32..]);
            self.k[22] = (&T[32..]).get_u64();
            self.k[23] = (&T[40..]).get_u64();

            rot_128(&kB, 111_u32, &mut T[32..]);
            self.kw[2] = (&T[32..]).get_u64();
            self.kw[3] = (&T[40..]).get_u64();
        }
        Ok(())
    }

    pub fn encrypt_block(&self, inout: &mut [u8]) -> CryptoResult<()> {
        let mut L: u64;
        let mut R: u64;
        let mut a: u32;
        let mut b: u32;
        {
            let mut pt = &*inout;
            L = pt.get_u64();
            R = pt.get_u64();
        }

        L ^= self.kw[0];
        R ^= self.kw[1];
        R ^= F(L ^ self.k[0]);
        L ^= F(R ^ self.k[1]);
        R ^= F(L ^ self.k[2]);
        L ^= F(R ^ self.k[3]);
        R ^= F(L ^ self.k[4]);
        L ^= F(R ^ self.k[5]);
        a = (L >> 32) as u32;
        b = (L & 0xffffffff) as u32;
        b ^= (a & (self.kl[0] >> 32) as u32).rotate_left(1);
        a = (a as u64 ^ (b as u64 | self.kl[0] & 0xffffffff_u32 as u64)) as u32;
        L = ((a as u64) << 32) | b as u64;
        a = (R >> 32) as u32;
        b = (R & 0xffffffff) as u32;
        a = (a as u64 ^ (b as u64 | self.kl[1] & 0xffffffff_u32 as u64)) as u32;
        b ^= (a & (self.kl[1] >> 32) as u32).rotate_left(1);
        R = ((a as u64) << 32) | b as u64;
        R ^= F(L ^ self.k[6]);
        L ^= F(R ^ self.k[7]);
        R ^= F(L ^ self.k[8]);
        L ^= F(R ^ self.k[9]);
        R ^= F(L ^ self.k[10]);
        L ^= F(R ^ self.k[11]);
        a = (L >> 32) as u32;
        b = (L & 0xffffffff) as u32;
        b ^= (a & (self.kl[2] >> 32) as u32).rotate_left(1);
        a = (a as u64 ^ (b as u64 | self.kl[2] & 0xffffffff_u32 as u64)) as u32;
        L = ((a as u64) << 32) | b as u64;
        a = (R >> 32) as u32;
        b = (R & 0xffffffff) as u32;
        a = (a as u64 ^ (b as u64 | self.kl[3] & 0xffffffff_u32 as u64)) as u32;
        b ^= (a & (self.kl[3] >> 32) as u32).rotate_left(1);
        R = ((a as u64) << 32) | b as u64;
        R ^= F(L ^ self.k[12]);
        L ^= F(R ^ self.k[13]);
        R ^= F(L ^ self.k[14]);
        L ^= F(R ^ self.k[15]);
        R ^= F(L ^ self.k[16]);
        L ^= F(R ^ self.k[17]);
        if self.rounds == 24 {
            a = (L >> 32) as u32;
            b = (L & 0xffffffff) as u32;
            b ^= (a & (self.kl[4] >> 32) as u32).rotate_left(1);
            a = (a as u64 ^ (b as u64 | self.kl[4] & 0xffffffff_u32 as u64)) as u32;
            L = ((a as u64) << 32) | b as u64;
            a = (R >> 32) as u32;
            b = (R & 0xffffffff) as u32;
            a = (a as u64 ^ (b as u64 | self.kl[5] & 0xffffffff_u32 as u64)) as u32;
            b ^= (a & (self.kl[5] >> 32) as u32).rotate_left(1);
            R = ((a as u64) << 32) | b as u64;
            R ^= F(L ^ self.k[18]);
            L ^= F(R ^ self.k[19]);
            R ^= F(L ^ self.k[20]);
            L ^= F(R ^ self.k[21]);
            R ^= F(L ^ self.k[22]);
            L ^= F(R ^ self.k[23]);
        }
        L ^= self.kw[3];
        R ^= self.kw[2];

        {
            let mut inout = inout;
            inout.put_u64(R);
            inout.put_u64(L);
        }

        Ok(())
    }

    pub fn decrypt_block(&self, inout: &mut [u8]) -> CryptoResult<()> {
        let mut L: u64;
        let mut R: u64;
        let mut a: u32;
        let mut b: u32;
        {
            let mut pt = &*inout;
            R = pt.get_u64();
            L = pt.get_u64();
        }

        L ^= self.kw[3];
        R ^= self.kw[2];
        if self.rounds == 24 {
            L ^= F(R ^ self.k[23]);
            R ^= F(L ^ self.k[22]);
            L ^= F(R ^ self.k[21]);
            R ^= F(L ^ self.k[20]);
            L ^= F(R ^ self.k[19]);
            R ^= F(L ^ self.k[18]);
            a = (L >> 32) as u32;
            b = (L & 0xffffffff) as u32;
            a = (a as u64 ^ (b as u64 | self.kl[4] & 0xffffffff_u32 as u64)) as u32;
            b ^= (a & (self.kl[4] >> 32) as u32).rotate_left(1);
            L = ((a as u64) << 32) | b as u64;
            a = (R >> 32) as u32;
            b = (R & 0xffffffff) as u32;
            b ^= (a & (self.kl[5] >> 32) as u32).rotate_left(1);
            a = (a as u64 ^ (b as u64 | self.kl[5] & 0xffffffff_u32 as u64)) as u32;
            R = ((a as u64) << 32) | b as u64;
        }
        L ^= F(R ^ self.k[17]);
        R ^= F(L ^ self.k[16]);
        L ^= F(R ^ self.k[15]);
        R ^= F(L ^ self.k[14]);
        L ^= F(R ^ self.k[13]);
        R ^= F(L ^ self.k[12]);
        a = (L >> 32) as u32;
        b = (L & 0xffffffff) as u32;
        a = (a as u64 ^ (b as u64 | self.kl[2] & 0xffffffff_u32 as u64)) as u32;
        b ^= (a & (self.kl[2] >> 32) as u32).rotate_left(1);
        L = ((a as u64) << 32) | b as u64;
        a = (R >> 32) as u32;
        b = (R & 0xffffffff) as u32;
        b ^= (a & (self.kl[3] >> 32) as u32).rotate_left(1);
        a = (a as u64 ^ (b as u64 | self.kl[3] & 0xffffffff_u32 as u64)) as u32;
        R = ((a as u64) << 32) | b as u64;
        L ^= F(R ^ self.k[11]);
        R ^= F(L ^ self.k[10]);
        L ^= F(R ^ self.k[9]);
        R ^= F(L ^ self.k[8]);
        L ^= F(R ^ self.k[7]);
        R ^= F(L ^ self.k[6]);
        a = (L >> 32) as u32;
        b = (L & 0xffffffff) as u32;
        a = (a as u64 ^ (b as u64 | self.kl[0] & 0xffffffff_u32 as u64)) as u32;
        b ^= (a & (self.kl[0] >> 32) as u32).rotate_left(1);
        L = ((a as u64) << 32) | b as u64;
        a = (R >> 32) as u32;
        b = (R & 0xffffffff) as u32;
        b ^= (a & (self.kl[1] >> 32) as u32).rotate_left(1);
        a = (a as u64 ^ (b as u64 | self.kl[1] & 0xffffffff_u32 as u64)) as u32;
        R = ((a as u64) << 32) | b as u64;
        L ^= F(R ^ self.k[5]);
        R ^= F(L ^ self.k[4]);
        L ^= F(R ^ self.k[3]);
        R ^= F(L ^ self.k[2]);
        L ^= F(R ^ self.k[1]);
        R ^= F(L ^ self.k[0]);
        R ^= self.kw[1];
        L ^= self.kw[0];

        let mut inout = inout;
        inout.put_u64(L);
        inout.put_u64(R);

        Ok(())
    }
}

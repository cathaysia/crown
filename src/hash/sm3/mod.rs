use crate::{
    core::CoreWrite,
    error::CryptoResult,
    hash::{Hash, HashUser},
    mac::hmac::Marshalable,
};
use bytes::{Buf, BufMut};

#[cfg(test)]
mod test;

const SM3_A: u32 = 0x7380166f;
const SM3_B: u32 = 0x4914b2b9;
const SM3_C: u32 = 0x172442d7;
const SM3_D: u32 = 0xda8a0600;
const SM3_E: u32 = 0xa96f30bc;
const SM3_F: u32 = 0x163138aa;
const SM3_G: u32 = 0xe38dee4d;
const SM3_H: u32 = 0xb0fb0e4e;

#[derive(Clone)]
pub struct Sm3 {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
    f: u32,
    g: u32,
    h: u32,
    nl: u32,
    nh: u32,
    data: [u32; Self::SM3_LBLOCK],
    num: usize,
}

macro_rules! ROTATE {
    ($a:expr, $n:expr) => {
        ($a).rotate_left($n)
    };
}

macro_rules! P0 {
    ($x:expr) => {
        $x ^ ROTATE!($x, 9) ^ ROTATE!($x, 17)
    };
}

macro_rules! P1 {
    ($x:expr) => {
        $x ^ ROTATE!($x, 15) ^ ROTATE!($x, 23)
    };
}

macro_rules! FF0 {
    ($x:expr, $y:expr, $z:expr) => {
        $x ^ $y ^ $z
    };
}

macro_rules! GG0 {
    ($x:expr, $y:expr, $z:expr) => {
        $x ^ $y ^ $z
    };
}

macro_rules! FF1 {
    ($x:expr, $y:expr, $z:expr) => {
        ($x & $y) | (($x | $y) & $z)
    };
}

macro_rules! GG1 {
    ($x:expr, $y:expr, $z:expr) => {
        $z ^ ($x & ($y ^ $z))
    };
}

macro_rules! EXPAND {
    ($W0:expr, $W7:expr, $W13:expr, $W3:expr, $W10:expr) => {
        P1!($W0 ^ $W7 ^ ROTATE!($W13, 15)) ^ ROTATE!($W3, 7) ^ $W10
    };
}

macro_rules! RND {
    ($A:expr, $B:expr, $C:expr, $D:expr, $E:expr, $F:expr, $G:expr, $H:expr, $TJ:expr, $Wi:expr, $Wj:expr, $FF:ident, $GG:ident) => {{
        let a12 = ROTATE!($A, 12);
        let a12_sm = a12.wrapping_add($E).wrapping_add($TJ);
        let ss1 = ROTATE!(a12_sm, 7);
        let tt1 = $FF!($A, $B, $C)
            .wrapping_add($D)
            .wrapping_add(ss1 ^ a12)
            .wrapping_add($Wj);
        let tt2 = $GG!($E, $F, $G)
            .wrapping_add($H)
            .wrapping_add(ss1)
            .wrapping_add($Wi);
        $B = ROTATE!($B, 9);
        $D = tt1;
        $F = ROTATE!($F, 19);
        $H = P0!(tt2);
    }};
}

macro_rules! R1 {
    ($A:expr, $B:expr, $C:expr, $D:expr, $E:expr, $F:expr, $G:expr, $H:expr, $TJ:expr, $Wi:expr, $Wj:expr) => {
        RND!($A, $B, $C, $D, $E, $F, $G, $H, $TJ, $Wi, $Wj, FF0, GG0)
    };
}

macro_rules! R2 {
    ($A:expr, $B:expr, $C:expr, $D:expr, $E:expr, $F:expr, $G:expr, $H:expr, $TJ:expr, $Wi:expr, $Wj:expr) => {
        RND!($A, $B, $C, $D, $E, $F, $G, $H, $TJ, $Wi, $Wj, FF1, GG1)
    };
}

impl Marshalable for Sm3 {
    fn marshal_size(&self) -> usize {
        // A, B, C, D, E, F, G, H (8 * 4 bytes) + Nl, Nh (2 * 4 bytes) + data (16 * 4 bytes) + num (8 bytes)
        32 + 8 + 64 + 8
    }

    fn marshal_into(&self, mut out: &mut [u8]) -> CryptoResult<usize> {
        if out.len() < self.marshal_size() {
            return Err(crate::error::CryptoError::InvalidLength);
        }

        out.put_u32(self.a);
        out.put_u32(self.b);
        out.put_u32(self.c);
        out.put_u32(self.d);
        out.put_u32(self.e);
        out.put_u32(self.f);
        out.put_u32(self.g);
        out.put_u32(self.h);

        out.put_u32(self.nl);
        out.put_u32(self.nh);

        for &word in &self.data {
            out.put_u32(word);
        }

        out.put_u64(self.num as u64);

        Ok(self.marshal_size())
    }

    fn unmarshal_binary(&mut self, mut data: &[u8]) -> CryptoResult<()> {
        if data.len() < self.marshal_size() {
            return Err(crate::error::CryptoError::InvalidLength);
        }

        self.a = data.get_u32();
        self.b = data.get_u32();
        self.c = data.get_u32();
        self.d = data.get_u32();
        self.e = data.get_u32();
        self.f = data.get_u32();
        self.g = data.get_u32();
        self.h = data.get_u32();

        self.nl = data.get_u32();
        self.nh = data.get_u32();

        for i in 0..Self::SM3_LBLOCK {
            self.data[i] = data.get_u32();
        }

        self.num = data.get_u64() as usize;

        Ok(())
    }
}

impl Sm3 {
    const SM3_CBLOCK: usize = 64;
    const SM3_LBLOCK: usize = (Self::SM3_CBLOCK / 4);

    pub fn block_data_order(&mut self, mut data: &[u8], num_blocks: usize) {
        for _ in 0..num_blocks {
            let mut a = self.a;
            let mut b = self.b;
            let mut c = self.c;
            let mut d = self.d;
            let mut e = self.e;
            let mut f = self.f;
            let mut g = self.g;
            let mut h = self.h;

            let mut w = [0u32; 16];
            (0..16).for_each(|i| {
                w[i] = data.get_u32();
            });

            let mut w00 = w[0];
            let mut w01 = w[1];
            let mut w02 = w[2];
            let mut w03 = w[3];
            let mut w04 = w[4];
            let mut w05 = w[5];
            let mut w06 = w[6];
            let mut w07 = w[7];
            let mut w08 = w[8];
            let mut w09 = w[9];
            let mut w10 = w[10];
            let mut w11 = w[11];
            let mut w12 = w[12];
            let mut w13 = w[13];
            let mut w14 = w[14];
            let mut w15 = w[15];

            R1!(a, b, c, d, e, f, g, h, 0x79CC4519, w00, w00 ^ w04);
            w00 = EXPAND!(w00, w07, w13, w03, w10);
            R1!(d, a, b, c, h, e, f, g, 0xF3988A32, w01, w01 ^ w05);
            w01 = EXPAND!(w01, w08, w14, w04, w11);
            R1!(c, d, a, b, g, h, e, f, 0xE7311465, w02, w02 ^ w06);
            w02 = EXPAND!(w02, w09, w15, w05, w12);
            R1!(b, c, d, a, f, g, h, e, 0xCE6228CB, w03, w03 ^ w07);
            w03 = EXPAND!(w03, w10, w00, w06, w13);
            R1!(a, b, c, d, e, f, g, h, 0x9CC45197, w04, w04 ^ w08);
            w04 = EXPAND!(w04, w11, w01, w07, w14);
            R1!(d, a, b, c, h, e, f, g, 0x3988A32F, w05, w05 ^ w09);
            w05 = EXPAND!(w05, w12, w02, w08, w15);
            R1!(c, d, a, b, g, h, e, f, 0x7311465E, w06, w06 ^ w10);
            w06 = EXPAND!(w06, w13, w03, w09, w00);
            R1!(b, c, d, a, f, g, h, e, 0xE6228CBC, w07, w07 ^ w11);
            w07 = EXPAND!(w07, w14, w04, w10, w01);
            R1!(a, b, c, d, e, f, g, h, 0xCC451979, w08, w08 ^ w12);
            w08 = EXPAND!(w08, w15, w05, w11, w02);
            R1!(d, a, b, c, h, e, f, g, 0x988A32F3, w09, w09 ^ w13);
            w09 = EXPAND!(w09, w00, w06, w12, w03);
            R1!(c, d, a, b, g, h, e, f, 0x311465E7, w10, w10 ^ w14);
            w10 = EXPAND!(w10, w01, w07, w13, w04);
            R1!(b, c, d, a, f, g, h, e, 0x6228CBCE, w11, w11 ^ w15);
            w11 = EXPAND!(w11, w02, w08, w14, w05);
            R1!(a, b, c, d, e, f, g, h, 0xC451979C, w12, w12 ^ w00);
            w12 = EXPAND!(w12, w03, w09, w15, w06);
            R1!(d, a, b, c, h, e, f, g, 0x88A32F39, w13, w13 ^ w01);
            w13 = EXPAND!(w13, w04, w10, w00, w07);
            R1!(c, d, a, b, g, h, e, f, 0x11465E73, w14, w14 ^ w02);
            w14 = EXPAND!(w14, w05, w11, w01, w08);
            R1!(b, c, d, a, f, g, h, e, 0x228CBCE6, w15, w15 ^ w03);
            w15 = EXPAND!(w15, w06, w12, w02, w09);

            R2!(a, b, c, d, e, f, g, h, 0x9D8A7A87, w00, w00 ^ w04);
            w00 = EXPAND!(w00, w07, w13, w03, w10);
            R2!(d, a, b, c, h, e, f, g, 0x3B14F50F, w01, w01 ^ w05);
            w01 = EXPAND!(w01, w08, w14, w04, w11);
            R2!(c, d, a, b, g, h, e, f, 0x7629EA1E, w02, w02 ^ w06);
            w02 = EXPAND!(w02, w09, w15, w05, w12);
            R2!(b, c, d, a, f, g, h, e, 0xEC53D43C, w03, w03 ^ w07);
            w03 = EXPAND!(w03, w10, w00, w06, w13);
            R2!(a, b, c, d, e, f, g, h, 0xD8A7A879, w04, w04 ^ w08);
            w04 = EXPAND!(w04, w11, w01, w07, w14);
            R2!(d, a, b, c, h, e, f, g, 0xB14F50F3, w05, w05 ^ w09);
            w05 = EXPAND!(w05, w12, w02, w08, w15);
            R2!(c, d, a, b, g, h, e, f, 0x629EA1E7, w06, w06 ^ w10);
            w06 = EXPAND!(w06, w13, w03, w09, w00);
            R2!(b, c, d, a, f, g, h, e, 0xC53D43CE, w07, w07 ^ w11);
            w07 = EXPAND!(w07, w14, w04, w10, w01);
            R2!(a, b, c, d, e, f, g, h, 0x8A7A879D, w08, w08 ^ w12);
            w08 = EXPAND!(w08, w15, w05, w11, w02);
            R2!(d, a, b, c, h, e, f, g, 0x14F50F3B, w09, w09 ^ w13);
            w09 = EXPAND!(w09, w00, w06, w12, w03);
            R2!(c, d, a, b, g, h, e, f, 0x29EA1E76, w10, w10 ^ w14);
            w10 = EXPAND!(w10, w01, w07, w13, w04);
            R2!(b, c, d, a, f, g, h, e, 0x53D43CEC, w11, w11 ^ w15);
            w11 = EXPAND!(w11, w02, w08, w14, w05);
            R2!(a, b, c, d, e, f, g, h, 0xA7A879D8, w12, w12 ^ w00);
            w12 = EXPAND!(w12, w03, w09, w15, w06);
            R2!(d, a, b, c, h, e, f, g, 0x4F50F3B1, w13, w13 ^ w01);
            w13 = EXPAND!(w13, w04, w10, w00, w07);
            R2!(c, d, a, b, g, h, e, f, 0x9EA1E762, w14, w14 ^ w02);
            w14 = EXPAND!(w14, w05, w11, w01, w08);
            R2!(b, c, d, a, f, g, h, e, 0x3D43CEC5, w15, w15 ^ w03);
            w15 = EXPAND!(w15, w06, w12, w02, w09);
            R2!(a, b, c, d, e, f, g, h, 0x7A879D8A, w00, w00 ^ w04);
            w00 = EXPAND!(w00, w07, w13, w03, w10);
            R2!(d, a, b, c, h, e, f, g, 0xF50F3B14, w01, w01 ^ w05);
            w01 = EXPAND!(w01, w08, w14, w04, w11);
            R2!(c, d, a, b, g, h, e, f, 0xEA1E7629, w02, w02 ^ w06);
            w02 = EXPAND!(w02, w09, w15, w05, w12);
            R2!(b, c, d, a, f, g, h, e, 0xD43CEC53, w03, w03 ^ w07);
            w03 = EXPAND!(w03, w10, w00, w06, w13);
            R2!(a, b, c, d, e, f, g, h, 0xA879D8A7, w04, w04 ^ w08);
            w04 = EXPAND!(w04, w11, w01, w07, w14);
            R2!(d, a, b, c, h, e, f, g, 0x50F3B14F, w05, w05 ^ w09);
            w05 = EXPAND!(w05, w12, w02, w08, w15);
            R2!(c, d, a, b, g, h, e, f, 0xA1E7629E, w06, w06 ^ w10);
            w06 = EXPAND!(w06, w13, w03, w09, w00);
            R2!(b, c, d, a, f, g, h, e, 0x43CEC53D, w07, w07 ^ w11);
            w07 = EXPAND!(w07, w14, w04, w10, w01);
            R2!(a, b, c, d, e, f, g, h, 0x879D8A7A, w08, w08 ^ w12);
            w08 = EXPAND!(w08, w15, w05, w11, w02);
            R2!(d, a, b, c, h, e, f, g, 0x0F3B14F5, w09, w09 ^ w13);
            w09 = EXPAND!(w09, w00, w06, w12, w03);
            R2!(c, d, a, b, g, h, e, f, 0x1E7629EA, w10, w10 ^ w14);
            w10 = EXPAND!(w10, w01, w07, w13, w04);
            R2!(b, c, d, a, f, g, h, e, 0x3CEC53D4, w11, w11 ^ w15);
            w11 = EXPAND!(w11, w02, w08, w14, w05);
            R2!(a, b, c, d, e, f, g, h, 0x79D8A7A8, w12, w12 ^ w00);
            w12 = EXPAND!(w12, w03, w09, w15, w06);
            R2!(d, a, b, c, h, e, f, g, 0xF3B14F50, w13, w13 ^ w01);
            w13 = EXPAND!(w13, w04, w10, w00, w07);
            R2!(c, d, a, b, g, h, e, f, 0xE7629EA1, w14, w14 ^ w02);
            w14 = EXPAND!(w14, w05, w11, w01, w08);
            R2!(b, c, d, a, f, g, h, e, 0xCEC53D43, w15, w15 ^ w03);
            w15 = EXPAND!(w15, w06, w12, w02, w09);
            R2!(a, b, c, d, e, f, g, h, 0x9D8A7A87, w00, w00 ^ w04);
            w00 = EXPAND!(w00, w07, w13, w03, w10);
            R2!(d, a, b, c, h, e, f, g, 0x3B14F50F, w01, w01 ^ w05);
            w01 = EXPAND!(w01, w08, w14, w04, w11);
            R2!(c, d, a, b, g, h, e, f, 0x7629EA1E, w02, w02 ^ w06);
            w02 = EXPAND!(w02, w09, w15, w05, w12);
            R2!(b, c, d, a, f, g, h, e, 0xEC53D43C, w03, w03 ^ w07);
            w03 = EXPAND!(w03, w10, w00, w06, w13);
            R2!(a, b, c, d, e, f, g, h, 0xD8A7A879, w04, w04 ^ w08);
            R2!(d, a, b, c, h, e, f, g, 0xB14F50F3, w05, w05 ^ w09);
            R2!(c, d, a, b, g, h, e, f, 0x629EA1E7, w06, w06 ^ w10);
            R2!(b, c, d, a, f, g, h, e, 0xC53D43CE, w07, w07 ^ w11);
            R2!(a, b, c, d, e, f, g, h, 0x8A7A879D, w08, w08 ^ w12);
            R2!(d, a, b, c, h, e, f, g, 0x14F50F3B, w09, w09 ^ w13);
            R2!(c, d, a, b, g, h, e, f, 0x29EA1E76, w10, w10 ^ w14);
            R2!(b, c, d, a, f, g, h, e, 0x53D43CEC, w11, w11 ^ w15);
            R2!(a, b, c, d, e, f, g, h, 0xA7A879D8, w12, w12 ^ w00);
            R2!(d, a, b, c, h, e, f, g, 0x4F50F3B1, w13, w13 ^ w01);
            R2!(c, d, a, b, g, h, e, f, 0x9EA1E762, w14, w14 ^ w02);
            R2!(b, c, d, a, f, g, h, e, 0x3D43CEC5, w15, w15 ^ w03);

            self.a ^= a;
            self.b ^= b;
            self.c ^= c;
            self.d ^= d;
            self.e ^= e;
            self.f ^= f;
            self.g ^= g;
            self.h ^= h;
        }
    }

    pub fn finalize(&self) -> [u8; 32] {
        let mut ret = [0u8; 32];
        {
            let mut ret = ret.as_mut_slice();
            ret.put_u32(self.a);
            ret.put_u32(self.b);
            ret.put_u32(self.c);
            ret.put_u32(self.d);
            ret.put_u32(self.e);
            ret.put_u32(self.f);
            ret.put_u32(self.g);
            ret.put_u32(self.h);
        }
        ret
    }

    pub fn transform(&mut self, data: &[u8]) {
        self.block_data_order(data, 1);
    }
}

impl HashUser for Sm3 {
    fn reset(&mut self) {
        *self = new_sm3();
    }

    fn size(&self) -> usize {
        32
    }

    fn block_size(&self) -> usize {
        256
    }
}

impl CoreWrite for Sm3 {
    fn write(&mut self, buf: &[u8]) -> CryptoResult<usize> {
        let len = buf.len();
        let mut input_offset = 0;
        let mut remaining = len;

        let old_nl = self.nl;
        self.nl = self.nl.wrapping_add((len as u32) << 3);
        if self.nl < old_nl {
            self.nh = self.nh.wrapping_add(1);
        }
        self.nh = self.nh.wrapping_add((len as u32) >> 29);

        if self.num != 0 {
            let space = Self::SM3_CBLOCK - self.num;
            if remaining >= space {
                let mut temp_data = vec![0u8; Self::SM3_CBLOCK];

                (0..self.num).for_each(|i| {
                    temp_data[i] = ((self.data[i / 4] >> (8 * (3 - (i % 4)))) & 0xff) as u8;
                });

                temp_data[self.num..Self::SM3_CBLOCK]
                    .copy_from_slice(&buf[input_offset..input_offset + space]);

                self.transform(&temp_data);

                input_offset += space;
                remaining -= space;
                self.num = 0;
                self.data = [0; Self::SM3_LBLOCK];
            } else {
                for i in 0..remaining {
                    let byte_idx = (self.num + i) / 4;
                    let bit_shift = 8 * (3 - ((self.num + i) % 4));
                    self.data[byte_idx] |= (buf[input_offset + i] as u32) << bit_shift;
                }
                self.num += remaining;
                return Ok(len);
            }
        }

        while remaining >= Self::SM3_CBLOCK {
            self.transform(&buf[input_offset..input_offset + Self::SM3_CBLOCK]);
            input_offset += Self::SM3_CBLOCK;
            remaining -= Self::SM3_CBLOCK;
        }

        if remaining > 0 {
            self.data = [0; Self::SM3_LBLOCK];
            for i in 0..remaining {
                let byte_idx = i / 4;
                let bit_shift = 8 * (3 - (i % 4));
                self.data[byte_idx] |= (buf[input_offset + i] as u32) << bit_shift;
            }
            self.num = remaining;
        }

        Ok(len)
    }

    fn flush(&mut self) -> CryptoResult<()> {
        Ok(())
    }
}

impl Hash<32> for Sm3 {
    fn sum(&mut self) -> [u8; 32] {
        let mut copy = self.clone();
        copy.finalize_with_padding();
        copy.finalize()
    }
}

impl Sm3 {
    fn finalize_with_padding(&mut self) {
        let mut temp_data = [0u8; Self::SM3_CBLOCK * 2];

        (0..self.num).for_each(|i| {
            temp_data[i] = ((self.data[i / 4] >> (8 * (3 - (i % 4)))) & 0xff) as u8;
        });
        let mut offset = self.num;

        temp_data[offset] = 0x80;
        offset += 1;

        let msg_bit_len = ((self.nh as u64) << 32) | (self.nl as u64);

        if offset > Self::SM3_CBLOCK - 8 {
            while offset < Self::SM3_CBLOCK {
                temp_data[offset] = 0;
                offset += 1;
            }
            self.transform(&temp_data[0..Self::SM3_CBLOCK]);

            (0..Self::SM3_CBLOCK).for_each(|i| {
                temp_data[i] = 0;
            });
            offset = 0;
        }

        while offset < Self::SM3_CBLOCK - 8 {
            temp_data[offset] = 0;
            offset += 1;
        }

        let len_bytes = msg_bit_len.to_be_bytes();
        temp_data[offset..offset + 8].copy_from_slice(&len_bytes);

        self.transform(&temp_data[0..Self::SM3_CBLOCK]);
    }
}

pub fn new_sm3() -> Sm3 {
    Sm3 {
        a: SM3_A,
        b: SM3_B,
        c: SM3_C,
        d: SM3_D,
        e: SM3_E,
        f: SM3_F,
        g: SM3_G,
        h: SM3_H,
        nl: 0,
        nh: 0,
        data: [0; Sm3::SM3_LBLOCK],
        num: 0,
    }
}

pub fn sum_sm3(input: &[u8]) -> [u8; 32] {
    let mut x = new_sm3();
    x.write_all(input).unwrap();
    x.sum()
}

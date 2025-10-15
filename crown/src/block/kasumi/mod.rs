#[cfg(test)]
mod tests;

use bytes::{Buf, BufMut};

use crate::{
    aead::ocb3::Ocb3Marker,
    block::BlockCipher,
    error::{CryptoError, CryptoResult},
};

pub struct Kasumi {
    pub kli1: [u32; 8],
    pub kli2: [u32; 8],
    pub koi1: [u32; 8],
    pub koi2: [u32; 8],
    pub koi3: [u32; 8],
    pub kii1: [u32; 8],
    pub kii2: [u32; 8],
    pub kii3: [u32; 8],
}

impl super::BlockCipherMarker for Kasumi {}
impl Ocb3Marker for Kasumi {}

fn kasumi_fi(in_0: u32, subkey: u32) -> u32 {
    let mut nine: u32;
    let mut seven: u32;
    static S7: [u32; 128] = [
        54, 50, 62, 56, 22, 34, 94, 96, 38, 6, 63, 93, 2, 18, 123, 33, 55, 113, 39, 114, 21, 67,
        65, 12, 47, 73, 46, 27, 25, 111, 124, 81, 53, 9, 121, 79, 52, 60, 58, 48, 101, 127, 40,
        120, 104, 70, 71, 43, 20, 122, 72, 61, 23, 109, 13, 100, 77, 1, 16, 7, 82, 10, 105, 98,
        117, 116, 76, 11, 89, 106, 0, 125, 118, 99, 86, 69, 30, 57, 126, 87, 112, 51, 17, 5, 95,
        14, 90, 84, 91, 8, 35, 103, 32, 97, 28, 66, 102, 31, 26, 45, 75, 4, 85, 92, 37, 74, 80, 49,
        68, 29, 115, 44, 64, 107, 108, 24, 110, 83, 36, 78, 42, 19, 15, 41, 88, 119, 59, 3,
    ];
    static S9: [u32; 512] = [
        167, 239, 161, 379, 391, 334, 9, 338, 38, 226, 48, 358, 452, 385, 90, 397, 183, 253, 147,
        331, 415, 340, 51, 362, 306, 500, 262, 82, 216, 159, 356, 177, 175, 241, 489, 37, 206, 17,
        0, 333, 44, 254, 378, 58, 143, 220, 81, 400, 95, 3, 315, 245, 54, 235, 218, 405, 472, 264,
        172, 494, 371, 290, 399, 76, 165, 197, 395, 121, 257, 480, 423, 212, 240, 28, 462, 176,
        406, 507, 288, 223, 501, 407, 249, 265, 89, 186, 221, 428, 164, 74, 440, 196, 458, 421,
        350, 163, 232, 158, 134, 354, 13, 250, 491, 142, 191, 69, 193, 425, 152, 227, 366, 135,
        344, 300, 276, 242, 437, 320, 113, 278, 11, 243, 87, 317, 36, 93, 496, 27, 487, 446, 482,
        41, 68, 156, 457, 131, 326, 403, 339, 20, 39, 115, 442, 124, 475, 384, 508, 53, 112, 170,
        479, 151, 126, 169, 73, 268, 279, 321, 168, 364, 363, 292, 46, 499, 393, 327, 324, 24, 456,
        267, 157, 460, 488, 426, 309, 229, 439, 506, 208, 271, 349, 401, 434, 236, 16, 209, 359,
        52, 56, 120, 199, 277, 465, 416, 252, 287, 246, 6, 83, 305, 420, 345, 153, 502, 65, 61,
        244, 282, 173, 222, 418, 67, 386, 368, 261, 101, 476, 291, 195, 430, 49, 79, 166, 330, 280,
        383, 373, 128, 382, 408, 155, 495, 367, 388, 274, 107, 459, 417, 62, 454, 132, 225, 203,
        316, 234, 14, 301, 91, 503, 286, 424, 211, 347, 307, 140, 374, 35, 103, 125, 427, 19, 214,
        453, 146, 498, 314, 444, 230, 256, 329, 198, 285, 50, 116, 78, 410, 10, 205, 510, 171, 231,
        45, 139, 467, 29, 86, 505, 32, 72, 26, 342, 150, 313, 490, 431, 238, 411, 325, 149, 473,
        40, 119, 174, 355, 185, 233, 389, 71, 448, 273, 372, 55, 110, 178, 322, 12, 469, 392, 369,
        190, 1, 109, 375, 137, 181, 88, 75, 308, 260, 484, 98, 272, 370, 275, 412, 111, 336, 318,
        4, 504, 492, 259, 304, 77, 337, 435, 21, 357, 303, 332, 483, 18, 47, 85, 25, 497, 474, 289,
        100, 269, 296, 478, 270, 106, 31, 104, 433, 84, 414, 486, 394, 96, 99, 154, 511, 148, 413,
        361, 409, 255, 162, 215, 302, 201, 266, 351, 343, 144, 441, 365, 108, 298, 251, 34, 182,
        509, 138, 210, 335, 133, 311, 352, 328, 141, 396, 346, 123, 319, 450, 281, 429, 228, 443,
        481, 92, 404, 485, 422, 248, 297, 23, 213, 130, 466, 22, 217, 283, 70, 294, 360, 419, 127,
        312, 377, 7, 468, 194, 2, 117, 295, 463, 258, 224, 447, 247, 187, 80, 398, 284, 353, 105,
        390, 299, 471, 470, 184, 57, 200, 348, 63, 204, 188, 33, 451, 97, 30, 310, 219, 94, 160,
        129, 493, 64, 179, 263, 102, 189, 207, 114, 402, 438, 477, 387, 122, 192, 42, 381, 5, 145,
        118, 180, 449, 293, 323, 136, 380, 43, 66, 60, 455, 341, 445, 202, 432, 8, 237, 15, 376,
        436, 464, 59, 461,
    ];
    nine = (in_0 >> 7) & 0x1ff;
    seven = in_0 & 0x7f;
    nine = S9[nine as usize] ^ seven;
    seven = S7[seven as usize] ^ nine & 0x7f;
    seven ^= subkey >> 9;
    nine ^= subkey & 0x1ff;
    nine = S9[nine as usize] ^ seven;
    seven = S7[seven as usize] ^ nine & 0x7f;
    (seven << 9).wrapping_add(nine)
}

impl Kasumi {
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        let mut ret = Self {
            kli1: [0; 8],
            kli2: [0; 8],
            koi1: [0; 8],
            koi2: [0; 8],
            koi3: [0; 8],
            kii1: [0; 8],
            kii2: [0; 8],
            kii3: [0; 8],
        };
        ret.setup(key, 0)?;
        Ok(ret)
    }
    fn fo(&self, in_0: u32, round_no: i32) -> u32 {
        let mut left: u32;
        let mut right: u32;
        left = in_0 >> 16;
        right = in_0 & 0xffff;
        left ^= self.koi1[round_no as usize];
        left = kasumi_fi(left, self.kii1[round_no as usize]);
        left ^= right;
        right ^= self.koi2[round_no as usize];
        right = kasumi_fi(right, self.kii2[round_no as usize]);
        right ^= left;
        left ^= self.koi3[round_no as usize];
        left = kasumi_fi(left, self.kii3[round_no as usize]);
        left ^= right;
        (right << 16).wrapping_add(left)
    }

    fn fl(&self, in_0: u32, round_no: i32) -> u32 {
        let mut l: u32;
        let mut r: u32;
        l = in_0 >> 16;
        r = in_0 & 0xffff;
        let a = l & self.kli1[round_no as usize];
        r ^= ((a << 1) | (a >> (16 - 1))) & 0xffff;
        let b = r | self.kli2[round_no as usize];
        l ^= ((b << 1) | (b >> (16 - 1))) & 0xffff;
        (l << 16).wrapping_add(r)
    }

    fn encrypt(&self, inout: &mut [u8]) {
        let mut temp: u32;
        let mut n: i32;

        let (mut left, mut right) = {
            let mut inout = &*inout;
            (inout.get_u32(), inout.get_u32())
        };

        n = 0;
        while n <= 7 {
            temp = self.fl(left, n);
            let fresh0 = n;
            n += 1;
            temp = self.fo(temp, fresh0);
            right ^= temp;
            temp = self.fo(right, n);
            let fresh1 = n;
            n += 1;
            temp = self.fl(temp, fresh1);
            left ^= temp;
        }

        let mut inout = inout;
        inout.put_u32(left);
        inout.put_u32(right);
    }

    fn decrypt(&self, inout: &mut [u8]) {
        let mut temp: u32;
        let mut n: i32;

        let (mut left, mut right) = {
            let mut inout = &*inout;
            (inout.get_u32(), inout.get_u32())
        };
        n = 7;
        while n >= 0 {
            temp = self.fo(right, n);
            let fresh2 = n;
            n -= 1;
            temp = self.fl(temp, fresh2);
            left ^= temp;
            temp = self.fl(left, n);
            let fresh3 = n;
            n -= 1;
            temp = self.fo(temp, fresh3);
            right ^= temp;
        }
        let mut inout = inout;
        inout.put_u32(left);
        inout.put_u32(right);
    }

    pub fn setup(&mut self, key: &[u8], num_rounds: usize) -> CryptoResult<()> {
        const C: [u32; 8] = [
            0x123, 0x4567, 0x89ab, 0xcdef, 0xfedc, 0xba98, 0x7654, 0x3210,
        ];
        let mut ukey: [u32; 8] = [0; 8];
        let mut kprime: [u32; 8] = [0; 8];

        if key.len() != 16 {
            return Err(CryptoError::InvalidKeySize {
                expected: "16",
                actual: key.len(),
            });
        }
        if num_rounds != 0 && num_rounds != 8 {
            return Err(CryptoError::InvalidRound(num_rounds));
        }

        for i in 0..8 {
            ukey[i] = ((key[2 * i] as u32) << 8) | (key[2 * i + 1] as u32);
        }

        for i in 0..8 {
            kprime[i] = ukey[i] ^ C[i];
        }

        for i in 0..8 {
            self.kli1[i] = ((ukey[i] << 1) | (ukey[i] >> (16 - 1))) & 0xffff;
            self.kli2[i] = kprime[(i + 2) & 0x7];
            self.koi1[i] =
                ((ukey[(i + 1) & 0x7] << 5) | (ukey[(i + 1) & 0x7] >> (16 - 5))) & 0xffff;
            self.koi2[i] =
                ((ukey[(i + 5) & 0x7] << 8) | (ukey[(i + 5) & 0x7] >> (16 - 8))) & 0xffff;
            self.koi3[i] =
                ((ukey[(i + 6) & 0x7] << 13) | (ukey[(i + 6) & 0x7] >> (16 - 13))) & 0xffff;
            self.kii1[i] = kprime[(i + 4) & 0x7];
            self.kii2[i] = kprime[(i + 3) & 0x7];
            self.kii3[i] = kprime[(i + 7) & 0x7];
        }

        Ok(())
    }
}

impl BlockCipher for Kasumi {
    fn encrypt_block(&self, inout: &mut [u8]) {
        self.encrypt(inout);
    }

    fn decrypt_block(&self, inout: &mut [u8]) {
        self.decrypt(inout);
    }

    fn block_size(&self) -> usize {
        8
    }
}

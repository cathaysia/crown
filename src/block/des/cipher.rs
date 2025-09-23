use super::block::*;
use crate::{
    block::{BlockCipher, BlockCipherMarker},
    error::{CryptoError, CryptoResult},
};

#[derive(Clone)]
pub struct Des {
    subkeys: [u64; 16],
}

impl BlockCipherMarker for Des {}

impl BlockCipher for Des {
    fn block_size(&self) -> usize {
        Des::BLOCK_SIZE
    }

    fn encrypt(&self, inout: &mut [u8]) {
        if inout.len() < Des::BLOCK_SIZE {
            panic!("crypto/des: inout not full block");
        }

        crypt_block(&self.subkeys, inout, false);
    }

    fn decrypt(&self, inout: &mut [u8]) {
        if inout.len() < Des::BLOCK_SIZE {
            panic!("crypto/des: output not full block");
        }

        crypt_block(&self.subkeys, inout, true);
    }
}

impl Des {
    pub const BLOCK_SIZE: usize = 8;
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != 8 {
            return Err(CryptoError::InvalidKeySize {
                expected: "8",
                actual: key.len(),
            });
        }

        let mut cipher = Self { subkeys: [0; 16] };
        cipher.generate_subkeys(key);

        Ok(cipher)
    }

    fn generate_subkeys(&mut self, key_bytes: &[u8]) {
        use super::consts::{KS_ROTATIONS, PERMUTED_CHOICE1, PERMUTED_CHOICE2};

        get_feistel_box();

        let key = u64::from_be_bytes(key_bytes[..8].try_into().unwrap());
        let permuted_key = permute_block(key, &PERMUTED_CHOICE1);

        let left_rotations = ks_rotate((permuted_key >> 28) as u32, &KS_ROTATIONS);
        let right_rotations = ks_rotate(((permuted_key << 4) >> 4) as u32, &KS_ROTATIONS);

        for i in 0..16 {
            let pc2_input = ((left_rotations[i] as u64) << 28) | (right_rotations[i] as u64);
            self.subkeys[i] = unpack(permute_block(pc2_input, &PERMUTED_CHOICE2));
        }
    }
}

pub struct TripleDes {
    cipher1: Des,
    cipher2: Des,
    cipher3: Des,
}
impl BlockCipherMarker for TripleDes {}

impl TripleDes {
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != 24 {
            return Err(CryptoError::InvalidKeySize {
                expected: "24",
                actual: key.len(),
            });
        }

        let mut cipher1 = Des { subkeys: [0; 16] };
        let mut cipher2 = Des { subkeys: [0; 16] };
        let mut cipher3 = Des { subkeys: [0; 16] };

        cipher1.generate_subkeys(&key[..8]);
        cipher2.generate_subkeys(&key[8..16]);
        cipher3.generate_subkeys(&key[16..]);

        Ok(Self {
            cipher1,
            cipher2,
            cipher3,
        })
    }
}

impl BlockCipher for TripleDes {
    fn block_size(&self) -> usize {
        Des::BLOCK_SIZE
    }

    fn encrypt(&self, inout: &mut [u8]) {
        if inout.len() < Des::BLOCK_SIZE {
            panic!("crypto/des: output not full block");
        }

        let b = u64::from_be_bytes(inout[..8].try_into().unwrap());
        let b = permute_initial_block(b);
        let mut left = (b >> 32) as u32;
        let mut right = b as u32;

        left = left.rotate_left(1);
        right = right.rotate_left(1);

        for i in 0..8 {
            let (new_left, new_right) = feistel(
                left,
                right,
                self.cipher1.subkeys[2 * i],
                self.cipher1.subkeys[2 * i + 1],
            );
            left = new_left;
            right = new_right;
        }

        for i in 0..8 {
            let (new_right, new_left) = feistel(
                right,
                left,
                self.cipher2.subkeys[15 - 2 * i],
                self.cipher2.subkeys[15 - (2 * i + 1)],
            );
            right = new_right;
            left = new_left;
        }

        for i in 0..8 {
            let (new_left, new_right) = feistel(
                left,
                right,
                self.cipher3.subkeys[2 * i],
                self.cipher3.subkeys[2 * i + 1],
            );
            left = new_left;
            right = new_right;
        }

        left = left.rotate_right(1);
        right = right.rotate_right(1);

        let pre_output = ((right as u64) << 32) | (left as u64);
        let result = permute_final_block(pre_output);
        inout[..8].copy_from_slice(&result.to_be_bytes());
    }

    fn decrypt(&self, inout: &mut [u8]) {
        if inout.len() < Des::BLOCK_SIZE {
            panic!("crypto/des: output not full block");
        }

        let b = u64::from_be_bytes(inout[..8].try_into().unwrap());
        let b = permute_initial_block(b);
        let mut left = (b >> 32) as u32;
        let mut right = b as u32;

        left = left.rotate_left(1);
        right = right.rotate_left(1);

        for i in 0..8 {
            let (new_left, new_right) = feistel(
                left,
                right,
                self.cipher3.subkeys[15 - 2 * i],
                self.cipher3.subkeys[15 - (2 * i + 1)],
            );
            left = new_left;
            right = new_right;
        }

        for i in 0..8 {
            let (new_right, new_left) = feistel(
                right,
                left,
                self.cipher2.subkeys[2 * i],
                self.cipher2.subkeys[2 * i + 1],
            );
            right = new_right;
            left = new_left;
        }

        for i in 0..8 {
            let (new_left, new_right) = feistel(
                left,
                right,
                self.cipher1.subkeys[15 - 2 * i],
                self.cipher1.subkeys[15 - (2 * i + 1)],
            );
            left = new_left;
            right = new_right;
        }

        left = left.rotate_right(1);
        right = right.rotate_right(1);

        let pre_output = ((right as u64) << 32) | (left as u64);
        let result = permute_final_block(pre_output);
        inout[..8].copy_from_slice(&result.to_be_bytes());
    }
}

use super::block::*;
use crate::{
    cipher::{
        cbc::{CbcDecAbleMarker, CbcEncAbleMarker},
        ctr::CtrAbleMarker,
        BlockCipher,
    },
    des::block::{init_feistel_box, FEISTEL_BOX_INIT},
};
use std::fmt;

pub const BLOCK_SIZE: usize = 8;

#[derive(Debug, Clone)]
pub struct KeySizeError(pub usize);

impl fmt::Display for KeySizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "crypto/des: invalid key size {}", self.0)
    }
}

impl std::error::Error for KeySizeError {}

pub struct DesCipher {
    pub subkeys: [u64; 16],
}

impl CtrAbleMarker for DesCipher {}
impl CbcEncAbleMarker for DesCipher {}
impl CbcDecAbleMarker for DesCipher {}

impl BlockCipher for DesCipher {
    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
        if src.len() < BLOCK_SIZE {
            panic!("crypto/des: input not full block");
        }
        if dst.len() < BLOCK_SIZE {
            panic!("crypto/des: output not full block");
        }
        if self.inexact_overlap(&dst[..BLOCK_SIZE], &src[..BLOCK_SIZE]) {
            panic!("crypto/des: invalid buffer overlap");
        }

        crypt_block(&self.subkeys, dst, src, false);
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
        if src.len() < BLOCK_SIZE {
            panic!("crypto/des: input not full block");
        }
        if dst.len() < BLOCK_SIZE {
            panic!("crypto/des: output not full block");
        }
        if self.inexact_overlap(&dst[..BLOCK_SIZE], &src[..BLOCK_SIZE]) {
            panic!("crypto/des: invalid buffer overlap");
        }

        crypt_block(&self.subkeys, dst, src, true);
    }
}

impl DesCipher {
    pub fn new(key: &[u8]) -> Result<Self, KeySizeError> {
        if key.len() != 8 {
            return Err(KeySizeError(key.len()));
        }

        let mut cipher = Self { subkeys: [0; 16] };
        cipher.generate_subkeys(key);

        Ok(cipher)
    }

    pub fn generate_subkeys(&mut self, key_bytes: &[u8]) {
        use super::consts::{KS_ROTATIONS, PERMUTED_CHOICE1, PERMUTED_CHOICE2};

        FEISTEL_BOX_INIT.call_once(|| {
            init_feistel_box();
        });

        let key = u64::from_be_bytes(key_bytes[..8].try_into().unwrap());
        let permuted_key = permute_block(key, &PERMUTED_CHOICE1);

        let left_rotations = ks_rotate((permuted_key >> 28) as u32, &KS_ROTATIONS);
        let right_rotations = ks_rotate(((permuted_key << 4) >> 4) as u32, &KS_ROTATIONS);

        for i in 0..16 {
            let pc2_input = ((left_rotations[i] as u64) << 28) | (right_rotations[i] as u64);
            self.subkeys[i] = unpack(permute_block(pc2_input, &PERMUTED_CHOICE2));
        }
    }

    fn inexact_overlap(&self, dst: &[u8], src: &[u8]) -> bool {
        let dst_ptr = dst.as_ptr() as usize;
        let src_ptr = src.as_ptr() as usize;
        let dst_end = dst_ptr + dst.len();
        let src_end = src_ptr + src.len();

        (dst_ptr < src_end && src_ptr < dst_end) && (dst_ptr != src_ptr)
    }
}

pub struct TripleDesBlockCipher {
    cipher1: DesCipher,
    cipher2: DesCipher,
    cipher3: DesCipher,
}

impl TripleDesBlockCipher {
    pub fn new(key: &[u8]) -> Result<Self, KeySizeError> {
        if key.len() != 24 {
            return Err(KeySizeError(key.len()));
        }

        let mut cipher1 = DesCipher { subkeys: [0; 16] };
        let mut cipher2 = DesCipher { subkeys: [0; 16] };
        let mut cipher3 = DesCipher { subkeys: [0; 16] };

        cipher1.generate_subkeys(&key[..8]);
        cipher2.generate_subkeys(&key[8..16]);
        cipher3.generate_subkeys(&key[16..]);

        Ok(Self {
            cipher1,
            cipher2,
            cipher3,
        })
    }

    pub fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    pub fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
        if src.len() < BLOCK_SIZE {
            panic!("crypto/des: input not full block");
        }
        if dst.len() < BLOCK_SIZE {
            panic!("crypto/des: output not full block");
        }
        if self.inexact_overlap(&dst[..BLOCK_SIZE], &src[..BLOCK_SIZE]) {
            panic!("crypto/des: invalid buffer overlap");
        }

        let b = u64::from_be_bytes(src[..8].try_into().unwrap());
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
        dst[..8].copy_from_slice(&result.to_be_bytes());
    }

    pub fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
        if src.len() < BLOCK_SIZE {
            panic!("crypto/des: input not full block");
        }
        if dst.len() < BLOCK_SIZE {
            panic!("crypto/des: output not full block");
        }
        if self.inexact_overlap(&dst[..BLOCK_SIZE], &src[..BLOCK_SIZE]) {
            panic!("crypto/des: invalid buffer overlap");
        }

        let b = u64::from_be_bytes(src[..8].try_into().unwrap());
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
        dst[..8].copy_from_slice(&result.to_be_bytes());
    }

    fn inexact_overlap(&self, dst: &[u8], src: &[u8]) -> bool {
        let dst_ptr = dst.as_ptr() as usize;
        let src_ptr = src.as_ptr() as usize;
        let dst_end = dst_ptr + dst.len();
        let src_end = src_ptr + src.len();

        (dst_ptr < src_end && src_ptr < dst_end) && (dst_ptr != src_ptr)
    }
}

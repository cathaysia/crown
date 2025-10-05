#[cfg(test)]
mod tests;

use crate::{
    aead::{Aead, AeadUser},
    block::{BlockCipher, MAX_BLOCK_SIZE},
    error::{CryptoError, CryptoResult},
};

pub trait Ocb {
    fn to_ocb<const TAG_SIZE: usize, const NONCE_SIZE: usize>(
        self,
    ) -> CryptoResult<impl Aead<TAG_SIZE>>;
}

pub trait OcbGeneric {}

impl<T> Ocb for T
where
    T: BlockCipher + OcbGeneric,
{
    fn to_ocb<const TAG_SIZE: usize, const NONCE_SIZE: usize>(
        self,
    ) -> CryptoResult<impl Aead<TAG_SIZE>> {
        Ok(OcbImpl::<TAG_SIZE, NONCE_SIZE, _>::new(self))
    }
}

struct OcbImpl<const TAG_SIZE: usize, const NONCE_SIZE: usize, T: BlockCipher> {
    cipher: T,
    l_star: [u8; MAX_BLOCK_SIZE],
    l_dollar: [u8; MAX_BLOCK_SIZE],
    l: [[u8; MAX_BLOCK_SIZE]; 64],
}

impl<const TAG_SIZE: usize, const NONCE_SIZE: usize, T: BlockCipher>
    OcbImpl<TAG_SIZE, NONCE_SIZE, T>
{
    pub fn new(cipher: T) -> Self {
        assert!(TAG_SIZE <= cipher.block_size());
        assert!((1..cipher.block_size()).contains(&NONCE_SIZE));

        let block_size = cipher.block_size();

        let mut l_star = [0u8; MAX_BLOCK_SIZE];
        l_star[..block_size].fill(0);
        cipher.encrypt(&mut l_star[..block_size]);

        let mut l_dollar = [0u8; MAX_BLOCK_SIZE];
        l_dollar[..block_size].copy_from_slice(&l_star[..block_size]);
        Self::double(&mut l_dollar[..block_size]);

        let mut l = [[0u8; MAX_BLOCK_SIZE]; 64];
        let mut current = [0u8; MAX_BLOCK_SIZE];
        current[..block_size].copy_from_slice(&l_dollar[..block_size]);
        Self::double(&mut current[..block_size]);
        l[0][..block_size].copy_from_slice(&current[..block_size]);

        (1..64).for_each(|i| {
            Self::double(&mut current[..block_size]);
            l[i][..block_size].copy_from_slice(&current[..block_size]);
        });

        Self {
            cipher,
            l_star,
            l_dollar,
            l,
        }
    }

    fn double(block: &mut [u8]) {
        let mut carry = 0u8;
        for i in (0..block.len()).rev() {
            let new_carry = (block[i] & 0x80) >> 7;
            block[i] = (block[i] << 1) | carry;
            carry = new_carry;
        }
        if carry != 0 {
            block[block.len() - 1] ^= 0x87;
        }
    }

    fn ntz(n: usize) -> usize {
        if n == 0 {
            return 64;
        }
        n.trailing_zeros() as usize
    }

    fn get_l(&self, i: usize) -> &[u8] {
        let ntz = Self::ntz(i);
        if ntz < 64 {
            &self.l[ntz][..self.cipher.block_size()]
        } else {
            &self.l_star[..self.cipher.block_size()]
        }
    }

    fn xor_blocks(dst: &mut [u8], src: &[u8]) {
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d ^= *s;
        }
    }

    fn process_nonce(&self, nonce: &[u8]) -> tinyvec::ArrayVec<[u8; MAX_BLOCK_SIZE]> {
        let block_size = self.cipher.block_size();
        let mut nonce_formatted = new_array(block_size);
        let mut stretch = [0u8; 24];

        let nonce_len = nonce.len();

        nonce_formatted[0] = (((TAG_SIZE * 8) % 128) as u8) << 1;
        nonce_formatted[block_size - nonce_len..block_size].copy_from_slice(nonce);
        nonce_formatted[block_size - nonce_len - 1] |= 1;

        let mut ktop = nonce_formatted;
        ktop[block_size - 1] &= 0xc0;
        self.cipher.encrypt(&mut ktop);

        stretch[..16].copy_from_slice(&ktop[..16]);
        for i in 0..8 {
            stretch[16 + i] = ktop[i] ^ ktop[i + 1];
        }

        let bottom = nonce_formatted[block_size - 1] & 0x3f;
        let shift = bottom % 8;
        let byte_offset = (bottom / 8) as usize;

        let mut offset = new_array(block_size);

        for i in 0..block_size {
            let src_idx = byte_offset + i;
            if src_idx < 24 {
                offset[i] = stretch[src_idx];
            }
        }

        if shift > 0 {
            let mut carry = 0u8;
            for i in (0..block_size).rev() {
                let new_carry = offset[i] >> (8 - shift);
                offset[i] = (offset[i] << shift) | carry;
                carry = new_carry;
            }

            if byte_offset + block_size < 24 {
                let mask = 0xff << (8 - shift);
                offset[block_size - 1] |= (stretch[byte_offset + block_size] & mask) >> (8 - shift);
            }
        }

        offset
    }
}

impl<const TAG_SIZE: usize, const NONCE_SIZE: usize, T: BlockCipher> AeadUser
    for OcbImpl<TAG_SIZE, NONCE_SIZE, T>
{
    fn nonce_size(&self) -> usize {
        NONCE_SIZE
    }

    fn overhead(&self) -> usize {
        TAG_SIZE
    }
}

impl<const TAG_SIZE: usize, const NONCE_SIZE: usize, T: BlockCipher> Aead<TAG_SIZE>
    for OcbImpl<TAG_SIZE, NONCE_SIZE, T>
{
    fn seal_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; TAG_SIZE]> {
        if nonce.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize {
                expected: "NONCE_SIZE",
                actual: nonce.len(),
            });
        }

        let block_size = self.cipher.block_size();
        let mut offset = self.process_nonce(nonce);
        let mut checksum = new_array(block_size);
        let mut sum = new_array(block_size);

        if !additional_data.is_empty() {
            let mut ad_offset = new_array(block_size);
            let ad_full_blocks = additional_data.len() / block_size;

            for i in 0..ad_full_blocks {
                let start = i * block_size;
                let end = start + block_size;
                let mut block = new_array(block_size);
                block[..block_size].copy_from_slice(&additional_data[start..end]);

                Self::xor_blocks(&mut ad_offset, self.get_l(i + 1));
                Self::xor_blocks(&mut block, &ad_offset);
                self.cipher.encrypt(&mut block);
                Self::xor_blocks(&mut sum, &block);
            }

            let remaining = additional_data.len() % block_size;
            if remaining > 0 {
                Self::xor_blocks(&mut ad_offset, &self.l_star[..block_size]);
                let mut block = new_array(block_size);
                let start = ad_full_blocks * block_size;
                block[..remaining].copy_from_slice(&additional_data[start..start + remaining]);
                block[remaining] = 0x80;
                Self::xor_blocks(&mut block, &ad_offset);
                self.cipher.encrypt(&mut block);
                Self::xor_blocks(&mut sum, &block);
            }
        }

        let full_blocks = inout.len() / block_size;

        for i in 0..full_blocks {
            let start = i * block_size;
            let end = start + block_size;
            let block = &mut inout[start..end];

            Self::xor_blocks(&mut offset, self.get_l(i + 1));

            for j in 0..block_size {
                checksum[j] ^= block[j];
            }

            Self::xor_blocks(block, &offset);
            self.cipher.encrypt(block);
            Self::xor_blocks(block, &offset);
        }

        let remaining = inout.len() % block_size;
        if remaining > 0 {
            Self::xor_blocks(&mut offset, &self.l_star[..block_size]);
            let mut pad = offset;
            self.cipher.encrypt(&mut pad);

            let start = full_blocks * block_size;
            for i in 0..remaining {
                checksum[i] ^= inout[start + i];
                inout[start + i] ^= pad[i];
            }
            checksum[remaining] ^= 0x80;
        }

        Self::xor_blocks(&mut checksum, &offset);
        Self::xor_blocks(&mut checksum, &self.l_dollar[..block_size]);
        self.cipher.encrypt(&mut checksum);
        Self::xor_blocks(&mut checksum, &sum);

        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&checksum[..TAG_SIZE]);
        Ok(tag)
    }

    fn open_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize {
                expected: "NONCE_SIZE",
                actual: nonce.len(),
            });
        }

        if tag.len() != TAG_SIZE {
            return Err(CryptoError::InvalidTagSize {
                expected: "TAG_SIZE",
                actual: tag.len(),
            });
        }

        let block_size = self.cipher.block_size();
        let mut offset = self.process_nonce(nonce);
        let mut checksum = new_array(block_size);
        let mut sum = new_array(block_size);

        if !additional_data.is_empty() {
            let mut ad_offset = new_array(block_size);
            let ad_full_blocks = additional_data.len() / block_size;

            for i in 0..ad_full_blocks {
                let start = i * block_size;
                let end = start + block_size;
                let mut block = new_array(block_size);
                block[..block_size].copy_from_slice(&additional_data[start..end]);

                Self::xor_blocks(&mut ad_offset, self.get_l(i + 1));
                Self::xor_blocks(&mut block, &ad_offset);
                self.cipher.encrypt(&mut block);
                Self::xor_blocks(&mut sum, &block);
            }

            let remaining = additional_data.len() % block_size;
            if remaining > 0 {
                Self::xor_blocks(&mut ad_offset, &self.l_star[..block_size]);
                let mut block = new_array(block_size);
                let start = ad_full_blocks * block_size;
                block[..remaining].copy_from_slice(&additional_data[start..start + remaining]);
                block[remaining] = 0x80;
                Self::xor_blocks(&mut block, &ad_offset);
                self.cipher.encrypt(&mut block);
                Self::xor_blocks(&mut sum, &block);
            }
        }

        let full_blocks = inout.len() / block_size;

        for i in 0..full_blocks {
            let start = i * block_size;
            let end = start + block_size;
            let block = &mut inout[start..end];

            Self::xor_blocks(&mut offset, self.get_l(i + 1));

            Self::xor_blocks(block, &offset);
            self.cipher.decrypt(block);
            Self::xor_blocks(block, &offset);

            for j in 0..block_size {
                checksum[j] ^= block[j];
            }
        }

        let remaining = inout.len() % block_size;
        if remaining > 0 {
            Self::xor_blocks(&mut offset, &self.l_star[..block_size]);
            let mut pad = offset;
            self.cipher.encrypt(&mut pad);

            let start = full_blocks * block_size;
            for i in 0..remaining {
                inout[start + i] ^= pad[i];
                checksum[i] ^= inout[start + i];
            }
            checksum[remaining] ^= 0x80;
        }

        Self::xor_blocks(&mut checksum, &offset);
        Self::xor_blocks(&mut checksum, &self.l_dollar[..block_size]);
        self.cipher.encrypt(&mut checksum);
        Self::xor_blocks(&mut checksum, &sum);

        let computed_tag = &checksum[..TAG_SIZE];
        if computed_tag != tag {
            return Err(CryptoError::AuthenticationFailed);
        }

        Ok(())
    }
}

fn new_array(block_size: usize) -> tinyvec::ArrayVec<[u8; MAX_BLOCK_SIZE]> {
    let mut arr = tinyvec::array_vec!([u8; MAX_BLOCK_SIZE]);
    arr.set_len(block_size);

    arr
}

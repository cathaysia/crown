use crate::{
    aead::{Aead, AeadUser},
    block::BlockCipher,
    error::{CryptoError, CryptoResult},
    utils::subtle::constant_time_eq,
};

const CCM_BLOCK_SIZE: usize = 16;
const CCM_MIN_NONCE_SIZE: usize = 7;
const CCM_MAX_NONCE_SIZE: usize = 13;

pub trait Ccm {
    fn to_ccm<const TAG_SIZE: usize, const NONCE_SIZE: usize>(
        self,
    ) -> CryptoResult<impl Aead<TAG_SIZE>>;
}

impl<T> Ccm for T
where
    T: BlockCipher,
{
    fn to_ccm<const TAG_SIZE: usize, const NONCE_SIZE: usize>(
        self,
    ) -> CryptoResult<impl Aead<TAG_SIZE>> {
        CcmImpl::<T, TAG_SIZE, NONCE_SIZE>::new(self)
    }
}

struct CcmImpl<B: BlockCipher, const TAG_SIZE: usize, const NONCE_SIZE: usize> {
    cipher: B,
}

impl<B: BlockCipher, const TAG_SIZE: usize, const NONCE_SIZE: usize>
    CcmImpl<B, TAG_SIZE, NONCE_SIZE>
{
    fn new(cipher: B) -> CryptoResult<Self> {
        if cipher.block_size() != CCM_BLOCK_SIZE {
            return Err(CryptoError::UnsupportedBlockSize(cipher.block_size()));
        }

        if !(CCM_MIN_NONCE_SIZE..=CCM_MAX_NONCE_SIZE).contains(&NONCE_SIZE) {
            return Err(CryptoError::InvalidNonceSize {
                expected: "7..=13",
                actual: NONCE_SIZE,
            });
        }

        if !(4..=CCM_BLOCK_SIZE).contains(&TAG_SIZE) || TAG_SIZE % 2 != 0 {
            return Err(CryptoError::InvalidTagSize {
                expected: "4, 6, 8, 10, 12, 14, or 16",
                actual: TAG_SIZE,
            });
        }

        Ok(Self { cipher })
    }

    fn q_size() -> usize {
        CCM_BLOCK_SIZE - 1 - NONCE_SIZE
    }

    fn validate_nonce_and_len(&self, nonce: &[u8], msg_len: usize) -> CryptoResult<()> {
        if nonce.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize {
                expected: "NONCE_SIZE",
                actual: nonce.len(),
            });
        }

        let q_size = Self::q_size();
        if q_size < core::mem::size_of::<usize>() && msg_len >= (1usize << (8 * q_size)) {
            return Err(CryptoError::MessageTooLarge);
        }

        Ok(())
    }

    fn encode_msg_len(block: &mut [u8; CCM_BLOCK_SIZE], msg_len: usize) {
        let q_size = Self::q_size();
        for i in 0..q_size {
            block[CCM_BLOCK_SIZE - 1 - i] = (msg_len >> (8 * i)) as u8;
        }
    }

    fn b0(nonce: &[u8], msg_len: usize, has_aad: bool) -> [u8; CCM_BLOCK_SIZE] {
        let mut block = [0u8; CCM_BLOCK_SIZE];
        let q_size = Self::q_size();
        block[0] =
            ((has_aad as u8) << 6) | ((((TAG_SIZE - 2) / 2) as u8) << 3) | (q_size as u8 - 1);
        block[1..1 + NONCE_SIZE].copy_from_slice(nonce);
        Self::encode_msg_len(&mut block, msg_len);
        block
    }

    fn counter(nonce: &[u8], value: usize) -> [u8; CCM_BLOCK_SIZE] {
        let mut block = [0u8; CCM_BLOCK_SIZE];
        let q_size = Self::q_size();
        block[0] = q_size as u8 - 1;
        block[1..1 + NONCE_SIZE].copy_from_slice(nonce);
        Self::encode_msg_len(&mut block, value);
        block
    }

    fn mac_block(&self, state: &mut [u8; CCM_BLOCK_SIZE], block: &[u8; CCM_BLOCK_SIZE]) {
        for i in 0..CCM_BLOCK_SIZE {
            state[i] ^= block[i];
        }
        self.cipher.encrypt_block(state);
    }

    fn mac_bytes(
        &self,
        state: &mut [u8; CCM_BLOCK_SIZE],
        block: &mut [u8; CCM_BLOCK_SIZE],
        offset: &mut usize,
        bytes: &[u8],
    ) {
        for &byte in bytes {
            block[*offset] = byte;
            *offset += 1;
            if *offset == CCM_BLOCK_SIZE {
                self.mac_block(state, block);
                block.fill(0);
                *offset = 0;
            }
        }
    }

    fn mac_aad(&self, state: &mut [u8; CCM_BLOCK_SIZE], aad: &[u8]) {
        if aad.is_empty() {
            return;
        }

        let mut block = [0u8; CCM_BLOCK_SIZE];
        let mut offset = 0usize;
        if aad.len() < 0xff00 {
            self.mac_bytes(
                state,
                &mut block,
                &mut offset,
                &(aad.len() as u16).to_be_bytes(),
            );
        } else if u32::try_from(aad.len()).is_ok() {
            self.mac_bytes(state, &mut block, &mut offset, &[0xff, 0xfe]);
            self.mac_bytes(
                state,
                &mut block,
                &mut offset,
                &(aad.len() as u32).to_be_bytes(),
            );
        } else {
            self.mac_bytes(state, &mut block, &mut offset, &[0xff, 0xff]);
            self.mac_bytes(
                state,
                &mut block,
                &mut offset,
                &(aad.len() as u64).to_be_bytes(),
            );
        }

        self.mac_bytes(state, &mut block, &mut offset, aad);
        if offset != 0 {
            self.mac_block(state, &block);
        }
    }

    fn raw_tag(
        &self,
        plaintext: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> [u8; CCM_BLOCK_SIZE] {
        let mut state = [0u8; CCM_BLOCK_SIZE];
        let block = Self::b0(nonce, plaintext.len(), !additional_data.is_empty());
        self.mac_block(&mut state, &block);
        self.mac_aad(&mut state, additional_data);

        for chunk in plaintext.chunks(CCM_BLOCK_SIZE) {
            let mut block = [0u8; CCM_BLOCK_SIZE];
            block[..chunk.len()].copy_from_slice(chunk);
            self.mac_block(&mut state, &block);
        }

        state
    }

    fn apply_ctr(&self, inout: &mut [u8], nonce: &[u8]) -> CryptoResult<()> {
        let mut counter = 1usize;
        for chunk in inout.chunks_mut(CCM_BLOCK_SIZE) {
            let mut mask = Self::counter(nonce, counter);
            self.cipher.encrypt_block(&mut mask);
            for i in 0..chunk.len() {
                chunk[i] ^= mask[i];
            }
            counter = counter.checked_add(1).ok_or(CryptoError::CounterOverflow)?;
        }

        Ok(())
    }

    fn mask_tag(&self, tag: &[u8; CCM_BLOCK_SIZE], nonce: &[u8]) -> [u8; TAG_SIZE] {
        let mut s0 = Self::counter(nonce, 0);
        self.cipher.encrypt_block(&mut s0);

        let mut result = [0u8; TAG_SIZE];
        for i in 0..TAG_SIZE {
            result[i] = tag[i] ^ s0[i];
        }
        result
    }
}

impl<B: BlockCipher, const TAG_SIZE: usize, const NONCE_SIZE: usize> AeadUser
    for CcmImpl<B, TAG_SIZE, NONCE_SIZE>
{
    fn nonce_size(&self) -> usize {
        NONCE_SIZE
    }

    fn tag_size(&self) -> usize {
        TAG_SIZE
    }
}

impl<B: BlockCipher, const TAG_SIZE: usize, const NONCE_SIZE: usize> Aead<TAG_SIZE>
    for CcmImpl<B, TAG_SIZE, NONCE_SIZE>
{
    fn seal_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; TAG_SIZE]> {
        self.validate_nonce_and_len(nonce, inout.len())?;

        let tag = self.raw_tag(inout, nonce, additional_data);
        self.apply_ctr(inout, nonce)?;
        Ok(self.mask_tag(&tag, nonce))
    }

    fn open_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        self.validate_nonce_and_len(nonce, inout.len())?;
        if tag.len() != TAG_SIZE {
            return Err(CryptoError::InvalidTagSize {
                expected: "TAG_SIZE",
                actual: tag.len(),
            });
        }

        self.apply_ctr(inout, nonce)?;
        let expected_tag = self.mask_tag(&self.raw_tag(inout, nonce, additional_data), nonce);
        if !constant_time_eq(&expected_tag, tag) {
            inout.fill(0);
            return Err(CryptoError::AuthenticationFailed);
        }

        Ok(())
    }
}

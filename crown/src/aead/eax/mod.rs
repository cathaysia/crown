//! EAX authenticated-encryption mode for 128-bit block ciphers.

#[cfg(test)]
mod tests;

use crate::{
    aead::{Aead, AeadUser},
    block::BlockCipher,
    error::{CryptoError, CryptoResult},
    utils::subtle::constant_time_eq,
};

const EAX_BLOCK_SIZE: usize = 16;

pub trait Eax {
    /// Converts a 128-bit block cipher into EAX mode with a fixed tag size.
    ///
    /// The nonce length is configured at construction time and checked on
    /// every seal or open operation.
    fn to_eax<const TAG_SIZE: usize>(self, nonce_size: usize) -> CryptoResult<impl Aead<TAG_SIZE>>;
}

impl<T> Eax for T
where
    T: BlockCipher,
{
    fn to_eax<const TAG_SIZE: usize>(self, nonce_size: usize) -> CryptoResult<impl Aead<TAG_SIZE>> {
        EaxImpl::<T, TAG_SIZE>::new(self, nonce_size)
    }
}

struct EaxImpl<B: BlockCipher, const TAG_SIZE: usize> {
    cipher: B,
    nonce_size: usize,
    subkey1: [u8; EAX_BLOCK_SIZE],
    subkey2: [u8; EAX_BLOCK_SIZE],
}

impl<B: BlockCipher, const TAG_SIZE: usize> EaxImpl<B, TAG_SIZE> {
    fn new(cipher: B, nonce_size: usize) -> CryptoResult<Self> {
        if cipher.block_size() != EAX_BLOCK_SIZE {
            return Err(CryptoError::UnsupportedBlockSize(cipher.block_size()));
        }

        if !(1..=EAX_BLOCK_SIZE).contains(&TAG_SIZE) {
            return Err(CryptoError::InvalidTagSize {
                expected: "1..=16",
                actual: TAG_SIZE,
            });
        }

        let mut subkey1 = [0u8; EAX_BLOCK_SIZE];
        cipher.encrypt_block(&mut subkey1);
        Self::double(&mut subkey1);

        let mut subkey2 = subkey1;
        Self::double(&mut subkey2);

        Ok(Self {
            cipher,
            nonce_size,
            subkey1,
            subkey2,
        })
    }

    fn double(block: &mut [u8; EAX_BLOCK_SIZE]) {
        let carry = block[0] >> 7;
        for i in 0..EAX_BLOCK_SIZE - 1 {
            block[i] = (block[i] << 1) | (block[i + 1] >> 7);
        }
        block[EAX_BLOCK_SIZE - 1] <<= 1;
        block[EAX_BLOCK_SIZE - 1] ^= 0x87 & carry.wrapping_neg();
    }

    fn mac_block(&self, state: &mut [u8; EAX_BLOCK_SIZE], block: &[u8; EAX_BLOCK_SIZE]) {
        for i in 0..EAX_BLOCK_SIZE {
            state[i] ^= block[i];
        }
        self.cipher.encrypt_block(state);
    }

    fn omac(&self, domain: u8, data: &[u8]) -> [u8; EAX_BLOCK_SIZE] {
        let mut state = [0u8; EAX_BLOCK_SIZE];
        let mut domain_block = [0u8; EAX_BLOCK_SIZE];
        domain_block[EAX_BLOCK_SIZE - 1] = domain;

        if data.is_empty() {
            for i in 0..EAX_BLOCK_SIZE {
                domain_block[i] ^= self.subkey1[i];
            }
            self.mac_block(&mut state, &domain_block);
            return state;
        }

        self.mac_block(&mut state, &domain_block);

        let complete_last_block = data.len().is_multiple_of(EAX_BLOCK_SIZE);
        let last_block_start = if complete_last_block {
            data.len() - EAX_BLOCK_SIZE
        } else {
            data.len() - data.len() % EAX_BLOCK_SIZE
        };

        for chunk in data[..last_block_start].chunks_exact(EAX_BLOCK_SIZE) {
            let mut block = [0u8; EAX_BLOCK_SIZE];
            block.copy_from_slice(chunk);
            self.mac_block(&mut state, &block);
        }

        let mut last_block = [0u8; EAX_BLOCK_SIZE];
        let tail = &data[last_block_start..];
        last_block[..tail.len()].copy_from_slice(tail);
        if complete_last_block {
            for i in 0..EAX_BLOCK_SIZE {
                last_block[i] ^= self.subkey1[i];
            }
        } else {
            last_block[tail.len()] = 0x80;
            for i in 0..EAX_BLOCK_SIZE {
                last_block[i] ^= self.subkey2[i];
            }
        }
        self.mac_block(&mut state, &last_block);

        state
    }

    fn tag(
        &self,
        nonce_tag: &[u8; EAX_BLOCK_SIZE],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> [u8; TAG_SIZE] {
        let header_tag = self.omac(1, additional_data);
        let message_tag = self.omac(2, ciphertext);
        let mut tag = [0u8; TAG_SIZE];

        for i in 0..TAG_SIZE {
            tag[i] = nonce_tag[i] ^ header_tag[i] ^ message_tag[i];
        }

        tag
    }

    fn increment_counter(counter: &mut [u8; EAX_BLOCK_SIZE]) {
        for byte in counter.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }

    fn apply_ctr(&self, inout: &mut [u8], initial_counter: &[u8; EAX_BLOCK_SIZE]) {
        let mut counter = *initial_counter;
        for chunk in inout.chunks_mut(EAX_BLOCK_SIZE) {
            let mut mask = counter;
            self.cipher.encrypt_block(&mut mask);
            for i in 0..chunk.len() {
                chunk[i] ^= mask[i];
            }
            Self::increment_counter(&mut counter);
        }
    }

    fn validate_nonce(&self, nonce: &[u8]) -> CryptoResult<()> {
        if nonce.len() != self.nonce_size {
            return Err(CryptoError::InvalidNonceSize {
                expected: "configured nonce size",
                actual: nonce.len(),
            });
        }

        Ok(())
    }
}

impl<B: BlockCipher, const TAG_SIZE: usize> AeadUser for EaxImpl<B, TAG_SIZE> {
    fn nonce_size(&self) -> usize {
        self.nonce_size
    }

    fn tag_size(&self) -> usize {
        TAG_SIZE
    }
}

impl<B: BlockCipher, const TAG_SIZE: usize> Aead<TAG_SIZE> for EaxImpl<B, TAG_SIZE> {
    fn seal_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; TAG_SIZE]> {
        self.validate_nonce(nonce)?;

        let nonce_tag = self.omac(0, nonce);
        self.apply_ctr(inout, &nonce_tag);
        Ok(self.tag(&nonce_tag, inout, additional_data))
    }

    fn open_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        self.validate_nonce(nonce)?;
        if tag.len() != TAG_SIZE {
            return Err(CryptoError::InvalidTagSize {
                expected: "TAG_SIZE",
                actual: tag.len(),
            });
        }

        let nonce_tag = self.omac(0, nonce);
        let expected_tag = self.tag(&nonce_tag, inout, additional_data);
        if !constant_time_eq(&expected_tag, tag) {
            return Err(CryptoError::AuthenticationFailed);
        }

        self.apply_ctr(inout, &nonce_tag);
        Ok(())
    }
}

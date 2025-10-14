use crate::{block::aes::Aes, block::BlockCipher, modes::BlockMode, utils::subtle::xor::xor_bytes};

/// CBC decrypter structure
pub struct CBCDecrypter {
    block: Aes,
    iv: [u8; Aes::BLOCK_SIZE],
}

impl BlockMode for CBCDecrypter {
    /// Returns the block size
    fn block_size(&self) -> usize {
        Aes::BLOCK_SIZE
    }

    /// Decrypts multiple blocks
    ///
    /// # Arguments
    /// * `dst` - Output buffer
    /// * `src` - Input data
    ///
    /// # Panics
    /// * If input is not full blocks
    /// * If output buffer is smaller than input
    /// * If buffers have invalid overlap
    fn encrypt(&mut self, inout: &mut [u8]) {
        if inout.is_empty() {
            return;
        }

        self.crypt_blocks_dec(inout);
    }

    fn decrypt(&mut self, _inout: &mut [u8]) {
        unreachable!()
    }
}

impl CBCDecrypter {
    /// Creates a new CBC decrypter
    ///
    /// # Arguments
    /// * `block` - AES block cipher
    /// * `iv` - Initialization vector, must be 16 bytes
    pub fn new(block: Aes, iv: [u8; Aes::BLOCK_SIZE]) -> Self {
        Self { block, iv }
    }

    /// Generic CBC decryption function
    fn crypt_blocks_dec(&mut self, inout: &mut [u8]) {
        // For each block, we need to xor the decrypted data with the previous
        // block's ciphertext (the iv). To avoid making a copy each time, we loop
        // over the blocks backwards.
        let mut end = inout.len();
        let mut start = end - Aes::BLOCK_SIZE;

        // Copy the last block of ciphertext as the IV of the next call
        let iv = self.iv;
        if end >= Aes::BLOCK_SIZE {
            self.iv.copy_from_slice(&inout[start..end]);
        }

        while start < inout.len() {
            // Decrypt the block
            self.block.decrypt_block(&mut inout[start..end]);

            if start > 0 {
                let prev = start - Aes::BLOCK_SIZE;
                let src = inout.to_vec();
                xor_bytes(&mut inout[start..end], &src[prev..start]);
            } else {
                // The first block is special because it uses the saved iv
                xor_bytes(&mut inout[start..end], &iv);
            }

            if start == 0 {
                break;
            }

            end -= Aes::BLOCK_SIZE;
            start -= Aes::BLOCK_SIZE;
        }
    }
}

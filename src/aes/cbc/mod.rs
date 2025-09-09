use crate::{
    aes::{Aes, BLOCK_SIZE},
    cipher::{BlockCipher, BlockMode},
    utils::subtle::xor::xor_bytes,
};

/// CBC encryptor structure
pub struct CBCEncryptor {
    block: Aes,
    iv: [u8; BLOCK_SIZE],
}

impl BlockMode for CBCEncryptor {
    /// Returns the block size
    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    /// Encrypts multiple blocks
    ///
    /// # Arguments
    /// * `dst` - Output buffer
    /// * `src` - Input data
    ///
    /// # Panics
    /// * If input is not full blocks
    /// * If output buffer is smaller than input
    /// * If buffers have invalid overlap
    fn crypt_blocks(&mut self, inout: &mut [u8]) {
        if inout.is_empty() {
            return;
        }

        self.crypt_blocks_enc(inout);
    }
}

impl CBCEncryptor {
    /// Creates a new CBC encryptor
    ///
    /// # Arguments
    /// * `block` - AES block cipher
    /// * `iv` - Initialization vector, must be 16 bytes
    pub fn new(block: Aes, iv: [u8; BLOCK_SIZE]) -> Self {
        Self { block, iv }
    }

    /// Sets a new IV
    ///
    /// # Arguments
    /// * `iv` - New initialization vector
    ///
    /// # Panics
    /// * If IV length is incorrect
    pub fn set_iv(&mut self, iv: &[u8]) {
        if iv.len() != self.iv.len() {
            panic!("cipher: incorrect length IV");
        }
        self.iv.copy_from_slice(iv);
    }

    /// Generic CBC encryption function
    fn crypt_blocks_enc(&mut self, inout: &mut [u8]) {
        let inout_chunks = inout.chunks_exact_mut(BLOCK_SIZE);

        for dst_block in inout_chunks {
            // Write the xor to dst, then encrypt in place
            xor_bytes(dst_block, &self.iv);
            self.block.encrypt(dst_block);

            // Move to the next block with this block as the next iv
            self.iv.copy_from_slice(dst_block);
        }
    }
}

/// CBC decrypter structure
pub struct CBCDecrypter {
    block: Aes,
    iv: [u8; BLOCK_SIZE],
}

impl BlockMode for CBCDecrypter {
    /// Returns the block size
    fn block_size(&self) -> usize {
        BLOCK_SIZE
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
    fn crypt_blocks(&mut self, inout: &mut [u8]) {
        if inout.is_empty() {
            return;
        }

        self.crypt_blocks_dec(inout);
    }
}

impl CBCDecrypter {
    /// Creates a new CBC decrypter
    ///
    /// # Arguments
    /// * `block` - AES block cipher
    /// * `iv` - Initialization vector, must be 16 bytes
    pub fn new(block: Aes, iv: [u8; BLOCK_SIZE]) -> Self {
        Self { block, iv }
    }

    /// Sets a new IV
    ///
    /// # Arguments
    /// * `iv` - New initialization vector
    ///
    /// # Panics
    /// * If IV length is incorrect
    pub fn set_iv(&mut self, iv: &[u8]) {
        if iv.len() != self.iv.len() {
            panic!("cipher: incorrect length IV");
        }
        self.iv.copy_from_slice(iv);
    }

    /// Generic CBC decryption function
    fn crypt_blocks_dec(&mut self, inout: &mut [u8]) {
        // For each block, we need to xor the decrypted data with the previous
        // block's ciphertext (the iv). To avoid making a copy each time, we loop
        // over the blocks backwards.
        let mut end = inout.len();
        let mut start = end - BLOCK_SIZE;

        // Copy the last block of ciphertext as the IV of the next call
        let iv = self.iv;
        if end >= BLOCK_SIZE {
            self.iv.copy_from_slice(&inout[start..end]);
        }

        while start < inout.len() {
            // Decrypt the block
            self.block.decrypt(&mut inout[start..end]);

            if start > 0 {
                let prev = start - BLOCK_SIZE;
                let src = inout.to_vec();
                xor_bytes(&mut inout[start..end], &src[prev..start]);
            } else {
                // The first block is special because it uses the saved iv
                xor_bytes(&mut inout[start..end], &iv);
            }

            if start == 0 {
                break;
            }

            end -= BLOCK_SIZE;
            start -= BLOCK_SIZE;
        }
    }
}

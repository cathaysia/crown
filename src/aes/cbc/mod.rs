use crate::{
    aes::{Aes, BLOCK_SIZE},
    cipher::{BlockCipher, BlockMode},
    subtle::xor::xor_bytes,
    utils::inexact_overlap,
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
    fn crypt_blocks(mut self, dst: &mut [u8], src: &[u8]) {
        if src.len() % BLOCK_SIZE != 0 {
            panic!("crypto/cipher: input not full blocks");
        }
        if dst.len() < src.len() {
            panic!("crypto/cipher: output smaller than input");
        }
        if inexact_overlap(&dst[..src.len()], src) {
            panic!("crypto/cipher: invalid buffer overlap");
        }

        if src.is_empty() {
            return;
        }

        self.crypt_blocks_enc(dst, src);
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
    fn crypt_blocks_enc(&mut self, dst: &mut [u8], src: &[u8]) {
        let src_chunks = src.chunks_exact(BLOCK_SIZE);
        let dst_chunks = dst.chunks_exact_mut(BLOCK_SIZE);

        for (src_block, dst_block) in src_chunks.zip(dst_chunks) {
            // Write the xor to dst, then encrypt in place
            xor_bytes(dst_block, src_block, &self.iv);
            let src = dst_block.to_vec();
            self.block.encrypt(dst_block, &src);

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
    fn crypt_blocks(mut self, dst: &mut [u8], src: &[u8]) {
        if src.len() % BLOCK_SIZE != 0 {
            panic!("crypto/cipher: input not full blocks");
        }
        if dst.len() < src.len() {
            panic!("crypto/cipher: output smaller than input");
        }
        if inexact_overlap(&dst[..src.len()], src) {
            panic!("crypto/cipher: invalid buffer overlap");
        }

        if src.is_empty() {
            return;
        }

        self.crypt_blocks_dec(dst, src);
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
    fn crypt_blocks_dec(&mut self, dst: &mut [u8], src: &[u8]) {
        // For each block, we need to xor the decrypted data with the previous
        // block's ciphertext (the iv). To avoid making a copy each time, we loop
        // over the blocks backwards.
        let mut end = src.len();
        let mut start = end - BLOCK_SIZE;

        // Copy the last block of ciphertext as the IV of the next call
        let iv = self.iv;
        if end >= BLOCK_SIZE {
            self.iv.copy_from_slice(&src[start..end]);
        }

        while start < src.len() {
            // Decrypt the block
            self.block.decrypt(&mut dst[start..end], &src[start..end]);

            let dst1 = dst[start..end].to_vec();
            if start > 0 {
                let prev = start - BLOCK_SIZE;
                xor_bytes(&mut dst[start..end], &dst1, &src[prev..start]);
            } else {
                // The first block is special because it uses the saved iv
                xor_bytes(&mut dst[start..end], &dst1, &iv);
            }

            if start == 0 {
                break;
            }

            end -= BLOCK_SIZE;
            start -= BLOCK_SIZE;
        }
    }
}

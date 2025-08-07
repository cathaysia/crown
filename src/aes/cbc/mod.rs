use crate::{
    aes::{Block, BLOCK_SIZE},
    subtle::xor::xor_bytes,
    utils::{copy, inexact_overlap},
};

/// CBC encryptor structure
pub struct CBCEncryptor {
    block: Block,
    iv: [u8; BLOCK_SIZE],
}

impl CBCEncryptor {
    /// Creates a new CBC encryptor
    ///
    /// # Arguments
    /// * `block` - AES block cipher
    /// * `iv` - Initialization vector, must be 16 bytes
    pub fn new(block: Block, iv: [u8; BLOCK_SIZE]) -> Self {
        Self { block, iv }
    }

    /// Returns the block size
    pub fn block_size(&self) -> usize {
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
    pub fn crypt_blocks(&mut self, dst: &mut [u8], src: &[u8]) {
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

        crypt_blocks_enc(&mut self.block, &mut self.iv, dst, src);
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
}

/// CBC decrypter structure
pub struct CBCDecrypter {
    block: Block,
    iv: [u8; BLOCK_SIZE],
}

impl CBCDecrypter {
    /// Creates a new CBC decrypter
    ///
    /// # Arguments
    /// * `block` - AES block cipher
    /// * `iv` - Initialization vector, must be 16 bytes
    pub fn new(block: Block, iv: [u8; BLOCK_SIZE]) -> Self {
        Self { block, iv }
    }

    /// Returns the block size
    pub fn block_size(&self) -> usize {
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
    pub fn crypt_blocks(&mut self, dst: &mut [u8], src: &[u8]) {
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

        crypt_blocks_dec(&mut self.block, &mut self.iv, dst, src);
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
}

/// Generic CBC encryption function
fn crypt_blocks_enc(block: &mut Block, civ: &mut [u8; BLOCK_SIZE], dst: &mut [u8], src: &[u8]) {
    let mut iv = civ.to_vec();
    let src_chunks = src.chunks_exact(BLOCK_SIZE);
    let dst_chunks = dst.chunks_exact_mut(BLOCK_SIZE);

    for (src_block, dst_block) in src_chunks.zip(dst_chunks) {
        // Write the xor to dst, then encrypt in place
        xor_bytes(dst_block, src_block, &iv);
        let src = dst_block.to_vec();
        block.encrypt(dst_block, &src);

        // Move to the next block with this block as the next iv
        iv = dst_block.to_vec();
    }

    // Save the iv for the next CryptBlocks call
    copy(civ, &iv);
}

/// Generic CBC decryption function
fn crypt_blocks_dec(block: &mut Block, civ: &mut [u8; BLOCK_SIZE], dst: &mut [u8], src: &[u8]) {
    // For each block, we need to xor the decrypted data with the previous
    // block's ciphertext (the iv). To avoid making a copy each time, we loop
    // over the blocks backwards.
    let mut end = src.len();
    let mut start = end - BLOCK_SIZE;

    // Copy the last block of ciphertext as the IV of the next call
    let iv = *civ;
    if end >= BLOCK_SIZE {
        civ.copy_from_slice(&src[start..end]);
    }

    while start < src.len() {
        // Decrypt the block
        block.decrypt(&mut dst[start..end], &src[start..end]);

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

/// Creates a new CBC encryptor
///
/// # Arguments
/// * `block` - AES block cipher
/// * `iv` - Initialization vector
///
/// # Returns
/// * New CBC encryptor instance
pub fn new_cbc_encryptor(block: Block, iv: [u8; BLOCK_SIZE]) -> CBCEncryptor {
    CBCEncryptor::new(block, iv)
}

/// Creates a new CBC decrypter
///
/// # Arguments
/// * `block` - AES block cipher
/// * `iv` - Initialization vector
///
/// # Returns
/// * New CBC decrypter instance
pub fn new_cbc_decrypter(block: Block, iv: [u8; BLOCK_SIZE]) -> CBCDecrypter {
    CBCDecrypter::new(block, iv)
}

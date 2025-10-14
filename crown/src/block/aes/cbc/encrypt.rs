use crate::{block::aes::Aes, block::BlockCipher, modes::BlockMode, utils::subtle::xor::xor_bytes};
/// CBC encryptor structure
pub struct CBCEncryptor {
    block: Aes,
    iv: [u8; Aes::BLOCK_SIZE],
}

impl BlockMode for CBCEncryptor {
    /// Returns the block size
    fn block_size(&self) -> usize {
        Aes::BLOCK_SIZE
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
    fn encrypt(&mut self, inout: &mut [u8]) {
        if inout.is_empty() {
            return;
        }

        self.crypt_blocks_enc(inout);
    }

    fn decrypt(&mut self, _inout: &mut [u8]) {
        unreachable!()
    }
}

impl CBCEncryptor {
    /// Creates a new CBC encryptor
    ///
    /// # Arguments
    /// * `block` - AES block cipher
    /// * `iv` - Initialization vector, must be 16 bytes
    pub fn new(block: Aes, iv: [u8; Aes::BLOCK_SIZE]) -> Self {
        Self { block, iv }
    }

    /// Generic CBC encryption function
    fn crypt_blocks_enc(&mut self, inout: &mut [u8]) {
        let inout_chunks = inout.chunks_exact_mut(Aes::BLOCK_SIZE);

        for dst_block in inout_chunks {
            // Write the xor to dst, then encrypt in place
            xor_bytes(dst_block, &self.iv);
            self.block.encrypt_block(dst_block);

            // Move to the next block with this block as the next iv
            self.iv.copy_from_slice(dst_block);
        }
    }
}

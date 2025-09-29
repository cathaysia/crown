use super::super::Chacha20;

extern "C" {
    /// ChaCha20 counter mode encryption/decryption
    ///
    /// # Parameters
    /// - `out`: Output buffer
    /// - `inp`: Input buffer
    /// - `len`: Length of data to process
    /// - `key`: 32-byte key
    /// - `counter`: 16-byte counter (4 bytes counter + 12 bytes nonce)
    fn ChaCha20_ctr32(out: *mut u8, inp: *const u8, len: usize, key: *const u8, counter: *const u8);

    /// ChaCha20 counter mode encryption/decryption using SVE
    ///
    /// # Parameters
    /// - `out`: Output buffer
    /// - `inp`: Input buffer
    /// - `len`: Length of data to process
    /// - `key`: 32-byte key
    /// - `counter`: 16-byte counter (4 bytes counter + 12 bytes nonce)
    #[allow(dead_code)]
    fn ChaCha20_ctr32_sve(
        out: *mut u8,
        inp: *const u8,
        len: usize,
        key: *const u8,
        counter: *const u8,
    );
}

impl Chacha20 {
    pub(crate) fn xor_key_stream_blocks(&mut self, inout: &mut [u8]) {
        // Check if we should use assembly implementation
        if inout.len() >= 192 {
            self.xor_key_stream_blocks_asm(inout);
        } else {
            self.xor_key_stream_blocks_generic(inout);
        }
    }

    fn xor_key_stream_blocks_asm(&mut self, inout: &mut [u8]) {
        // Prepare the key in the format expected by the assembly function
        let mut key_bytes = [0u8; 32];
        for (i, &word) in self.key.iter().enumerate() {
            let bytes = word.to_le_bytes();
            key_bytes[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }

        // Prepare the counter + nonce in the format expected by the assembly function
        let mut counter_nonce = [0u8; 16];

        // Counter (4 bytes)
        counter_nonce[0..4].copy_from_slice(&self.counter.to_le_bytes());

        // Nonce (12 bytes)
        for (i, &word) in self.nonce.iter().enumerate() {
            let bytes = word.to_le_bytes();
            counter_nonce[4 + i * 4..4 + (i + 1) * 4].copy_from_slice(&bytes);
        }

        let len = inout.len();
        let blocks = len / 64;

        unsafe {
            ChaCha20_ctr32(
                inout.as_mut_ptr(),
                inout.as_ptr(),
                len,
                key_bytes.as_ptr(),
                counter_nonce.as_ptr(),
            );
        }

        // Update the counter for the number of blocks processed
        self.counter = self.counter.wrapping_add(blocks as u32);
    }
}

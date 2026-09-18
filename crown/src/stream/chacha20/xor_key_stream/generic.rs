use super::super::Chacha20;

impl Chacha20 {
    pub(crate) fn xor_key_stream_blocks(&mut self, inout: &mut [u8]) {
        #[cfg(all(feature = "asm", target_arch = "x86_64"))]
        {
            super::asm::xor_key_stream_blocks(self, inout);
        }

        #[cfg(any(not(feature = "asm"), not(target_arch = "x86_64")))]
        {
            self.xor_key_stream_blocks_generic(inout);
        }
    }
}

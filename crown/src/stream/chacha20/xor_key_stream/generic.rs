use super::super::Chacha20;

impl Chacha20 {
    pub(crate) fn xor_key_stream_blocks(&mut self, inout: &mut [u8]) {
        #[cfg(any(
            all(feature = "asm", target_arch = "x86_64"),
            crown_aarch64_asm,
            crown_riscv64_asm
        ))]
        {
            // riscv64 has only the vector body, entered under the same
            // conditions `chacha_riscv.c` uses.
            #[cfg(crown_riscv64_asm)]
            if !super::asm::supported(inout) {
                self.xor_key_stream_blocks_generic(inout);
                return;
            }
            super::asm::xor_key_stream_blocks(self, inout);
        }

        #[cfg(not(any(
            all(feature = "asm", target_arch = "x86_64"),
            crown_aarch64_asm,
            crown_riscv64_asm
        )))]
        {
            self.xor_key_stream_blocks_generic(inout);
        }
    }
}

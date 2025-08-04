use super::*;

impl Cipher {
    pub(super) fn xor_key_stream_blocks(&mut self, dst: &mut [u8], src: &[u8]) {
        self.xor_key_stream_blocks_generic(dst, src);
    }
}

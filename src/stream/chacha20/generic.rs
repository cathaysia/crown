use super::*;

impl Chacha20 {
    pub(super) fn xor_key_stream_blocks(&mut self, inout: &mut [u8]) {
        self.xor_key_stream_blocks_generic(inout);
    }
}

pub use super::*;
pub use crate::block::aes::*;

pub fn ctr_blocks_1(block: &Aes, inout: &mut [u8], iv_low: u64, iv_high: u64) {
    ctr_blocks(block, inout, iv_low, iv_high);
}

pub fn ctr_blocks_2(block: &Aes, inout: &mut [u8], iv_low: u64, iv_high: u64) {
    ctr_blocks(block, inout, iv_low, iv_high);
}

pub fn ctr_blocks_4(block: &Aes, inout: &mut [u8], iv_low: u64, iv_high: u64) {
    ctr_blocks(block, inout, iv_low, iv_high);
}

pub fn ctr_blocks_8(block: &Aes, inout: &mut [u8], iv_low: u64, iv_high: u64) {
    ctr_blocks(block, inout, iv_low, iv_high);
}

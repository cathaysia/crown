pub use super::*;
pub use crate::aes::*;

pub fn ctr_blocks_1(
    block: &Block,
    destination: &mut [u8],
    source: &[u8],
    iv_low: u64,
    iv_high: u64,
) {
    ctr_blocks(block, destination, source, iv_low, iv_high);
}

pub fn ctr_blocks_2(
    block: &Block,
    destination: &mut [u8],
    source: &[u8],
    iv_low: u64,
    iv_high: u64,
) {
    ctr_blocks(block, destination, source, iv_low, iv_high);
}

pub fn ctr_blocks_4(
    block: &Block,
    destination: &mut [u8],
    source: &[u8],
    iv_low: u64,
    iv_high: u64,
) {
    ctr_blocks(block, destination, source, iv_low, iv_high);
}

pub fn ctr_blocks_8(
    block: &Block,
    destination: &mut [u8],
    source: &[u8],
    iv_low: u64,
    iv_high: u64,
) {
    ctr_blocks(block, destination, source, iv_low, iv_high);
}

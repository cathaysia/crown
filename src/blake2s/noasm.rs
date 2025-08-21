use super::generic;

pub fn hash_blocks(h: &mut [u32; 8], c: &mut [u32; 2], flag: u32, blocks: &[u8]) {
    generic::hash_blocks_generic(h, c, flag, blocks);
}

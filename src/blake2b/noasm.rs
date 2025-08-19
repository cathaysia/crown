use crate::blake2b::generic;

pub fn hash_blocks(h: &mut [u64; 8], c: &mut [u64; 2], flag: u64, blocks: &[u8]) {
    generic::hash_blocks_generic(h, c, flag, blocks);
}

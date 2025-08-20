use super::blamka_generic::process_block_generic;
use super::Block;

pub fn process_block(out: &mut Block, in1: &Block, in2: &Block) {
    process_block_generic(out, in1, in2, false);
}

pub fn process_block_xor(out: &mut Block, in1: &Block, in2: &Block) {
    process_block_generic(out, in1, in2, true);
}

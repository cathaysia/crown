use super::{block::block_generic, Sha1};

pub fn block(dig: &mut Sha1, p: &[u8]) {
    block_generic(dig, p);
}

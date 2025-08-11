use crate::aes::{generic, Aes};

pub(crate) fn encrypt_block(c: &Aes, dst: &mut [u8], src: &[u8]) {
    generic::encrypt_block_generic(&c.block, dst, src);
}

pub(crate) fn decrypt_block(c: &Aes, dst: &mut [u8], src: &[u8]) {
    generic::decrypt_block_generic(&c.block, dst, src);
}

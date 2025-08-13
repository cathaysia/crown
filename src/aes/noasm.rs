use crate::aes::{generic, Aes};

pub(crate) fn encrypt_block(c: &Aes, inout: &mut [u8]) {
    generic::encrypt_block_generic(&c.block, inout);
}

pub(crate) fn decrypt_block(c: &Aes, inout: &mut [u8]) {
    generic::decrypt_block_generic(&c.block, inout);
}

use crate::aes::{generic, AesCipher};

pub(crate) fn encrypt_block(c: &AesCipher, dst: &mut [u8], src: &[u8]) {
    generic::encrypt_block_generic(&c.block, dst, src);
}

pub(crate) fn decrypt_block(c: &AesCipher, dst: &mut [u8], src: &[u8]) {
    generic::decrypt_block_generic(&c.block, dst, src);
}

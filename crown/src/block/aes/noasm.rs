use crate::block::aes::{generic, Aes};

// The OpenSSL vpaes/aesni block routines compiled through asm.rs are wired
// here once a suitable key-schedule format is chosen; vpaes keeps its keys in
// a transformed domain produced by vpaes_set_*_key, while aesni consumes the
// standard FIPS-197 schedule (crown's enc limb) directly.

pub(crate) fn encrypt_block(c: &Aes, inout: &mut [u8]) {
    generic::encrypt_block_generic(&c.block, inout);
}

pub(crate) fn decrypt_block(c: &Aes, inout: &mut [u8]) {
    generic::decrypt_block_generic(&c.block, inout);
}

use crate::{aes::gcm::GCM, error::CryptoResult};

pub fn seal(out: &mut [u8], g: &GCM, nonce: &[u8], plaintext: &[u8], additional_data: &[u8]) {
    super::generic::seal_generic(out, g, nonce, plaintext, additional_data);
}

pub fn open(
    out: &mut [u8],
    g: &GCM,
    nonce: &[u8],
    ciphertext: &[u8],
    additional_data: &[u8],
) -> CryptoResult<()> {
    super::generic::open_generic(out, g, nonce, ciphertext, additional_data)
}

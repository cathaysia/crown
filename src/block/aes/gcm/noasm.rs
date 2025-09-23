use crate::{
    block::aes::gcm::{Gcm, GCM_TAG_SIZE},
    error::CryptoResult,
};

pub fn seal<const N: usize, const T: usize>(
    inout: &mut [u8],
    g: &Gcm<N, T>,
    nonce: &[u8],
    additional_data: &[u8],
) -> [u8; GCM_TAG_SIZE] {
    super::generic::seal_generic::<N, T>(inout, g, nonce, additional_data)
}

pub fn open<const N: usize, const T: usize>(
    inout: &mut [u8],
    g: &Gcm<N, T>,
    nonce: &[u8],
    additional_data: &[u8],
    tag: &[u8],
) -> CryptoResult<()> {
    super::generic::open_generic::<N, T>(inout, g, nonce, additional_data, tag)
}

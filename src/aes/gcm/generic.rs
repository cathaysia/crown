use super::ghash::ghash;
use super::*;
use crate::aes::Aes;
use crate::error::{CryptoError, CryptoResult};
use crate::subtle::xor::xor_bytes;
use crate::utils::{constant_time_eq, copy};

const GCM_BLOCK_SIZE: usize = 16;
const GCM_TAG_SIZE: usize = 16;
const GCM_STANDARD_NONCE_SIZE: usize = 12;

pub fn seal_generic(
    out: &mut [u8],
    g: &GCM,
    nonce: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
) {
    let mut h = [0u8; GCM_BLOCK_SIZE];
    let mut counter = [0u8; GCM_BLOCK_SIZE];
    let mut tag_mask = [0u8; GCM_BLOCK_SIZE];

    g.cipher.encrypt_block_internal(&mut h);
    derive_counter_generic(&h, &mut counter, nonce);
    {
        let src = tag_mask;
        gcm_counter_crypt_generic(&g.cipher, &mut tag_mask, &src, &mut counter);
    }

    gcm_counter_crypt_generic(
        &g.cipher,
        &mut out[..plaintext.len()],
        plaintext,
        &mut counter,
    );

    let mut tag = [0u8; GCM_TAG_SIZE];
    gcm_auth_generic(
        &mut tag,
        &h,
        &tag_mask,
        &out[..plaintext.len()],
        additional_data,
    );
    out[plaintext.len()..plaintext.len() + tag.len()].copy_from_slice(&tag);
}

pub fn open_generic(
    out: &mut [u8],
    g: &GCM,
    nonce: &[u8],
    ciphertext: &[u8],
    additional_data: &[u8],
) -> CryptoResult<()> {
    let mut h = [0u8; GCM_BLOCK_SIZE];
    let mut counter = [0u8; GCM_BLOCK_SIZE];
    let mut tag_mask = [0u8; GCM_BLOCK_SIZE];

    g.cipher.encrypt_block_internal(&mut h);
    derive_counter_generic(&h, &mut counter, nonce);
    {
        let src = tag_mask;
        gcm_counter_crypt_generic(&g.cipher, &mut tag_mask, &src, &mut counter);
    }

    let tag = &ciphertext[ciphertext.len() - g.tag_size..];
    let ciphertext = &ciphertext[..ciphertext.len() - g.tag_size];

    let mut expected_tag = [0u8; GCM_TAG_SIZE];
    gcm_auth_generic(
        &mut expected_tag,
        &h,
        &tag_mask,
        ciphertext,
        additional_data,
    );

    if !constant_time_eq(&expected_tag[..g.tag_size], tag) {
        return Err(CryptoError::AuthenticationFailed);
    }

    gcm_counter_crypt_generic(&g.cipher, out, ciphertext, &mut counter);

    Ok(())
}

// deriveCounterGeneric computes the initial GCM counter state from the given nonce.
// See NIST SP 800-38D, section 7.1. This assumes that counter is filled with
// zeros on entry.
fn derive_counter_generic(
    h: &[u8; GCM_BLOCK_SIZE],
    counter: &mut [u8; GCM_BLOCK_SIZE],
    nonce: &[u8],
) {
    // GCM has two modes of operation with respect to the initial counter
    // state: a "fast path" for 96-bit (12-byte) nonces, and a "slow path"
    // for nonces of other lengths. For a 96-bit nonce, the nonce, along
    // with a four-byte big-endian counter starting at one, is used
    // directly as the starting counter. For other nonce sizes, the counter
    // is computed by passing it through the GHASH function.
    if nonce.len() == GCM_STANDARD_NONCE_SIZE {
        counter[..nonce.len()].copy_from_slice(nonce);
        counter[GCM_BLOCK_SIZE - 1] = 1;
    } else {
        let mut len_block = [0u8; 16];
        let nonce_len_bits = (nonce.len() as u64) * 8;
        len_block[8..].copy_from_slice(&nonce_len_bits.to_be_bytes());
        ghash(counter, h, &[nonce, &len_block]);
    }
}

// gcmCounterCryptGeneric encrypts src using AES in counter mode with 32-bit
// wrapping (which is different from AES-CTR) and places the result into out.
// counter is the initial value and will be updated with the next value.
fn gcm_counter_crypt_generic(
    b: &Aes,
    out: &mut [u8],
    src: &[u8],
    counter: &mut [u8; GCM_BLOCK_SIZE],
) {
    let mut mask = [0u8; GCM_BLOCK_SIZE];
    let mut src = src;
    let mut out = out;

    while src.len() >= GCM_BLOCK_SIZE {
        mask.copy_from_slice(counter);
        b.encrypt_block_internal(&mut mask);
        gcm_inc32(counter);

        copy(&mut out[..GCM_BLOCK_SIZE], &src[..GCM_BLOCK_SIZE]);
        xor_bytes(&mut out[..GCM_BLOCK_SIZE], &mask);
        out = &mut out[GCM_BLOCK_SIZE..];
        src = &src[GCM_BLOCK_SIZE..];
    }

    if !src.is_empty() {
        mask.copy_from_slice(counter);
        b.encrypt_block_internal(&mut mask);
        gcm_inc32(counter);
        copy(&mut out[..src.len()], src);
        xor_bytes(&mut out[..src.len()], &mask[..src.len()]);
    }
}

// gcmInc32 treats the final four bytes of counterBlock as a big-endian value
// and increments it.
fn gcm_inc32(counter_block: &mut [u8; GCM_BLOCK_SIZE]) {
    let len = counter_block.len();
    let ctr = &mut counter_block[len - 4..];
    let current = u32::from_be_bytes([ctr[0], ctr[1], ctr[2], ctr[3]]);
    let incremented = current.wrapping_add(1);
    ctr.copy_from_slice(&incremented.to_be_bytes());
}

// gcmAuthGeneric calculates GHASH(additionalData, ciphertext), masks the result
// with tagMask and writes the result to out.
fn gcm_auth_generic(
    out: &mut [u8],
    h: &[u8; GCM_BLOCK_SIZE],
    tag_mask: &[u8; GCM_BLOCK_SIZE],
    ciphertext: &[u8],
    additional_data: &[u8],
) {
    let mut len_block = [0u8; 16];
    let ad_len_bits = (additional_data.len() as u64) * 8;
    let ct_len_bits = (ciphertext.len() as u64) * 8;
    len_block[..8].copy_from_slice(&ad_len_bits.to_be_bytes());
    len_block[8..].copy_from_slice(&ct_len_bits.to_be_bytes());

    let mut s = [0u8; GCM_BLOCK_SIZE];
    ghash(&mut s, h, &[additional_data, ciphertext, &len_block]);
    copy(out, &s);
    xor_bytes(out, tag_mask);
}

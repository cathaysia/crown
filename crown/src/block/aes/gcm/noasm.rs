use super::generic::derive_counter_generic;
use super::generic::gcm_counter_crypt_generic;
use super::generic::gcm_inc32;
use super::ghash::ghash_absorb;
use super::*;
use crate::error::CryptoResult;
use crate::utils::subtle::xor::xor_bytes;
use crate::utils::subtle::constant_time_eq;

pub fn seal<const N: usize, const T: usize>(
    inout: &mut [u8],
    g: &Gcm<N, T>,
    nonce: &[u8],
    additional_data: &[u8],
) -> [u8; GCM_TAG_SIZE] {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        if let Some(tag) = seal_stitch(inout, g, nonce, additional_data) {
            return tag;
        }
    }
    super::generic::seal_generic::<N, T>(inout, g, nonce, additional_data)
}

pub fn open<const N: usize, const T: usize>(
    inout: &mut [u8],
    g: &Gcm<N, T>,
    nonce: &[u8],
    additional_data: &[u8],
    tag: &[u8],
) -> CryptoResult<()> {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        if let Some(r) = open_stitch(inout, g, nonce, additional_data, tag) {
            return r;
        }
    }
    super::generic::open_generic::<N, T>(inout, g, nonce, additional_data, tag)
}

/// Length block for GHASH: ad_bits || ct_bits (big-endian u64s).
fn length_block(additional_data: &[u8], ct_len: usize) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&((additional_data.len() as u64) * 8).to_be_bytes());
    b[8..].copy_from_slice(&((ct_len as u64) * 8).to_be_bytes());
    b
}

/// Encrypt `inout` with the fused AES-NI+GHASH stitch over the bulk of the
/// message. Returns `None` when the CPU or the message is too small, in
/// which case the caller uses the portable path.
///
/// The stitch processes `len & !95` bytes (a multiple of 96) and returns
/// that count; the tail is finished in software. `ctx.xi` is the running
/// GHASH over ciphertext, in the same representation as software GHASH.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
fn seal_stitch<const N: usize, const T: usize>(
    inout: &mut [u8],
    g: &Gcm<N, T>,
    nonce: &[u8],
    additional_data: &[u8],
) -> Option<[u8; GCM_TAG_SIZE]> {
    use crate::aead::gcm::aesni;
    if !(aesni::aesni_supported() && aesni::avx_supported()) {
        return None;
    }
    // The fused encrypt body needs at least 0x60*3 bytes to engage.
    if inout.len() < 288 {
        return None;
    }

    let mut h = [0u8; 16];
    g.cipher.encrypt_block_internal(&mut h);
    let mut counter = [0u8; 16];
    derive_counter_generic(&h, &mut counter, nonce);

    // tag_mask = E(K, J0); counter advances to J0+1 for the message.
    let mut tag_mask = [0u8; 16];
    gcm_counter_crypt_generic(&g.cipher, &mut tag_mask, &mut counter);

    let mut ctx = aesni::init_ctx(&h);
    ghash_absorb(&mut ctx.xi, &h, &[additional_data]);

    let (sched, _) = g.cipher.enc_schedule();
    let key = aesni::AesKey {
        rd_key: sched.rd_key,
        rounds: sched.rounds,
    };

    let n = aesni::encrypt_inplace(&key, inout, &mut counter, &mut ctx);
    if n == 0 {
        return None;
    }

    // Software tail: remaining bytes of CTR and GHASH.
    let tail = &mut inout[n..];
    if !tail.is_empty() {
        let mut mask = [0u8; 16];
        let mut t = tail;
        while !t.is_empty() {
            mask.copy_from_slice(&counter);
            g.cipher.encrypt_block_internal(&mut mask);
            gcm_inc32(&mut counter);
            let k = t.len().min(16);
            xor_bytes(&mut t[..k], &mask[..k]);
            t = &mut t[k..];
        }
        ghash_absorb(&mut ctx.xi, &h, &[&inout[n..]]);
    }

    let lb = length_block(additional_data, inout.len());
    ghash_absorb(&mut ctx.xi, &h, &[&lb]);

    let mut tag = [0u8; GCM_TAG_SIZE];
    for i in 0..GCM_TAG_SIZE {
        tag[i] = ctx.xi[i] ^ tag_mask[i];
    }
    let _ = T;
    Some(tag)
}

/// Decrypt + verify with the stitch. `None` falls back to the portable path.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
fn open_stitch<const N: usize, const T: usize>(
    inout: &mut [u8],
    g: &Gcm<N, T>,
    nonce: &[u8],
    additional_data: &[u8],
    tag: &[u8],
) -> Option<CryptoResult<()>> {
    use crate::aead::gcm::aesni;
    if !(aesni::aesni_supported() && aesni::avx_supported()) {
        return None;
    }
    if inout.len() < 96 {
        return None;
    }

    let mut h = [0u8; 16];
    g.cipher.encrypt_block_internal(&mut h);
    let mut counter = [0u8; 16];
    derive_counter_generic(&h, &mut counter, nonce);

    let mut tag_mask = [0u8; 16];
    gcm_counter_crypt_generic(&g.cipher, &mut tag_mask, &mut counter);

    let mut ctx = aesni::init_ctx(&h);
    ghash_absorb(&mut ctx.xi, &h, &[additional_data]);

    let (sched, _) = g.cipher.enc_schedule();
    let key = aesni::AesKey {
        rd_key: sched.rd_key,
        rounds: sched.rounds,
    };

    let n = aesni::decrypt_inplace(&key, inout, &mut counter, &mut ctx);
    if n == 0 {
        return None;
    }

    let tail = &mut inout[n..];
    if !tail.is_empty() {
        // Decrypt tail in software (GHASH is over ciphertext, so hash the
        // ciphertext side while decrypting).
        let ct_tail = tail.to_vec();
        let mut mask = [0u8; 16];
        let mut t = tail;
        let mut off = 0;
        while !t.is_empty() {
            mask.copy_from_slice(&counter);
            g.cipher.encrypt_block_internal(&mut mask);
            gcm_inc32(&mut counter);
            let k = t.len().min(16);
            xor_bytes(&mut t[..k], &mask[..k]);
            t = &mut t[k..];
            off += k;
        }
        let _ = off;
        ghash_absorb(&mut ctx.xi, &h, &[&ct_tail]);
    }

    let lb = length_block(additional_data, inout.len());
    ghash_absorb(&mut ctx.xi, &h, &[&lb]);

    let mut expected = [0u8; GCM_TAG_SIZE];
    for i in 0..GCM_TAG_SIZE {
        expected[i] = ctx.xi[i] ^ tag_mask[i];
    }
    if !constant_time_eq(&expected[..T], &tag[..T.min(tag.len())]) {
        return Some(Err(crate::error::CryptoError::AuthenticationFailed));
    }
    Some(Ok(()))
}

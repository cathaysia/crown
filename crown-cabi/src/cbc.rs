//! Raw CBC mode without padding.
//!
//! `EvpBlockCipher` always applies PKCS#7 padding, which is wrong for
//! protocols that do their own packet padding (SSH being the canonical
//! example). These exports wrap `modes::cbc` directly so the caller sees a
//! pure streaming CBC transform that keeps its chaining state across calls.

use super::*;
use crown::block::aes::Aes;
use crown::block::BlockCipher;
use crown::modes::cbc::{CbcDecryptor, CbcEncryptor};
use crown::modes::BlockMode;

/// CBC chaining state, in the requested direction.
pub struct CbcHandle {
    mode: Direction,
    block_size: usize,
}

enum Direction {
    Encrypt(Box<dyn BlockMode>),
    Decrypt(Box<dyn BlockMode>),
}

fn to_encrypt<B>(cipher: B, iv: &[u8]) -> Box<dyn BlockMode>
where
    B: BlockCipher + CbcEncryptor<B> + 'static,
{
    Box::new(cipher.to_cbc_enc(iv))
}

fn to_decrypt<B>(cipher: B, iv: &[u8]) -> Box<dyn BlockMode>
where
    B: BlockCipher + CbcDecryptor<B> + 'static,
{
    Box::new(cipher.to_cbc_dec(iv))
}

/// Create an AES-CBC transform. `key` selects the variant (16/24/32 bytes)
/// and `iv` must be 16 bytes. `encrypt` is non-zero for the encryption
/// direction.
///
/// Returns NULL on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_cbc_new_aes(
    key: *const u8,
    key_len: usize,
    iv: *const u8,
    iv_len: usize,
    encrypt: i32,
) -> *mut CbcHandle {
    let (Some(key), Some(iv)) = (unsafe { slice_from_raw_parts(key, key_len) }, unsafe {
        slice_from_raw_parts(iv, iv_len)
    }) else {
        return std::ptr::null_mut();
    };
    if iv.len() != 16 {
        return std::ptr::null_mut();
    }
    let mode = if encrypt != 0 {
        let Ok(cipher) = Aes::new(key) else {
            return std::ptr::null_mut();
        };
        Direction::Encrypt(to_encrypt(cipher, iv))
    } else {
        let Ok(cipher) = Aes::new(key) else {
            return std::ptr::null_mut();
        };
        Direction::Decrypt(to_decrypt(cipher, iv))
    };
    Box::into_raw(Box::new(CbcHandle {
        mode,
        block_size: 16,
    }))
}

/// Release a CBC transform. NULL is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_cbc_free(c: *mut CbcHandle) {
    if !c.is_null() {
        drop(unsafe { Box::from_raw(c) });
    }
}

/// Block size of the transform in bytes (16 for AES).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_cbc_block_size(c: *const CbcHandle) -> usize {
    if c.is_null() {
        return 0;
    }
    unsafe { (*c).block_size }
}

/// Transform `len` bytes in place. `len` must be a non-zero multiple of the
/// block size; the chaining state carries over to the next call.
///
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crown_cbc_crypt(c: *mut CbcHandle, data: *mut u8, len: usize) -> i32 {
    if c.is_null() || (data.is_null() && len != 0) {
        return -1;
    }
    let handle = unsafe { &mut *c };
    if len == 0 || !len.is_multiple_of(handle.block_size) {
        return -1;
    }
    let buf = unsafe { std::slice::from_raw_parts_mut(data, len) };
    match &mut handle.mode {
        // crown's CBC objects carry the transform in `encrypt()`; the
        // decrypter's `decrypt()` is `unreachable!()` (see
        // envelope::evp_block::block_mode, which calls `dec.encrypt`).
        Direction::Encrypt(m) => m.encrypt(buf),
        Direction::Decrypt(m) => m.encrypt(buf),
    }
    0
}

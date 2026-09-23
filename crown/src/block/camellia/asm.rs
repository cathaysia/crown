//! Camellia assembly implementation for x86_64.
//!
//! `Camellia_Ekeygen` expands a raw key into OpenSSL's `KEY_TABLE_TYPE`
//! (272 bytes of packed subkeys). `Camellia_EncryptBlock_Rounds` /
//! `Camellia_DecryptBlock_Rounds` consume that table plus the grand-round
//! count returned by Ekeygen (3 for 128-bit keys, 4 for 192/256-bit).

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/camellia/x86_64.ts"),
    options(att_syntax)
);

/// KEY_TABLE_TYPE is 272 bytes / 4.
pub const KEY_TABLE_WORDS: usize = 272 / 4;

extern "C" {
    fn Camellia_Ekeygen(key_bit_length: i32, raw_key: *const u8, key_table: *mut u32) -> i32;
    fn Camellia_EncryptBlock_Rounds(
        grand_rounds: i32,
        plaintext: *const u8,
        key_table: *const u32,
        ciphertext: *mut u8,
    );
    fn Camellia_DecryptBlock_Rounds(
        grand_rounds: i32,
        ciphertext: *const u8,
        key_table: *const u32,
        plaintext: *mut u8,
    );
}

/// Expand `raw_key` into `key_table`. Returns the grand-round count.
pub fn ekeygen(raw_key: &[u8], key_table: &mut [u32]) -> i32 {
    debug_assert_eq!(key_table.len(), KEY_TABLE_WORDS);
    unsafe { Camellia_Ekeygen((raw_key.len() * 8) as i32, raw_key.as_ptr(), key_table.as_mut_ptr()) }
}

/// Encrypt one 16-byte block in place.
pub fn encrypt_block(grand_rounds: i32, inout: &mut [u8], key_table: &[u32]) {
    let p = inout.as_mut_ptr();
    unsafe {
        Camellia_EncryptBlock_Rounds(grand_rounds, p, key_table.as_ptr(), p);
    }
}

/// Decrypt one 16-byte block in place.
pub fn decrypt_block(grand_rounds: i32, inout: &mut [u8], key_table: &[u32]) {
    let p = inout.as_mut_ptr();
    unsafe {
        Camellia_DecryptBlock_Rounds(grand_rounds, p, key_table.as_ptr(), p);
    }
}

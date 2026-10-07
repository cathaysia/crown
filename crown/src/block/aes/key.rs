//! OpenSSL `AES_KEY` layout shared by the assembly-backed implementations.
//!
//! `struct aes_key_st` is `{ unsigned int rd_key[60]; int rounds; }`; the
//! x86_64 `aesni_*`/`vpaes_*` writers and the aarch64 `aes_v8_*` writers all
//! fill it, but they disagree on the byte order of each round-key word: the
//! AES-NI routines store the words in instruction order while the generic and
//! ARMv8 routines store the FIPS-197 (big-endian) words.

/// OpenSSL `AES_KEY`: 15 round keys then the round count.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AesKey {
    pub rd_key: [u32; 60],
    pub rounds: u32,
}

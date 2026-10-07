//! AES-XTS with VAES + AVX512 (aesni-xts-avx512.pl) for x86_64.
//!
//! OpenSSL selects these bodies from the AES-XTS provider when
//! `aesni_xts_avx512_eligible()` reports the CPU has AVX512F/DQ/BW/VL plus
//! VAES, VPCLMULQDQ and VBMI2 (`cipher_aes_xts_hw.c`); the entry points take
//! the same ABI as `aesni_xts_encrypt`/`aesni_xts_decrypt`, with ciphertext
//! stealing handled inside.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/aes/xts_avx512/x86_64.ts"),
    // The EVEX bodies carry write-mask operands like `{%k2}`, which the
    // default `global_asm!` template syntax reads as substitution braces.
    options(att_syntax, raw)
);

pub use super::ttable::AesKey;

extern "C" {
    /// Non-zero when the CPU has the VAES/AVX512 feature set the bodies need.
    fn aesni_xts_avx512_eligible() -> i32;
    fn aesni_xts_128_encrypt_avx512(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key1: *const AesKey,
        key2: *const AesKey,
        iv: *const u8,
    );
    fn aesni_xts_128_decrypt_avx512(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key1: *const AesKey,
        key2: *const AesKey,
        iv: *const u8,
    );
    fn aesni_xts_256_encrypt_avx512(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key1: *const AesKey,
        key2: *const AesKey,
        iv: *const u8,
    );
    fn aesni_xts_256_decrypt_avx512(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key1: *const AesKey,
        key2: *const AesKey,
        iv: *const u8,
    );
}

/// CPU support probe; forwards to the assembly checker.
pub fn eligible() -> bool {
    unsafe { aesni_xts_avx512_eligible() != 0 }
}

/// In-place XTS over one data unit. Returns `false` when the CPU is not
/// eligible or the data key is not AES-128/256 (`XtsCipher for Aes` rejects
/// AES-192, so `rounds` is 10 or 14).
pub fn xts_crypt(inout: &mut [u8], key1: &AesKey, key2: &AesKey, iv: &[u8; 16], enc: bool) -> bool {
    if inout.len() < 16 || !eligible() {
        return false;
    }
    let f: unsafe extern "C" fn(
        *const u8,
        *mut u8,
        usize,
        *const AesKey,
        *const AesKey,
        *const u8,
    ) = match (key1.rounds, enc) {
        (10, true) => aesni_xts_128_encrypt_avx512,
        (10, false) => aesni_xts_128_decrypt_avx512,
        (14, true) => aesni_xts_256_encrypt_avx512,
        (14, false) => aesni_xts_256_decrypt_avx512,
        _ => return false,
    };
    unsafe {
        f(
            inout.as_ptr(),
            inout.as_mut_ptr(),
            inout.len(),
            key1,
            key2,
            iv.as_ptr(),
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::cpuid::ia32cap;

    /// The assembly probe must agree with the raw capability words it reads:
    /// AVX512F/DQ/BW/VL from `OPENSSL_ia32cap_P+8` and VAES, VPCLMULQDQ and
    /// VBMI2 from `OPENSSL_ia32cap_P+12`.
    #[test]
    fn eligibility_matches_capability_words() {
        let avx512 = (ia32cap(2) & 0xc003_0000) == 0xc003_0000;
        let vaes = (ia32cap(3) & 0x640) == 0x640;
        assert_eq!(eligible(), avx512 && vaes);
    }

    #[test]
    fn short_input_is_rejected() {
        let key = AesKey {
            rd_key: [0; 60],
            rounds: 10,
        };
        let mut buf = [0u8; 8];
        assert!(!xts_crypt(&mut buf, &key, &key, &[0u8; 16], true));
    }
}

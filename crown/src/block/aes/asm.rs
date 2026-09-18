//! AES assembly modules for x86_64.
//!
//! vpaes (SSSE3) is compiled in here. Its key schedule lives in a transformed
//! domain produced by vpaes_set_encrypt_key/vpaes_set_decrypt_key, so wiring
//! it into the block dispatch requires calling those at key-expansion time.
//! The plain aes and aesni modules consume the standard FIPS-197 schedule
//! (crown's BlockExpanded.enc limb) directly through an AES_KEY shim.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/aes/vpaes/x86_64.ts"),
    options(att_syntax)
);

use crate::utils::cpuid::ia32cap;

/// VPAES requires SSSE3 (ECX bit 9 of CPUID leaf 1, i.e. ia32cap[1] bit 9).
#[allow(dead_code)] // capability probe for the pending block-dispatch wiring
pub fn vpaes_supported() -> bool {
    ia32cap(1) & (1 << 9) != 0
}

/// AES-NI requires ECX bit 25 of CPUID leaf 1.
#[allow(dead_code)] // capability probe for the pending block-dispatch wiring
pub fn aesni_supported() -> bool {
    ia32cap(1) & (1 << 25) != 0
}

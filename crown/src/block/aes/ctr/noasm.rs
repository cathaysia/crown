// Re-exports feed `ctr.rs` (`pub use noasm::*` supplies Aes, CryptoResult, ...).
pub use crate::block::aes::*;

/// CTR32 multi-block XOR. The generic mode increments a 128-bit counter;
/// when the low 32-bit word will not wrap over `n` blocks the CTR32 asm
/// (which increments only the final four bytes) is keystream-identical.
#[cfg(any(
    all(feature = "asm", target_arch = "x86_64"),
    crown_aarch64_asm,
    crown_riscv64_asm
))]
fn ctr32_xor(b: &Aes, inout: &mut [u8], ivlo: u64, ivhi: u64, n: usize) -> bool {
    if n == 0 || inout.len() < n * 16 {
        return false;
    }
    let lo32 = ivlo as u32;
    if lo32.checked_add(n as u32).is_none() {
        return false;
    }
    let mut ivec = [0u8; 16];
    ivec[..8].copy_from_slice(&ivhi.to_be_bytes());
    ivec[8..].copy_from_slice(&ivlo.to_be_bytes());
    let (key, sched_ok) = b.enc_schedule();
    let ptr = inout.as_mut_ptr();
    let len = n * 16;
    // SAFETY: `ptr`/`len` alias the same buffer the CTR32 routine xors in place.
    let (ip, op) = unsafe {
        (
            core::slice::from_raw_parts(ptr as *const u8, len),
            core::slice::from_raw_parts_mut(ptr, len),
        )
    };

    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        if sched_ok {
            crate::block::aes::aesni::ctr32_encrypt_blocks(ip, op, n, &key, &ivec);
            return true;
        }
        if crate::block::aes::bsaes::supported() {
            crate::block::aes::bsaes::ctr32_encrypt_blocks(ip, op, &key, &ivec);
            return true;
        }
    }

    #[cfg(crown_aarch64_asm)]
    {
        if sched_ok {
            crate::block::aes::aesv8::ctr32_encrypt_blocks(ip, op, n, &key, &ivec);
            return true;
        }
    }

    #[cfg(crown_riscv64_asm)]
    {
        // The Zvkb+Zvkned CTR32 routine; the other tiers have no bulk CTR
        // body and stay on the portable path.
        if sched_ok && crate::block::aes::riscv64::ctr32_encrypt_blocks(ip, op, n, &key, &ivec) {
            return true;
        }
    }

    false
}

pub fn ctr_blocks_1(block: &Aes, inout: &mut [u8], iv_low: u64, iv_high: u64) {
    #[cfg(any(
        all(feature = "asm", target_arch = "x86_64"),
        crown_aarch64_asm,
        crown_riscv64_asm
    ))]
    if ctr32_xor(block, inout, iv_low, iv_high, 1) {
        return;
    }
    super::ctr_blocks(block, inout, iv_low, iv_high);
}

pub fn ctr_blocks_2(block: &Aes, inout: &mut [u8], iv_low: u64, iv_high: u64) {
    #[cfg(any(
        all(feature = "asm", target_arch = "x86_64"),
        crown_aarch64_asm,
        crown_riscv64_asm
    ))]
    if ctr32_xor(block, inout, iv_low, iv_high, 2) {
        return;
    }
    super::ctr_blocks(block, inout, iv_low, iv_high);
}

pub fn ctr_blocks_4(block: &Aes, inout: &mut [u8], iv_low: u64, iv_high: u64) {
    #[cfg(any(
        all(feature = "asm", target_arch = "x86_64"),
        crown_aarch64_asm,
        crown_riscv64_asm
    ))]
    if ctr32_xor(block, inout, iv_low, iv_high, 4) {
        return;
    }
    super::ctr_blocks(block, inout, iv_low, iv_high);
}

pub fn ctr_blocks_8(block: &Aes, inout: &mut [u8], iv_low: u64, iv_high: u64) {
    #[cfg(any(
        all(feature = "asm", target_arch = "x86_64"),
        crown_aarch64_asm,
        crown_riscv64_asm
    ))]
    if ctr32_xor(block, inout, iv_low, iv_high, 8) {
        return;
    }
    super::ctr_blocks(block, inout, iv_low, iv_high);
}

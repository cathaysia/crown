//! aarch64 CPU capability detection (`crypto/armcap.c`).
//!
//! The aarch64 perlasm modules published by [`super`] read the
//! `OPENSSL_armcap_P` global; this module owns the storage and fills it from
//! the Linux HWCAP words, mirroring the `getauxval` branch of OpenSSL's
//! `OPENSSL_cpuid_setup`. Feature bits are the `ARMV8_*` constants of
//! `crypto/arm_arch.h`; the MIDR-dependent `*_EOR3` hints are derived the
//! same way as upstream, with `MIDR_EL1` read from user space when the
//! kernel advertises `HWCAP_CPUID`.

use core::sync::atomic::{AtomicU32, Ordering};

extern "C" {
    /// Linux `getauxval`; an unknown key reads as 0, which the HWCAP probes
    /// treat as "feature absent".
    fn getauxval(type_: usize) -> usize;
}

/// The global the assembly reads. The modules declare it `.hidden`, so the
/// definition stays private to the final artifact.
#[no_mangle]
#[allow(non_upper_case_globals)]
static mut OPENSSL_armcap_P: u32 = 0;

/// `OPENSSL_armv8_rsa_neonized` of `crypto/armcap.c`: set when the CPU is one
/// whose NEON Montgomery multiplication beats the scalar one. `bn_mul_mont`
/// reads it directly.
#[no_mangle]
#[allow(non_upper_case_globals)]
static mut OPENSSL_armv8_rsa_neonized: u32 = 0;

// Feature bits, from crypto/arm_arch.h.
pub(crate) const ARMV7_NEON: u32 = 1 << 0;
pub(crate) const ARMV8_AES: u32 = 1 << 2;
pub(crate) const ARMV8_SHA1: u32 = 1 << 3;
pub(crate) const ARMV8_SHA256: u32 = 1 << 4;
pub(crate) const ARMV8_PMULL: u32 = 1 << 5;
pub(crate) const ARMV8_SHA512: u32 = 1 << 6;
pub(crate) const ARMV8_CPUID: u32 = 1 << 7;
pub(crate) const ARMV8_RNG: u32 = 1 << 8;
pub(crate) const ARMV8_SM3: u32 = 1 << 9;
pub(crate) const ARMV8_SM4: u32 = 1 << 10;
pub(crate) const ARMV8_SHA3: u32 = 1 << 11;
pub(crate) const ARMV8_UNROLL8_EOR3: u32 = 1 << 12;
pub(crate) const ARMV8_SVE: u32 = 1 << 13;
pub(crate) const ARMV8_SVE2: u32 = 1 << 14;
pub(crate) const ARMV8_HAVE_SHA3_AND_WORTH_USING: u32 = 1 << 15;
pub(crate) const ARMV8_UNROLL12_EOR3: u32 = 1 << 16;

// AT_HWCAP / AT_HWCAP2 and the aarch64 HWCAP bits, from Linux uapi/asm/hwcap.h.
const AT_HWCAP: usize = 16;
const AT_HWCAP2: usize = 26;
const HWCAP_NEON: usize = 1 << 1;
const HWCAP_AES: usize = 1 << 3;
const HWCAP_PMULL: usize = 1 << 4;
const HWCAP_SHA1: usize = 1 << 5;
const HWCAP_SHA256: usize = 1 << 6;
const HWCAP_CPUID: usize = 1 << 11;
const HWCAP_SHA3: usize = 1 << 17;
const HWCAP_SM3: usize = 1 << 18;
const HWCAP_SM4: usize = 1 << 19;
const HWCAP_SHA512: usize = 1 << 21;
const HWCAP_SVE: usize = 1 << 22;
const HWCAP2_SVE2: usize = 1 << 1;
const HWCAP2_RNG: usize = 1 << 16;

// MIDR_EL1 model matching, from crypto/arm_arch.h.
const ARM_CPU_IMP_ARM: u32 = 0x41;
const ARM_CPU_IMP_APPLE: u32 = 0x61;
const ARM_CPU_IMP_MICROSOFT: u32 = 0x6D;
const ARM_CPU_IMP_AMPERE: u32 = 0xC0;
const ARM_CPU_PART_CORTEX_A72: u32 = 0xD08;
const ARM_CPU_PART_N1: u32 = 0xD0C;
const ARM_CPU_PART_V1: u32 = 0xD40;
const ARM_CPU_PART_N2: u32 = 0xD49;
const ARM_CPU_PART_V2: u32 = 0xD4F;
const MICROSOFT_CPU_PART_COBALT_100: u32 = 0xD49;

const MIDR_CPU_MODEL_MASK: u32 = (0xff << 24) | (0xfff << 4) | (0xf << 16);

const fn midr_cpu_model(imp: u32, partnum: u32) -> u32 {
    (imp << 24) | (0xf << 16) | (partnum << 4)
}

const fn midr_is_cpu_model(midr: u32, imp: u32, partnum: u32) -> bool {
    (midr & MIDR_CPU_MODEL_MASK) == midr_cpu_model(imp, partnum)
}

/// The cached capability word. `u32::MAX` marks "not probed yet"; the
/// assember reads the global, so any probe must publish before use.
static CACHE: AtomicU32 = AtomicU32::new(u32::MAX);

/// The `OPENSSL_armcap_P` feature bits, probed once.
pub(crate) fn armcap() -> u32 {
    let cached = CACHE.load(Ordering::Relaxed);
    if cached != u32::MAX {
        return cached;
    }

    let (cap, midr) = detect();
    // Publish for the assembly before returning: every Rust call site probes
    // through here first, and the assembly reads the globals at entry.
    let neonized =
        u32::from(cap & ARMV7_NEON != 0 && cap & ARMV8_CPUID != 0 && is_neonized_midr(midr));
    unsafe {
        *core::ptr::addr_of_mut!(OPENSSL_armcap_P) = cap;
        *core::ptr::addr_of_mut!(OPENSSL_armv8_rsa_neonized) = neonized;
    }
    CACHE.store(cap, Ordering::Relaxed);
    cap
}

/// `OPENSSL_armv8_rsa_neonized`: the CPUs whose NEON Montgomery multiplication
/// beats the scalar one (`crypto/armcap.c`).
fn is_neonized_midr(midr: u32) -> bool {
    midr_is_cpu_model(midr, ARM_CPU_IMP_ARM, ARM_CPU_PART_CORTEX_A72)
        || midr_is_cpu_model(midr, ARM_CPU_IMP_ARM, ARM_CPU_PART_N1)
}

/// The capability word and `MIDR_EL1` (0 when the kernel does not expose it).
fn detect() -> (u32, u32) {
    // SAFETY: getauxval has no preconditions; unknown keys read as 0.
    let (hwcap, hwcap2) = unsafe { (getauxval(AT_HWCAP), getauxval(AT_HWCAP2)) };
    let mut cap = 0;

    if hwcap & HWCAP_NEON != 0 {
        cap |= ARMV7_NEON;
    }
    if hwcap & HWCAP_AES != 0 {
        cap |= ARMV8_AES;
    }
    if hwcap & HWCAP_PMULL != 0 {
        cap |= ARMV8_PMULL;
    }
    if hwcap & HWCAP_SHA1 != 0 {
        cap |= ARMV8_SHA1;
    }
    if hwcap & HWCAP_SHA256 != 0 {
        cap |= ARMV8_SHA256;
    }
    if hwcap & HWCAP_SHA512 != 0 {
        cap |= ARMV8_SHA512;
    }
    if hwcap & HWCAP_CPUID != 0 {
        cap |= ARMV8_CPUID;
    }
    if hwcap & HWCAP_SM3 != 0 {
        cap |= ARMV8_SM3;
    }
    if hwcap & HWCAP_SM4 != 0 {
        cap |= ARMV8_SM4;
    }
    if hwcap & HWCAP_SHA3 != 0 {
        cap |= ARMV8_SHA3;
    }
    if hwcap & HWCAP_SVE != 0 {
        cap |= ARMV8_SVE;
    }
    if hwcap2 & HWCAP2_SVE2 != 0 {
        cap |= ARMV8_SVE2;
    }
    if hwcap2 & HWCAP2_RNG != 0 {
        cap |= ARMV8_RNG;
    }

    let mut midr = 0;
    if cap & ARMV8_CPUID != 0 {
        midr = read_midr();
        let unroll8 = midr_is_cpu_model(midr, ARM_CPU_IMP_ARM, ARM_CPU_PART_V1)
            || midr_is_cpu_model(midr, ARM_CPU_IMP_ARM, ARM_CPU_PART_N2)
            || midr_is_cpu_model(midr, ARM_CPU_IMP_MICROSOFT, MICROSOFT_CPU_PART_COBALT_100)
            || midr_is_cpu_model(midr, ARM_CPU_IMP_ARM, ARM_CPU_PART_V2)
            || (midr >> 24) == ARM_CPU_IMP_AMPERE;
        let unroll12 = midr_is_cpu_model(midr, ARM_CPU_IMP_ARM, ARM_CPU_PART_V1)
            || midr_is_cpu_model(midr, ARM_CPU_IMP_ARM, ARM_CPU_PART_V2)
            || (midr >> 24) == ARM_CPU_IMP_AMPERE;
        let apple_worth_it = midr_is_cpu_model(midr, ARM_CPU_IMP_APPLE, 0x022)
            || midr_is_cpu_model(midr, ARM_CPU_IMP_APPLE, 0x023)
            || midr_is_cpu_model(midr, ARM_CPU_IMP_APPLE, 0x024)
            || midr_is_cpu_model(midr, ARM_CPU_IMP_APPLE, 0x025)
            || midr_is_cpu_model(midr, ARM_CPU_IMP_APPLE, 0x028)
            || midr_is_cpu_model(midr, ARM_CPU_IMP_APPLE, 0x029)
            || midr_is_cpu_model(midr, ARM_CPU_IMP_APPLE, 0x032)
            || midr_is_cpu_model(midr, ARM_CPU_IMP_APPLE, 0x033)
            || midr_is_cpu_model(midr, ARM_CPU_IMP_APPLE, 0x034)
            || midr_is_cpu_model(midr, ARM_CPU_IMP_APPLE, 0x035)
            || midr_is_cpu_model(midr, ARM_CPU_IMP_APPLE, 0x038)
            || midr_is_cpu_model(midr, ARM_CPU_IMP_APPLE, 0x039);

        if cap & ARMV8_SHA3 != 0 {
            if unroll8 {
                cap |= ARMV8_UNROLL8_EOR3;
            }
            if unroll12 {
                cap |= ARMV8_UNROLL12_EOR3;
            }
            if apple_worth_it {
                cap |= ARMV8_HAVE_SHA3_AND_WORTH_USING;
            }
        }
    }

    (cap, midr)
}

/// `MIDR_EL1`, readable from EL0 when the kernel advertises `HWCAP_CPUID`.
fn read_midr() -> u32 {
    let midr: u64;
    unsafe {
        core::arch::asm!("mrs {}, MIDR_EL1", out(reg) midr, options(nomem, nostack, preserves_flags));
    }
    midr as u32
}

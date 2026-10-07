//! riscv64 CPU capability detection (`crypto/riscvcap.c`).
//!
//! Unlike the aarch64 modules, whose entry points test `OPENSSL_armcap_P`
//! themselves, the riscv64 perlasm output does not self-dispatch: OpenSSL's C
//! consumers test `RISCV_HAS_*()` and call the matching symbol. crown mirrors
//! that split, so this module owns the capability word and every riscv64
//! dispatch site asks it first.
//!
//! The bits are the `RISCV_DEFINE_CAP` list of
//! `include/crypto/riscv_arch.def` (all of them live in word 0 of
//! `OPENSSL_riscvcap_P`); they are filled from the `riscv_hwprobe` syscall key
//! `RISCV_HWPROBE_KEY_IMA_EXT_0`, exactly like the `hwprobe_to_cap()` branch
//! of `OPENSSL_cpuid_setup`. Note that `riscv_hwprobe`'s own `IMA_EXT_0` bit
//! positions differ from the capability-word ones, so the mapping is spelled
//! out per extension.
//!
//! One deliberate addition, documented in docs/algorithms-status.md §1c: the
//! `OPENSSL_riscvcap` environment override of `parse_env()` is honoured. It
//! exists because `riscv_hwprobe` only grew the multi-letter extension bits in
//! Linux 6.4 and several emulators still do not report them, which would leave
//! every tier above `Zbb` untestable under qemu-user. Like upstream, the
//! variable *replaces* the probe (and only ever sets bits), and a vector
//! extension listed there needs `_v` in the same string for
//! [`riscv_vlen`] to be non-zero.

use core::sync::atomic::{AtomicU32, Ordering};

// Feature bits, from include/crypto/riscv_arch.def.
pub(crate) const RISCV_ZBA: u32 = 1 << 0;
pub(crate) const RISCV_ZBB: u32 = 1 << 1;
pub(crate) const RISCV_ZBC: u32 = 1 << 2;
pub(crate) const RISCV_ZBS: u32 = 1 << 3;
pub(crate) const RISCV_ZBKB: u32 = 1 << 4;
pub(crate) const RISCV_ZBKC: u32 = 1 << 5;
pub(crate) const RISCV_ZBKX: u32 = 1 << 6;
pub(crate) const RISCV_ZKND: u32 = 1 << 7;
pub(crate) const RISCV_ZKNE: u32 = 1 << 8;
pub(crate) const RISCV_ZKNH: u32 = 1 << 9;
pub(crate) const RISCV_ZKSED: u32 = 1 << 10;
pub(crate) const RISCV_ZKSH: u32 = 1 << 11;
pub(crate) const RISCV_ZKR: u32 = 1 << 12;
pub(crate) const RISCV_ZKT: u32 = 1 << 13;
pub(crate) const RISCV_V: u32 = 1 << 14;
pub(crate) const RISCV_ZVBB: u32 = 1 << 15;
pub(crate) const RISCV_ZVBC: u32 = 1 << 16;
pub(crate) const RISCV_ZVKB: u32 = 1 << 17;
pub(crate) const RISCV_ZVKG: u32 = 1 << 18;
pub(crate) const RISCV_ZVKNED: u32 = 1 << 19;
pub(crate) const RISCV_ZVKNHA: u32 = 1 << 20;
pub(crate) const RISCV_ZVKNHB: u32 = 1 << 21;
pub(crate) const RISCV_ZVKSED: u32 = 1 << 22;
pub(crate) const RISCV_ZVKSH: u32 = 1 << 23;

/// `ZVX_MIN`..`ZVX_MAX` of `riscv_arch.h`: the capability bits that are only
/// meaningful on a CPU that has `V` (`IS_IN_DEPEND_VECTOR`).
const ZVX_MIN: u32 = 15;
const ZVX_MAX: u32 = 23;
const ZVX_MASK: u32 = ((1 << (ZVX_MAX + 1)) - 1) & !((1 << ZVX_MIN) - 1);

/// `RISCV_DEFINE_CAP(NAME, INDEX, BIT_INDEX, HWPROBE_KEY, HWPROBE_VALUE)`:
/// the extension name as `riscv_arch.def` spells it, its bit in the
/// capability word, and the matching `RISCV_HWPROBE_KEY_IMA_EXT_0` bit (0
/// where upstream has a `-1` key, i.e. no hwprobe source: `ZKR`).
const CAPS: &[(&str, u32, u64)] = &[
    ("ZBA", RISCV_ZBA, 1 << 3),
    ("ZBB", RISCV_ZBB, 1 << 4),
    ("ZBC", RISCV_ZBC, 1 << 7),
    ("ZBS", RISCV_ZBS, 1 << 5),
    ("ZBKB", RISCV_ZBKB, 1 << 8),
    ("ZBKC", RISCV_ZBKC, 1 << 9),
    ("ZBKX", RISCV_ZBKX, 1 << 10),
    ("ZKND", RISCV_ZKND, 1 << 11),
    ("ZKNE", RISCV_ZKNE, 1 << 12),
    ("ZKNH", RISCV_ZKNH, 1 << 13),
    ("ZKSED", RISCV_ZKSED, 1 << 14),
    ("ZKSH", RISCV_ZKSH, 1 << 15),
    ("ZKR", RISCV_ZKR, 0),
    ("ZKT", RISCV_ZKT, 1 << 16),
    ("V", RISCV_V, 1 << 2),
    ("ZVBB", RISCV_ZVBB, 1 << 17),
    ("ZVBC", RISCV_ZVBC, 1 << 18),
    ("ZVKB", RISCV_ZVKB, 1 << 19),
    ("ZVKG", RISCV_ZVKG, 1 << 20),
    ("ZVKNED", RISCV_ZVKNED, 1 << 21),
    ("ZVKNHA", RISCV_ZVKNHA, 1 << 22),
    ("ZVKNHB", RISCV_ZVKNHB, 1 << 23),
    ("ZVKSED", RISCV_ZVKSED, 1 << 24),
    ("ZVKSH", RISCV_ZVKSH, 1 << 25),
];

// Linux uapi: AT_HWCAP, HWCAP_ISA_V (bit 21, `1 << ('V' - 'A')`), and the
// riscv-specific syscall number (`__NR_arch_specific_syscall + 14`).
const AT_HWCAP: usize = 16;
const HWCAP_ISA_V: usize = 1 << 21;
const SYS_RISCV_HWPROBE: usize = 244 + 14;
const RISCV_HWPROBE_KEY_IMA_EXT_0: i64 = 4;

extern "C" {
    /// Linux `getauxval`; an unknown key reads as 0.
    fn getauxval(type_: usize) -> usize;
    /// Linux `getenv`; null when unset.
    fn getenv(name: *const core::ffi::c_char) -> *const core::ffi::c_char;
}

/// `struct riscv_hwprobe` — one `{key, value}` pair.
#[repr(C)]
struct Hwprobe {
    key: i64,
    value: u64,
}

/// `riscv_hwprobe()` through `ecall`, mirroring the syscall wrapper in
/// `riscvcap.c`. Returns `None` when the syscall is unavailable (`-ENOSYS`
/// on kernels before Linux 6.4).
fn hwprobe_ext_0() -> Option<u64> {
    let mut pairs = [Hwprobe {
        key: RISCV_HWPROBE_KEY_IMA_EXT_0,
        value: 0,
    }];
    let ret: usize;
    // SAFETY: the kernel reads one `{i64, u64}` pair and writes `value` back;
    // cpu_count = 0 asks about the calling CPU and cpus = NULL is required
    // with it. The syscall clobbers nothing else.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") pairs.as_mut_ptr() as usize => ret,
            in("a1") pairs.len(),
            in("a2") 0usize,
            in("a3") 0usize,
            in("a4") 0usize,
            in("a7") SYS_RISCV_HWPROBE,
            options(nostack)
        );
    }
    if (ret as isize) < 0 {
        None
    } else {
        Some(pairs[0].value)
    }
}

/// The capability word, probed once. `u32::MAX` marks "not probed yet".
static CACHE: AtomicU32 = AtomicU32::new(u32::MAX);
/// `riscv_vlen()`: VLEN in bits, 0 when the CPU has no vector extension.
static VLEN: AtomicU32 = AtomicU32::new(0);

/// The `RISCV_HAS_*()` capability word, probed once.
pub(crate) fn riscvcap() -> u32 {
    let cached = CACHE.load(Ordering::Relaxed);
    if cached != u32::MAX {
        return cached;
    }

    let cap = detect();
    if cap & RISCV_V != 0 {
        VLEN.store(read_vlen(), Ordering::Relaxed);
    }
    CACHE.store(cap, Ordering::Relaxed);
    cap
}

/// `riscv_vlen()`: the length of a vector register in bits (0 without `V`).
pub(crate) fn riscv_vlen() -> usize {
    riscvcap();
    VLEN.load(Ordering::Relaxed) as usize
}

/// `RISCV_HAS_ZVKB()`: `Zvbb` is a superset of `Zvkb`, and the macro in
/// `riscv_arch.h` tests either.
pub(crate) fn has_zvkb() -> bool {
    let cap = riscvcap();
    cap & (RISCV_ZVKB | RISCV_ZVBB) != 0
}

/// The capability word: the `OPENSSL_riscvcap` override when it is set, else
/// `riscv_hwprobe` plus the `AT_HWCAP` vector bit.
fn detect() -> u32 {
    if let Some(cap) = env_cap() {
        return cap;
    }

    // `VECTOR_CAPABLE` of crypto/riscv_arch.h: the vector-crypto bits are
    // only trusted when AT_HWCAP reports the V extension.
    // SAFETY: getauxval has no preconditions; unknown keys read as 0.
    let hwcap_v = unsafe { getauxval(AT_HWCAP) } & HWCAP_ISA_V != 0;
    let mut cap = if hwcap_v { RISCV_V } else { 0 };

    if let Some(ima_ext_0) = hwprobe_ext_0() {
        for (_, bit, hwprobe_bit) in CAPS {
            // `IS_IN_DEPEND_VECTOR`.
            if *bit & ZVX_MASK != 0 && !hwcap_v {
                continue;
            }
            if *hwprobe_bit != 0 && ima_ext_0 & *hwprobe_bit != 0 {
                cap |= *bit;
            }
        }
    }
    cap
}

/// `parse_env()` of `riscvcap.c`: `OPENSSL_riscvcap` holds an ISA string such
/// as `rv64gc_v_zba_zbb_zvkned_zvkg_zvkb`; every `_<extension>` found in it
/// (case insensitively) sets that capability, and nothing is ever cleared.
// A byte string rather than a `c"..."` literal: the pre-commit hook runs
// rustfmt without an edition argument, and rustfmt's parser rejects C string
// literals outside edition 2021+.
#[allow(clippy::manual_c_str_literals)]
fn env_cap() -> Option<u32> {
    // SAFETY: the name is NUL-terminated; getenv returns null or a
    // NUL-terminated C string.
    let ptr = unsafe { getenv(b"OPENSSL_riscvcap\0".as_ptr().cast()) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: getenv returned a valid NUL-terminated string.
    let env = unsafe { core::ffi::CStr::from_ptr(ptr) };
    let env = env.to_bytes();

    let mut cap = 0;
    for (name, bit, _) in CAPS {
        if contains_ext(env, name.as_bytes()) {
            cap |= *bit;
        }
    }
    Some(cap)
}

/// Case-insensitive search for `_<name>` in the ISA string, what `strstr`
/// over the upper-cased copy of `parse_env()` does.
fn contains_ext(haystack: &[u8], name: &[u8]) -> bool {
    if haystack.len() < name.len() + 1 {
        return false;
    }
    (0..=haystack.len() - name.len() - 1).any(|start| {
        haystack[start] == b'_'
            && name
                .iter()
                .enumerate()
                .all(|(i, c)| haystack[start + 1 + i].eq_ignore_ascii_case(c))
    })
}

/// `riscv_vlen_asm()`: `vlenb * 8`, read with a CSR read instead of the
/// perlasm `riscv64cpuid.pl` (whose other entry points, `CRYPTO_memcmp` and
/// `OPENSSL_cleanse`, crown implements in Rust). Only called with `V` set:
/// the CSR does not exist without the vector extension.
fn read_vlen() -> u32 {
    let vlenb: usize;
    // SAFETY: `vlenb` (0xc22) is readable from EL0 and cannot trap while the
    // V extension is enabled, which the caller checked.
    unsafe {
        core::arch::asm!("csrr {}, 0xc22", out(reg) vlenb, options(nomem, nostack, preserves_flags));
    }
    (vlenb * 8) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every vector-crypto bit must come with `V`, and a CPU with `V` must
    /// report at least the 128 bits of VLEN that every vector module requires.
    #[test]
    fn cap_word_is_self_consistent() {
        let cap = riscvcap();
        assert!(
            cap & ZVX_MASK == 0 || cap & RISCV_V != 0,
            "Zv* capability without V: {cap:#x}"
        );
        if cap & RISCV_V != 0 {
            assert!(riscv_vlen() >= 128, "VLEN {}", riscv_vlen());
        }
    }

    /// The environment parser matches whole `_extension` names, like
    /// `parse_env()`'s `strstr` over the upper-cased string.
    #[test]
    fn env_parser_matches_extensions() {
        assert!(contains_ext(b"rv64gc_v_zvkned_zvkg_zvkb", b"ZVKNED"));
        assert!(contains_ext(b"rv64gc_V_zknd_zkne", b"zkne"));
        assert!(!contains_ext(b"rv64gc_v", b"VNED"));
        assert!(!contains_ext(b"rv64gc", b"V"));
        assert!(!contains_ext(b"rv64i_m", b"V"));
    }
}

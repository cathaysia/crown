#![allow(dead_code)]
fn main() {
    println!("cargo::rerun-if-changed=**/*.cu");

    #[cfg(feature = "cuda")]
    build_cuda();

    #[cfg(feature = "asm")]
    {
        #[cfg(target_arch = "aarch64")]
        build_aarch64();
        #[cfg(target_arch = "x86_64")]
        build_x86_64();
    }
}

bitflags::bitflags! {
    pub struct ArmCap: u32 {
        const ARMV7_NEON = 1<<0;
        const ARMV7_TICK = 1<<1;
        const ARMV8_AES = 1<<2;
        const ARMV8_SHA1 = 1<<3;
        const ARMV8_SHA256 = 1<<4;
        const ARMV8_PMULL = 1<<5;
        const ARMV8_SHA512 = 1<<6;
        const ARMV8_CPUID = 1<<7;
        const ARMV8_RNG = 1<<8;
        const ARMV8_SM3 = 1<<9;
        const ARMV8_SM4 = 1<<10;
        const ARMV8_SHA3 = 1<<11;
        const ARMV8_UNROLL8_EOR3 = 1<<12;
        const ARMV8_SVE = 1<<13;
        const ARMV8_SVE2 = 1<<14;
        const ARMV8_HAVE_SHA3_AND_WORTH_USING = 1<<15;
        const ARMV8_UNROLL12_EOR3 = 1<<16;
    }
}

pub struct X86Cap {
    pub caps: [u32; 10],
}

impl X86Cap {
    pub fn detect() -> Self {
        let mut caps = [0u32; 10];

        // P[0] - CPUID EDX features (basic feature)
        caps[0] |= 1 << 0; // FPU
        caps[0] |= 1 << 4; // TSC
        caps[0] |= 1 << 15; // CMOV
        caps[0] |= 1 << 23; // MMX
        caps[0] |= 1 << 24; // FXSR

        // SSE
        if cfg!(target_feature = "sse") {
            caps[0] |= 1 << 25; // SSE
        }
        if cfg!(target_feature = "sse2") {
            caps[0] |= 1 << 26; // SSE2
        }

        // P[1] - CPUID ECX features (extend feature)
        if cfg!(target_feature = "sse3") {
            caps[1] |= 1 << 0; // SSE3
        }
        if cfg!(target_feature = "pclmulqdq") {
            caps[1] |= 1 << 1; // PCLMULQDQ
        }
        if cfg!(target_feature = "ssse3") {
            caps[1] |= 1 << 9; // SSSE3
        }
        if cfg!(target_feature = "fma") {
            caps[1] |= 1 << 12; // FMA
        }
        if cfg!(target_feature = "cmpxchg16b") {
            caps[1] |= 1 << 13; // CMPXCHG16B
        }
        if cfg!(target_feature = "sse4.1") {
            caps[1] |= 1 << 19; // SSE4.1
        }
        if cfg!(target_feature = "sse4.2") {
            caps[1] |= 1 << 20; // SSE4.2
        }
        if cfg!(target_feature = "movbe") {
            caps[1] |= 1 << 22; // MOVBE
        }
        if cfg!(target_feature = "popcnt") {
            caps[1] |= 1 << 23; // POPCNT
        }
        if cfg!(target_feature = "aes") {
            caps[1] |= 1 << 25; // AES
        }
        if cfg!(target_feature = "avx") {
            caps[1] |= 1 << 28; // AVX
        }
        if cfg!(target_feature = "f16c") {
            caps[1] |= 1 << 29; // F16C
        }
        if cfg!(target_feature = "rdrand") {
            caps[1] |= 1 << 30; // RDRAND
        }

        // P[2] - Extended features (AVX2, BMI, etc.)
        if cfg!(target_feature = "avx2") {
            caps[2] |= 1 << 5; // AVX2
        }
        if cfg!(target_feature = "bmi1") {
            caps[2] |= 1 << 3; // BMI1
        }
        if cfg!(target_feature = "bmi2") {
            caps[2] |= 1 << 8; // BMI2
        }
        if cfg!(target_feature = "adx") {
            caps[2] |= 1 << 19; // ADX
        }
        if cfg!(target_feature = "sha") {
            caps[2] |= 1 << 29; // SHA
        }

        // P[3] - AVX-512 features
        if cfg!(target_feature = "avx512f") {
            caps[3] |= 1 << 16; // AVX512F
        }
        if cfg!(target_feature = "avx512dq") {
            caps[3] |= 1 << 17; // AVX512DQ
        }
        if cfg!(target_feature = "avx512cd") {
            caps[3] |= 1 << 28; // AVX512CD
        }
        if cfg!(target_feature = "avx512bw") {
            caps[3] |= 1 << 30; // AVX512BW
        }
        if cfg!(target_feature = "avx512vl") {
            caps[3] |= 1 << 31; // AVX512VL
        }

        Self { caps }
    }
}

impl ArmCap {
    pub fn detect() -> Self {
        let mut cap = ArmCap::empty();
        if cfg!(target_feature = "neon") {
            cap |= Self::ARMV7_NEON;
        }
        cap |= Self::ARMV7_TICK;
        if cfg!(target_feature = "sha2") {
            cap |= Self::ARMV8_SHA1;
            cap |= Self::ARMV8_SHA256;
        }
        if cfg!(target_feature = "aes") {
            cap |= Self::ARMV8_AES;
            cap |= Self::ARMV8_PMULL;
        }
        if cfg!(target_feature = "sve") {
            cap |= Self::ARMV8_SVE;
        }
        if cfg!(target_feature = "sve2") {
            cap |= Self::ARMV8_SVE2;
        }
        if cfg!(target_feature = "sha3") {
            cap |= Self::ARMV8_HAVE_SHA3_AND_WORTH_USING;
        }

        cap
    }
}

#[cfg(target_arch = "aarch64")]
fn build_aarch64() {
    let mut macros = vec![];
    if cfg!(target_endian = "big") {
        macros.push("#define __AARCH64EB__");
    }
    let armcap = ArmCap::detect().bits();

    let outdir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(
        format!("{outdir}/cap.c"),
        format!(
            r#"
unsigned int crown_armcap_P = {armcap};
"#
        ),
    )
    .unwrap();

    let arch = format!(
        r#"
#ifndef ARM_ARCH_H
#define ARM_ARCH_H

#define AARCH64_VALID_CALL_TARGET
#define AARCH64_VALIDATE_LINK_REGISTER
#define AARCH64_SIGN_LINK_REGISTER

#define ARMV7_NEON      (1<<0)
#define ARMV7_TICK      (1<<1)
#define ARMV8_AES       (1<<2)
#define ARMV8_SHA1      (1<<3)
#define ARMV8_SHA256    (1<<4)
#define ARMV8_PMULL     (1<<5)
#define ARMV8_SHA512    (1<<6)
#define ARMV8_CPUID     (1<<7)
#define ARMV8_RNG       (1<<8)
#define ARMV8_SM3       (1<<9)
#define ARMV8_SM4       (1<<10)
#define ARMV8_SHA3      (1<<11)
#define ARMV8_UNROLL8_EOR3      (1<<12)
#define ARMV8_SVE       (1<<13)
#define ARMV8_SVE2      (1<<14)
#define ARMV8_HAVE_SHA3_AND_WORTH_USING     (1<<15)
#define ARMV8_UNROLL12_EOR3     (1<<16)

{}
#endif  // ARM_ARCH_H
"#,
        macros.join("\n")
    );
    std::fs::write(format!("{}/arm_arch.h", outdir), arch).unwrap();
    let mut build = cc::Build::new();
    build
        .file("./src/hash/md5/block/aarch64.S")
        .file("src/mac/poly1305/sum/aarch64.S")
        .file("src/stream/chacha20/xor_key_stream/aarch64.S")
        .file("src/stream/chacha20/xor_key_stream/aarch64_sve.S")
        .file(format!("{outdir}/cap.c"))
        .include(outdir);

    build.compile("crown_asm");
}

#[cfg(feature = "cuda")]
fn build_cuda() {
    #[cfg(feature = "bindgen")]
    {
        use std::path::PathBuf;
        let bindings = bindgen::Builder::default()
            .clang_args(&["-I", "/usr/local/cuda/include/"])
            .header("wrapper.h")
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .raw_line("#![allow(non_upper_case_globals)]")
            .raw_line("#![allow(non_camel_case_types)]")
            .raw_line("#![allow(non_snake_case)]")
            .raw_line("#![allow(dead_code)]")
            .raw_line("#![allow(unused_imports)]")
            .raw_line("#![allow(clippy::enum_variant_names)]")
            .use_core()
            .default_enum_style(bindgen::EnumVariation::Rust {
                non_exhaustive: false,
            })
            .constified_enum("Neg")
            .generate()
            .expect("Unable to generate bindings");

        // Write the bindings to the $OUT_DIR/bindings.rs file.
        let out_path = PathBuf::from("./src/cuda/sys.rs");
        bindings
            .write_to_file(out_path)
            .expect("Couldn't write bindings!");
    }

    let mut build = cc::Build::new();
    build
        .cuda(true)
        .file("./src/utils/subtle/xor.cu")
        .file("./src/hash/sha256/sha256.cu")
        .file("./src/hash/md5/md5.cu");
    if cfg!(debug_assertions) {
        build.flags(&["-O0", "-G", "-Xptxas", "-O0"]);
    };

    build.compile("crown_cuda");
}

#[cfg(target_arch = "x86_64")]
fn build_x86_64() {
    let x86cap = X86Cap::detect();

    let outdir = std::env::var("OUT_DIR").unwrap();

    let cap_array = format!(
        "{{0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}}}",
        x86cap.caps[0], x86cap.caps[1], x86cap.caps[2], x86cap.caps[3], x86cap.caps[4],
        x86cap.caps[5], x86cap.caps[6], x86cap.caps[7], x86cap.caps[8], x86cap.caps[9]
    );

    std::fs::write(
        format!("{outdir}/cap.c"),
        format!(
            r#"
unsigned int crown_ia32cap_P[10] = {};
"#,
            cap_array
        ),
    )
    .unwrap();

    let mut build = cc::Build::new();
    build
        .file("./src/hash/md5/block/x86_64.S")
        .file("src/mac/poly1305/sum/x86_64.S")
        .file("src/stream/chacha20/xor_key_stream/x86_64.S")
        .file(format!("{outdir}/cap.c"))
        .include(outdir);

    build.compile("crown_asm");
}

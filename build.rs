#![allow(dead_code)]
fn main() {
    println!("cargo::rerun-if-changed=**/*.cu");

    #[cfg(feature = "cuda")]
    build_cuda();

    #[cfg(target_arch = "aarch64")]
    build_aarch64();
    #[cfg(target_arch = "x86_64")]
    build_x86_64();
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
unsigned int OPENSSL_armcap_P = {armcap};
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

    build.compile("kittycrypto_asm");
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

    build.compile("kittycrypto_cuda");
}

#[cfg(target_arch = "x86_64")]
fn build_x86_64() {
    let outdir = std::env::var("OUT_DIR").unwrap();
    let mut build = cc::Build::new();
    build.file("./src/hash/md5/block/x86_64.S").include(outdir);

    build.compile("kittycrypto_asm");
}

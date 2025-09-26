fn main() {
    println!("cargo::rerun-if-changed=**/*.cu");
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

    #[cfg(feature = "cuda")]
    {
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

    // Build assembly files for AArch64
    #[cfg(target_arch = "aarch64")]
    {
        let mut macros = vec![];
        if cfg!(target_endian = "big") {
            macros.push("#define __AARCH64EB__");
        }
        let arch = format!(
            r#"
#ifndef ARM_ARCH_H
#define ARM_ARCH_H

        {}
#endif  // ARM_ARCH_H
"#,
            macros.join("\n")
        );
        let outdir = std::env::var("OUT_DIR").unwrap();
        std::fs::write(format!("{}/arm_arch.h", outdir), arch).unwrap();
        let mut build = cc::Build::new();
        build.file("./src/hash/md5/block/aarch64.S").include(outdir);

        build.compile("kittycrypto_asm");
    }
}

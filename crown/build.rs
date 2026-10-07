fn main() {
    println!("cargo::rerun-if-changed=**/*.cu");

    // The aarch64 assembly modules are frozen ELF output of the OpenSSL
    // perlasm scripts, so they are only offered on the targets whose
    // assembler accepts them. This cfg keeps the module gates readable; see
    // scripts/gen-aarch64-asm.py.
    println!("cargo::rustc-check-cfg=cfg(crown_aarch64_asm)");
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let asm = std::env::var("CARGO_FEATURE_ASM").is_ok();
    if asm && arch == "aarch64" && (os == "linux" || os == "android") {
        println!("cargo::rustc-cfg=crown_aarch64_asm");
    }

    #[cfg(feature = "asm")]
    {
        let ctx = crown_jsasm::JsasmContext::new().unwrap();
        let s = serde_json::to_string(&ctx).unwrap();
        println!("cargo:rustc-env=JSASM_VAR={}", s);
    }

    #[cfg(feature = "cuda")]
    build_cuda();
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

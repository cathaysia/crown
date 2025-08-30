fn main() {
    println!("cargo::rerun-if-changed=**/*.cu");
    #[cfg(feature = "cuda")]
    {
        let mut build = cc::Build::new();
        build
            .cuda(true)
            .file("./src/subtle/xor.cu")
            .file("./src/sha256/sha256.cu")
            .file("./src/md5/md5.cu");
        if cfg!(debug_assertions) {
            build.flags(&["-O0", "-G", "-Xptxas", "-O0"]);
        };

        build.compile("kittycrypto_cuda");
    }
}

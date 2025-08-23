fn main() {
    println!("cargo::rerun-if-changed=**/*.cu");
    #[cfg(feature = "cuda")]
    cc::Build::new()
        .cuda(true)
        .file("./src/subtle/xor.cu")
        .file("./src/md5/md5.cu")
        .compile("kittycrypto_cuda");
}

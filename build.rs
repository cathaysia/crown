fn main() {
    println!("cargo::rerun-if-changed=**/*.cu");
    cc::Build::new()
        .cuda(true)
        .file("./src/subtle/xor.cu")
        .compile("kittycrypto_cuda");
}

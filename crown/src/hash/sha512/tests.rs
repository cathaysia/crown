use sha2::Digest;

#[test]
fn rustcrypto_sha256_interop() {
    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut buf = vec![0u8; s];
        rand::fill(buf.as_mut_slice());
        let this = &super::sum512(&buf);

        let rustcrypto = sha2::Sha512::digest(&buf).to_vec();

        assert_eq!(this, rustcrypto.as_slice());
    }
}

use sha3::Digest;

#[test]
fn rustcrypto_sha3_interop() {
    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut buf = vec![0u8; s];
        rand::fill(buf.as_mut_slice());
        let k256 = super::sum256(&buf);
        let k384 = super::sum384(&buf);
        let k512 = super::sum512(&buf);

        let r256 = sha3::Sha3_256::digest(&buf).as_slice().to_vec();
        let r384 = sha3::Sha3_384::digest(&buf).as_slice().to_vec();
        let r512 = sha3::Sha3_512::digest(&buf).as_slice().to_vec();

        assert_eq!(k256, r256.as_slice());
        assert_eq!(k384, r384.as_slice());
        assert_eq!(k512, r512.as_slice());
    }
}

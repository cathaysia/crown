use digest::Digest;

use super::*;

#[test]
fn rustcrypto_blake2s_interop() {
    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut buf = vec![0u8; s];
        rand::fill(buf.as_mut_slice());

        let this = &sum256(&buf);
        let rustcrypto = {
            let mut digest = blake2::Blake2s256::new();
            digest.update(&buf);
            digest.finalize()
        };

        assert_eq!(hex::encode(this), hex::encode(rustcrypto));
    }
}

use md4::Digest;

use super::sum_md4;

#[test]
fn rustcrypto_md4_interop() {
    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut buf = vec![0u8; s];
        rand::fill(buf.as_mut_slice());
        let this = sum_md4(&buf);
        let rustcrypto = {
            let mut h = md4::Md4::new();
            h.update(&buf);
            h.finalize().to_vec()
        };

        assert_eq!(this, rustcrypto.as_slice());
    }
}

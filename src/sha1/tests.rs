use digest::Digest;

use super::*;

#[test]
fn test_example() {
    let mut h = Sha1::default();
    h.write_all(b"His money is twice tainted:").unwrap();
    h.write_all(b" 'taint yours and 'taint mine.").unwrap();
    assert_eq!(
        h.sum(),
        [
            0x59, 0x7f, 0x6a, 0x54, 0x00, 0x10, 0xf9, 0x4c, 0x15, 0xd7, 0x18, 0x06, 0xa9, 0x9a,
            0x2c, 0x87, 0x10, 0xe7, 0x47, 0xbd,
        ]
    );
}

#[test]
fn rustcrypto_sha1_interop() {
    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut buf = vec![0u8; s];
        rand::fill(buf.as_mut_slice());
        let this = &crate::sha1::sum(&buf);

        let rustcrypto = sha1::Sha1::digest(&buf).as_slice().to_vec();

        assert_eq!(this, rustcrypto.as_slice());
    }
}

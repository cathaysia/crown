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

#[test]
#[cfg(feature = "marshal")]
fn test_marsh_unmarsh() {
    use crate::core::CoreWrite;
    use crate::mac::hmac::Marshalable;

    let mut x = new256(None).unwrap();
    x.write_all(b"xxxxx").unwrap();

    let status = x.marshal_binary().unwrap();

    let mut x_cloned = x.clone();
    let ret1 = x_cloned.sum();

    let mut x2 = new256(None).unwrap();
    x2.unmarshal_binary(&status).unwrap();
    let ret2 = x2.sum();

    assert_eq!(ret1, ret2);
}

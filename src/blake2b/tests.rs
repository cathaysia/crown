mod data;

use std::io::Write;

use digest::Digest;

use crate::{
    blake2b::{new512, tests::data::HASHES},
    hash::{Hash, HashUser},
};

#[test]
fn test_hashes() {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
    let mut input = [0u8; 255];
    (0..255).for_each(|i| {
        input[i] = i as u8;
    });

    for (i, expected) in HASHES.iter().enumerate() {
        let mut h = new512(&key).unwrap();
        h.write_all(&input[..i]).unwrap();
        let sum = h.sum();
        assert_eq!(&hex::encode(sum), expected);
        h.reset();

        for j in 0..i {
            h.write_all(&input[j..j + 1]).unwrap();
        }

        let sum = h.sum();
        assert_eq!(&hex::encode(sum), expected);
    }
}

#[test]
fn rustcrypto_blake2_interop() {
    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut buf = vec![0u8; s];
        rand::fill(buf.as_mut_slice());

        let this = &crate::blake2b::sum512(&buf);
        let rustcrypto = {
            let mut digest = blake2::Blake2b512::new();
            digest.update(&buf);
            digest.finalize()
        };
        let rustcrypto = rustcrypto.as_slice();

        assert_eq!(hex::encode(this), hex::encode(rustcrypto));
    }
}

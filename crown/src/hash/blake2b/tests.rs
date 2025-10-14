mod data;

use digest::Digest;

use super::{new512, tests::data::HASHES, Blake2bVariable};
use crate::{
    core::CoreWrite,
    hash::{Hash, HashUser, HashVariable},
};

#[test]
fn test_hashes() {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
    let mut input = [0u8; 255];
    (0..255).for_each(|i| {
        input[i] = i as u8;
    });

    for (i, expected) in HASHES.iter().enumerate() {
        let mut h = new512(Some(&key)).unwrap();
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

        let this = &super::sum512(&buf);
        let rustcrypto = {
            let mut digest = blake2::Blake2b512::new();
            digest.update(&buf);
            digest.finalize()
        };

        assert_eq!(hex::encode(this), hex::encode(rustcrypto));
    }
}

#[test]
fn rustcrypto_blake2_variable_interop() {
    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut buf = vec![0u8; s];
        rand::fill(buf.as_mut_slice());

        let this = {
            let mut digest = Blake2bVariable::new(None, 64).unwrap();
            digest.write_all(&buf).unwrap();
            digest.sum_vec()
        };
        let rustcrypto = {
            let mut digest = blake2::Blake2b512::new();
            digest.update(&buf);
            digest.finalize()
        };

        assert_eq!(hex::encode(this), hex::encode(rustcrypto));
    }
}

mod data;
use chacha20poly1305::aead::AeadMutInPlace;
use rc4::KeyInit;

use crate::{
    chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305},
    cipher::{erased::ErasedAead, Aead},
};

#[test]
fn test_vector() {
    for (idx, t) in data::CHACHA20_POLY1305_TESTS.into_iter().enumerate() {
        let [plaintext, aad, key, nonce, out] = t;
        let key = hex::decode(key).unwrap();
        let nonce = hex::decode(nonce).unwrap();
        let aad = hex::decode(aad).unwrap();
        let plaintext = hex::decode(plaintext).unwrap();
        let cipher = match nonce.len() {
            12 => ErasedAead::new(ChaCha20Poly1305::new(&key).unwrap()),
            24 => ErasedAead::new(XChaCha20Poly1305::new(&key).unwrap()),
            _ => unreachable!(),
        };

        let mut plaintext2 = plaintext.clone();
        cipher
            .seal_in_place_append_tag(&mut plaintext2, &nonce, &aad)
            .unwrap();

        let ct = plaintext2.clone();
        assert_eq!(hex::encode(&plaintext2), out);

        cipher
            .open_in_place(&mut plaintext2, &nonce, &aad)
            .unwrap_or_else(|_| panic!("failed to decrypt ciphertext: {idx}"));
        assert_eq!(plaintext, plaintext2);

        let mut aad = aad;
        if !aad.is_empty() {
            let idx: usize = rand::random_range(0..aad.len());
            aad[idx] ^= 0x80;
            let mut ct = ct.clone();
            assert!(cipher.open_in_place(&mut ct, &nonce, &aad).is_err());
            aad[idx] ^= 0x80;
        }

        {
            let mut nonce = nonce.clone();
            let idx: usize = rand::random_range(0..nonce.len());
            nonce[idx] ^= 0x80;
            let mut ct = ct.clone();
            assert!(cipher.open_in_place(&mut ct, &nonce, &aad).is_err());
            nonce[idx] ^= 0x80;
        }

        {
            let mut ct = ct;
            let idx: usize = rand::random_range(0..ct.len());
            ct[idx] ^= 0x80;
            let mut ct = ct.clone();
            assert!(cipher.open_in_place(&mut ct, &nonce, &aad).is_err());
            ct[idx] ^= 0x80;
        }
    }
}

#[test]
fn rustcrypto_chacha20poly1305_interop() {
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    let key = key;
    let mut nonce = [0u8; 12];
    rand::fill(&mut nonce);
    let nonce = nonce;

    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut src = vec![0u8; s];
        rand::fill(src.as_mut_slice());
        let ciphertext = {
            let mut dst = src.clone();
            let cipher = crate::chacha20poly1305::ChaCha20Poly1305::new(&key).unwrap();
            cipher
                .seal_in_place_append_tag(&mut dst, &nonce, &[])
                .unwrap();
            dst
        };

        let plaintext = {
            let mut dst = ciphertext.clone();
            let mut cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key).unwrap();
            cipher
                .decrypt_in_place(&nonce.into(), &[], &mut dst)
                .unwrap();
            dst
        };

        assert_eq!(src, plaintext);
    }

    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut src = vec![0u8; s];
        rand::fill(src.as_mut_slice());

        let ciphertext = {
            let mut dst = src.clone();
            let mut cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key).unwrap();
            cipher
                .encrypt_in_place(&nonce.into(), &[], &mut dst)
                .unwrap();
            dst
        };

        let this = {
            let mut inout = ciphertext.clone();
            let cipher = crate::chacha20poly1305::ChaCha20Poly1305::new(&key).unwrap();
            cipher.open_in_place(&mut inout, &nonce, &[]).unwrap();
            inout
        };

        assert_eq!(this, src);
    }
}

#[test]
fn rustcrypto_xchacha20poly1305_interop() {
    let mut key = [0u8; XChaCha20Poly1305::KEY_SIZE];
    rand::fill(&mut key);
    let key = key;
    let mut nonce = [0u8; XChaCha20Poly1305::NONCE_SIZE];
    rand::fill(&mut nonce);
    let nonce = nonce;

    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut src = vec![0u8; s];
        rand::fill(src.as_mut_slice());
        let ciphertext = {
            let mut dst = src.clone();
            let cipher = crate::chacha20poly1305::XChaCha20Poly1305::new(&key).unwrap();
            cipher
                .seal_in_place_append_tag(&mut dst, &nonce, &[])
                .unwrap();
            dst
        };

        let plaintext = {
            let mut dst = ciphertext.clone();
            let mut cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&key).unwrap();
            cipher
                .decrypt_in_place(&nonce.into(), &[], &mut dst)
                .unwrap();
            dst
        };

        assert_eq!(src, plaintext);
    }

    for _ in 0..1000 {
        let s: usize = rand::random_range(100..1000);
        let mut src = vec![0u8; s];
        rand::fill(src.as_mut_slice());

        let ciphertext = {
            let mut dst = src.clone();
            let mut cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&key).unwrap();
            cipher
                .encrypt_in_place(&nonce.into(), &[], &mut dst)
                .unwrap();
            dst
        };

        let this = {
            let mut inout = ciphertext.clone();
            let cipher = crate::chacha20poly1305::XChaCha20Poly1305::new(&key).unwrap();
            cipher.open_in_place(&mut inout, &nonce, &[]).unwrap();
            inout
        };

        assert_eq!(this, src);
    }
}

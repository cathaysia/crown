#![no_main]

use arbitrary::Arbitrary;
use crown::core::CoreWrite;
use crown::envelope::{EvpAeadCipher, EvpHash};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum FuzzAction {
    HashSha256 {
        data: Vec<u8>,
    },
    HashSha3_256 {
        data: Vec<u8>,
    },
    HashMd5 {
        data: Vec<u8>,
    },
    HashBlake2b {
        data: Vec<u8>,
        key: Option<Vec<u8>>,
        key_len: u8,
    },
    AesGcm {
        key: [u8; 16],
        nonce: [u8; 12],
        data: Vec<u8>,
        aad: Vec<u8>,
    },
    ChaCha20Poly1305 {
        key: [u8; 32],
        nonce: [u8; 12],
        data: Vec<u8>,
        aad: Vec<u8>,
    },
    XChaCha20Poly1305 {
        key: [u8; 32],
        nonce: [u8; 24],
        data: Vec<u8>,
        aad: Vec<u8>,
    },
    AesCcm {
        key: [u8; 16],
        nonce: [u8; 12],
        data: Vec<u8>,
        aad: Vec<u8>,
    },
}

fuzz_target!(|action: FuzzAction| {
    match action {
        FuzzAction::HashSha256 { data } => {
            if let Ok(mut hasher) = EvpHash::new_sha256() {
                let _ = hasher.write(&data);
                let _ = hasher.sum();
            }
        }
        FuzzAction::HashSha3_256 { data } => {
            if let Ok(mut hasher) = EvpHash::new_sha3_256() {
                let _ = hasher.write(&data);
                let _ = hasher.sum();
            }
        }
        FuzzAction::HashMd5 { data } => {
            if let Ok(mut hasher) = EvpHash::new_md5() {
                let _ = hasher.write(&data);
                let _ = hasher.sum();
            }
        }
        FuzzAction::HashBlake2b { data, key, key_len } => {
            let k = key.as_deref();
            if let Ok(mut hasher) = EvpHash::new_blake2b(k, key_len as usize) {
                let _ = hasher.write(&data);
                let _ = hasher.sum();
            }
        }
        FuzzAction::AesGcm {
            key,
            nonce,
            data,
            aad,
        } => {
            if let Ok(cipher) = EvpAeadCipher::new_aes_gcm(&key) {
                let mut data_clone = data.clone();
                if let Ok(tag) = cipher.seal_in_place_separate_tag(&mut data_clone, &nonce, &aad) {
                    let mut decrypted = data_clone.clone();
                    let res = cipher.open_in_place_separate_tag(&mut decrypted, &tag, &nonce, &aad);
                    assert!(res.is_ok());
                    assert_eq!(data, decrypted);
                }
            }
        }
        FuzzAction::ChaCha20Poly1305 {
            key,
            nonce,
            data,
            aad,
        } => {
            if let Ok(cipher) = EvpAeadCipher::new_chacha20_poly1305(&key) {
                let mut data_clone = data.clone();
                if let Ok(tag) = cipher.seal_in_place_separate_tag(&mut data_clone, &nonce, &aad) {
                    let mut decrypted = data_clone.clone();
                    let res = cipher.open_in_place_separate_tag(&mut decrypted, &tag, &nonce, &aad);
                    assert!(res.is_ok());
                    assert_eq!(data, decrypted);
                }
            }
        }
        FuzzAction::XChaCha20Poly1305 {
            key,
            nonce,
            data,
            aad,
        } => {
            if let Ok(cipher) = EvpAeadCipher::new_xchacha20_poly1305(&key) {
                let mut data_clone = data.clone();
                if let Ok(tag) = cipher.seal_in_place_separate_tag(&mut data_clone, &nonce, &aad) {
                    let mut decrypted = data_clone.clone();
                    let res = cipher.open_in_place_separate_tag(&mut decrypted, &tag, &nonce, &aad);
                    assert!(res.is_ok());
                    assert_eq!(data, decrypted);
                }
            }
        }
        FuzzAction::AesCcm {
            key,
            nonce,
            data,
            aad,
        } => {
            // CCM needs const TAG_SIZE and NONCE_SIZE, assuming standard 16 and 12
            if let Ok(cipher) = EvpAeadCipher::new_aes_ccm::<16, 12>(&key) {
                let mut data_clone = data.clone();
                if let Ok(tag) = cipher.seal_in_place_separate_tag(&mut data_clone, &nonce, &aad) {
                    let mut decrypted = data_clone.clone();
                    let res = cipher.open_in_place_separate_tag(&mut decrypted, &tag, &nonce, &aad);
                    assert!(res.is_ok());
                    assert_eq!(data, decrypted);
                }
            }
        }
    }
});

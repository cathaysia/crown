mod utils;
use kittycrypto::{envelope::EvpAeadCipher, error::CryptoResult};

use crate::utils::parse_response_line;

#[test]
fn test_pyca_aead_vectors() {
    const BASE_DIR: &str = "tests/cryptography/vectors/cryptography_vectors/";
    const FILES: [(fn(key: &[u8]) -> CryptoResult<EvpAeadCipher>, &str); 2] = [
        (
            EvpAeadCipher::new_aes_ocb3::<16, 12>,
            "ciphers/AES/OCB3/rfc7253.txt",
        ),
        (
            EvpAeadCipher::new_aes_ocb3::<16, 13>,
            "ciphers/AES/OCB3/test-vector-1-nonce104.txt",
        ),
    ];

    for (newer, filename) in FILES {
        let content = std::fs::read_to_string(format!("{BASE_DIR}/{filename}")).unwrap();
        let mut lines = content.lines();

        while let Some(line) = lines.next() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with("COUNT = ") {
                let mut key = None;
                let mut nonce = None;
                let mut aad = None;
                let mut plaintext = None;
                let mut expected_ciphertext = None;

                for line in lines.by_ref() {
                    let line = line.trim();
                    if line.is_empty() {
                        break;
                    }
                    if line.starts_with('#') {
                        continue;
                    }

                    let Ok((rkey, value)) = parse_response_line(line) else {
                        eprintln!("parse response line failed: {line}");
                        continue;
                    };

                    match rkey.as_str() {
                        "key" => {
                            key = Some(value);
                        }
                        "plaintext" => {
                            plaintext = Some(value);
                        }
                        "ciphertext" => {
                            expected_ciphertext = Some(value);
                        }
                        "nonce" => {
                            nonce = Some(value);
                        }
                        "aad" => {
                            aad = Some(value);
                        }
                        _ => {
                            eprintln!("unexpected key: {rkey}");
                        }
                    }
                }

                if let (
                    Some(key),
                    Some(nonce),
                    Some(aad),
                    Some(mut plaintext),
                    Some(expected_ciphertext),
                ) = (key, nonce, aad, plaintext, expected_ciphertext)
                {
                    let cipher = newer(&key).unwrap();

                    let tag = cipher
                        .seal_in_place_separate_tag(&mut plaintext, &nonce, &aad)
                        .unwrap();

                    let mut result_ciphertext = plaintext;
                    result_ciphertext.extend_from_slice(&tag);

                    assert_eq!(
                        result_ciphertext,
                        expected_ciphertext,
                        "OCB3 test failed for {}: expected {}, got {}",
                        filename,
                        hex::encode(&expected_ciphertext),
                        hex::encode(&result_ciphertext)
                    );
                }
            }
        }
    }
}

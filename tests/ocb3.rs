use kittycrypto::envelope::EvpAeadCipher;

#[test]
fn test_pyca_ocb3_vectors() {
    const BASE_DIR: &str = "tests/cryptography/vectors/cryptography_vectors/";
    const FILES: [&str; 2] = [
        "ciphers/AES/OCB3/rfc7253.txt",
        "ciphers/AES/OCB3/test-vector-1-nonce104.txt",
    ];

    for filename in FILES {
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

                    if let Some(key_hex) = line.strip_prefix("Key = ") {
                        key = Some(hex::decode(key_hex).unwrap());
                    } else if let Some(nonce_hex) = line.strip_prefix("Nonce = ") {
                        nonce = Some(hex::decode(nonce_hex).unwrap());
                    } else if let Some(aad_hex) = line.strip_prefix("AAD = ") {
                        if aad_hex.is_empty() {
                            aad = Some(Vec::new());
                        } else {
                            aad = Some(hex::decode(aad_hex).unwrap());
                        }
                    } else if let Some(pt_hex) = line.strip_prefix("Plaintext = ") {
                        if pt_hex.len() % 2 != 0 {
                            continue;
                        }
                        if pt_hex.is_empty() {
                            plaintext = Some(Vec::new());
                        } else {
                            plaintext = Some(hex::decode(pt_hex).unwrap());
                        }
                    } else if let Some(ct_hex) = line.strip_prefix("Ciphertext = ") {
                        expected_ciphertext = Some(hex::decode(ct_hex).unwrap());
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
                    let cipher = EvpAeadCipher::new_aes_ocb3::<16, 12>(&key).unwrap();

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

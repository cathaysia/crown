use kittycrypto::envelope::EvpStreamCipher;

#[test]
fn test_pyca_ctr_vectors() {
    const BASE_DIR: &str = "tests/cryptography/vectors/cryptography_vectors/";
    const FILES: [&str; 3] = [
        "ciphers/AES/CTR/aes-128-ctr.txt",
        "ciphers/AES/CTR/aes-192-ctr.txt",
        "ciphers/AES/CTR/aes-256-ctr.txt",
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
                let mut plaintext = None;
                let mut expected_ciphertext = None;
                let mut iv = None;

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
                    } else if let Some(pt_hex) = line.strip_prefix("PLAINTEXT = ") {
                        if pt_hex.len() % 2 != 0 {
                            continue;
                        }
                        if pt_hex.is_empty() {
                            plaintext = Some(Vec::new());
                        } else {
                            plaintext = Some(hex::decode(pt_hex).unwrap());
                        }
                    } else if let Some(ct_hex) = line.strip_prefix("CIPHERTEXT = ") {
                        expected_ciphertext = Some(hex::decode(ct_hex).unwrap());
                    } else if let Some(ct_hex) = line.strip_prefix("IV = ") {
                        iv = Some(hex::decode(ct_hex).unwrap());
                    }
                }

                if let (Some(key), Some(mut plaintext), Some(expected_ciphertext), Some(iv)) =
                    (key, plaintext, expected_ciphertext, iv)
                {
                    let mut cipher = EvpStreamCipher::new_aes_ctr(&key, &iv).unwrap();

                    cipher.encrypt(&mut plaintext).unwrap();
                    let result_ciphertext = plaintext;

                    assert_eq!(
                        result_ciphertext,
                        expected_ciphertext,
                        "ctr test failed for {}: expected {}, got {}",
                        filename,
                        hex::encode(&expected_ciphertext),
                        hex::encode(&result_ciphertext)
                    );
                }
            }
        }
    }
}

mod utils;
use crown::{envelope::EvpBlockCipher, error::CryptoResult};

use crate::utils::parse_response_line;

#[test]
fn test_pyca_block_vectors() {
    const BASE_DIR: &str = "tests/cryptography/vectors/cryptography_vectors/";
    #[allow(clippy::type_complexity)]
    #[rustfmt::skip]
    const FILES: [(fn(key: &[u8], iv: &[u8]) -> CryptoResult<EvpBlockCipher>, &str); 32] = [
        (EvpBlockCipher::new_tripledes_cbc, "ciphers/3DES/CBC/TCBCIinvperm.rsp"),
        (EvpBlockCipher::new_tripledes_cbc, "ciphers/3DES/CBC/TCBCIMMT1.rsp"),
        (EvpBlockCipher::new_tripledes_cbc, "ciphers/3DES/CBC/TCBCIMMT2.rsp"),
        (EvpBlockCipher::new_tripledes_cbc, "ciphers/3DES/CBC/TCBCIMMT3.rsp"),
        // (EvpBlockCipher::new_tripledes_cbc, "ciphers/3DES/CBC/TCBCinvperm.rsp"),
        (EvpBlockCipher::new_tripledes_cbc, "ciphers/3DES/CBC/TCBCIpermop.rsp"),
        (EvpBlockCipher::new_tripledes_cbc, "ciphers/3DES/CBC/TCBCIsubtab.rsp"),
        (EvpBlockCipher::new_tripledes_cbc, "ciphers/3DES/CBC/TCBCIvarkey.rsp"),
        (EvpBlockCipher::new_tripledes_cbc, "ciphers/3DES/CBC/TCBCIvartext.rsp"),
        (EvpBlockCipher::new_tripledes_cbc, "ciphers/3DES/CBC/TCBCMMT1.rsp"),
        (EvpBlockCipher::new_tripledes_cbc, "ciphers/3DES/CBC/TCBCMMT2.rsp"),
        (EvpBlockCipher::new_tripledes_cbc, "ciphers/3DES/CBC/TCBCMMT3.rsp"),
        // (EvpBlockCipher::new_tripledes_cbc, "ciphers/3DES/CBC/TCBCpermop.rsp"),
        // (EvpBlockCipher::new_tripledes_cbc, "ciphers/3DES/CBC/TCBCsubtab.rsp"),
        // (EvpBlockCipher::new_tripledes_cbc, "ciphers/3DES/CBC/TCBCvarkey.rsp"),
        // (EvpBlockCipher::new_tripledes_cbc, "ciphers/3DES/CBC/TCBCvartext.rsp"),
        (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCGFSbox128.rsp"),
        (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCGFSbox192.rsp"),
        (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCGFSbox256.rsp"),
        (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCKeySbox128.rsp"),
        (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCKeySbox192.rsp"),
        (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCKeySbox256.rsp"),
        (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCMMT128.rsp"),
        (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCMMT192.rsp"),
        (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCMMT256.rsp"),
        (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCVarKey128.rsp"),
        (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCVarKey192.rsp"),
        (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCVarKey256.rsp"),
        (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCVarTxt128.rsp"),
        (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCVarTxt192.rsp"),
        (EvpBlockCipher::new_aes_cbc, "ciphers/AES/CBC/CBCVarTxt256.rsp"),
        (EvpBlockCipher::new_blowfish_cbc, "ciphers/Blowfish/bf-cbc.txt"),
        (|key: &[u8], iv: &[u8]| ->CryptoResult<EvpBlockCipher> { EvpBlockCipher::new_camellia_cbc (key, iv, None)}, "ciphers/Camellia/camellia-cbc.txt"),
        (EvpBlockCipher::new_cast5_cbc, "ciphers/CAST5/cast5-cbc.txt"),
        (EvpBlockCipher::new_idea_cbc, "ciphers/IDEA/idea-cbc.txt"),
        (|key: &[u8], iv: &[u8]| ->CryptoResult<EvpBlockCipher> { EvpBlockCipher::new_rc2_cbc (key, iv, None)}, "ciphers/RC2/rc2-cbc.txt"),
        (EvpBlockCipher::new_sm4_cbc, "ciphers/SM4/draft-ribose-cfrg-sm4-10-cbc.txt"),
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
                let mut keys = None;
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

                    let Ok((rkey, value)) = parse_response_line(line) else {
                        eprintln!("parse response line failed: {line}");
                        continue;
                    };

                    match rkey.as_str() {
                        "keys" => {
                            keys = Some(value);
                        }
                        "plaintext" => {
                            plaintext = Some(value);
                        }
                        "ciphertext" => {
                            expected_ciphertext = Some(value);
                        }
                        "iv" => {
                            iv = Some(value);
                        }
                        _ => {
                            eprintln!("unexpected key: {rkey}");
                        }
                    }
                }

                if let (Some(key), Some(mut plaintext), Some(iv), Some(expected_ciphertext)) =
                    (keys, plaintext, iv, expected_ciphertext)
                {
                    let mut cipher = newer(&key, &iv).unwrap();

                    cipher.encrypt_alloc(&mut plaintext).unwrap();

                    let result_ciphertext = plaintext;

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
